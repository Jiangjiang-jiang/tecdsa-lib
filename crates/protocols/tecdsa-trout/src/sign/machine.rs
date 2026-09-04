// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    non_snake_case
)]

//! StateMachine wrapper for the Trout online signing protocol.
//!
//! ## Protocol flow
//!
//! 1. On construction: verify all presign broadcast proofs (eVRF, R_{CL-EC},
//!    R_{ComKwlg}), reconstruct public aggregated ciphertext/commitment
//!    components, compute this party's F_i contributions for both scaled
//!    decryption instances, and queue a broadcast of `(F_i_1, F_i_2)`.
//! 2. Round 1: collect F-share broadcasts from all other parties.
//! 3. Once all collected: aggregate F_i shares, solve discrete logs, compute
//!    `s = (u*k)^{-1} * u*(H(m)+r*x)`, verify ECDSA, output signature.
//!
//! ## Backward compatibility
//!
//! `new_simulation()` provides the old simulation-mode constructor that calls
//! `sign_round2()` directly with all parties' secrets.

use std::collections::BTreeMap;

use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use tecdsa_class_group::{
    cl::{ClPublicKey, ClSetup, Qfi},
    scaled_decrypt::{
        aggregate_and_solve, aggregate_ciphertext_components, aggregate_commitments,
        compute_f_share, ScaledDecryptPartyInput, ScaledDecryptPublic,
    },
};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{
    ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature},
    state_machine::Outgoing,
    IaReport, PartyId, Recipient, StateMachine,
};

use super::sign_round2;
use crate::{
    error::{qfi_from_abc, qfi_to_abc},
    key_share::TroutKeyShare,
    presign::types::TroutPresignOutput,
};

// ---------------------------------------------------------------------------
// Wire message types
// ---------------------------------------------------------------------------

/// Sign wire message for the Trout protocol.
///
/// Each party broadcasts its scaled decryption shares (F_i_1, F_i_2) serialized
/// as `(a, b, c)` decimal string triples for the two scaled decryption instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TroutSignMsg {
    /// Round 1: party's F-share contributions for both scaled decryptions.
    FShares(TroutFSharePayload),
}

/// Payload containing a party's scaled decryption shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TroutFSharePayload {
    /// F_i for scaled decryption #1 (u*k), as (a, b, c) decimal strings.
    pub f_i_1_abc: (String, String, String),
    /// F_i for scaled decryption #2 (u*(H(m)+r*x)), as (a, b, c) decimal strings.
    pub f_i_2_abc: (String, String, String),
}

// ---------------------------------------------------------------------------
// State machine internals
// ---------------------------------------------------------------------------

struct ReceivedFShare {
    f_i_1: Qfi,
    f_i_2: Qfi,
}

enum SignRound {
    Round1(Round1State),
    Done(Signature<k256::Secp256k1>),
    Poisoned,
}

struct Round1State {
    received: BTreeMap<PartyId, ReceivedFShare>,
    outgoing: Vec<Outgoing<TroutSignMsg>>,
}

/// Data needed to finalize the signature after collecting all F-shares.
struct FinalizeData {
    r_scalar: k256::Scalar,
    public_key: k256::ProjectivePoint,
    message: DataToSign<k256::Secp256k1>,
    setup: ClSetup,
}

// ---------------------------------------------------------------------------
// Public state machine
// ---------------------------------------------------------------------------

/// StateMachine wrapper for Trout online signing.
///
/// On construction, verifies presign proofs, computes this party's F_i
/// contributions, and queues them for broadcast. Collects F-shares from
/// all other parties, then aggregates and produces the final ECDSA signature.
pub struct TroutSignMachine {
    round: SignRound,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    finalize: Option<FinalizeData>,
    ia_report: Option<IaReport>,
}

impl TroutSignMachine {
    /// Create a new sign state machine for distributed execution.
    ///
    /// Each party provides only its OWN presign output. The constructor:
    /// 1. Verifies all presign broadcast proofs (R_{CL-EC}, R_{ComKwlg})
    /// 2. Reconstructs public aggregated ciphertext/commitment components
    /// 3. Computes this party's F_i contributions for both scaled decryptions
    /// 4. Queues broadcast of the F-shares
    ///
    /// # Arguments
    /// - `my_id`: this party's ID (1-based `PartyId`)
    /// - `all_parties`: all participating party IDs (1-based)
    /// - `my_presign`: this party's presign output (consumed by value)
    /// - `message`: the message digest to sign
    /// - `share`: this party's key share (for public key verification)
    /// - `setup`: CL-HSM setup (consumed by value, stored for finalization)
    /// - `cl_pk`: the joint CL public key
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        my_presign: TroutPresignOutput,
        message: &DataToSign<k256::Secp256k1>,
        share: &TroutKeyShare,
        setup: ClSetup,
        cl_pk: &ClPublicKey,
    ) -> tecdsa_core::Result<Self> {
        if !all_parties.contains(&my_id) {
            return Err(TecdsaError::Other("my_id not in all_parties".into()));
        }

        let r_scalar = my_presign.r_scalar;
        let r_bytes = tecdsa_curve::conv::scalar_to_bytes(&r_scalar);
        let m_bytes = tecdsa_curve::conv::scalar_to_bytes(message.digest());
        let broadcasts = &my_presign.all_broadcasts;

        // -----------------------------------------------------------
        // Verify R_{CL-EC} proofs: K_tilde_i encrypts same k_i as R_i
        // -----------------------------------------------------------
        for bcast in broadcasts {
            let (c1_a, c1_b, c1_c) = &bcast.kt_c1_abc;
            let (c2_a, c2_b, c2_c) = &bcast.kt_c2_abc;
            let c1 = qfi_from_abc(c1_a, c1_b, c1_c)
                .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
            let c2 = qfi_from_abc(c2_a, c2_b, c2_c)
                .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
            let kt_ct = setup
                .ct_from_components(&c1, &c2)
                .map_err(|e| TecdsaError::Other(format!("ct_from_components: {e}")))?;

            let cl_ec_ok = bcast
                .pi_cl_ec
                .verify(&setup, cl_pk, &kt_ct, &bcast.r_i_bytes)
                .map_err(|e| TecdsaError::Other(format!("R_CL-EC verify: {e}")))?;
            if !cl_ec_ok {
                return Err(TecdsaError::InvalidProof(format!(
                    "R_CL-EC proof failed for party {}",
                    bcast.party_index
                )));
            }
        }

        // -----------------------------------------------------------
        // Verify R_{ComKwlg} proofs
        // -----------------------------------------------------------
        let pk_elt = cl_pk.elt();
        for bcast in broadcasts {
            let (a, b, c) = &bcast.u_com_abc;
            let u_com = qfi_from_abc(a, b, c)
                .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;

            let com_kwlg_ok = bcast
                .pi_com_kwlg
                .verify_with_base(&setup, &u_com, pk_elt)
                .map_err(|e| TecdsaError::Other(format!("R_ComKwlg verify: {e}")))?;
            if !com_kwlg_ok {
                return Err(TecdsaError::InvalidProof(format!(
                    "R_ComKwlg proof failed for party {}",
                    bcast.party_index
                )));
            }
        }

        // -----------------------------------------------------------
        // Reconstruct ciphertext and commitment components
        // -----------------------------------------------------------
        let mut kt_components = Vec::new();
        for bcast in broadcasts {
            let (c1_a, c1_b, c1_c) = &bcast.kt_c1_abc;
            let (c2_a, c2_b, c2_c) = &bcast.kt_c2_abc;
            let c1 = qfi_from_abc(c1_a, c1_b, c1_c)
                .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
            let c2 = qfi_from_abc(c2_a, c2_b, c2_c)
                .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
            kt_components.push((c1, c2));
        }

        let mut u_coms = Vec::new();
        for bcast in broadcasts {
            let (a, b, c) = &bcast.u_com_abc;
            let u = qfi_from_abc(a, b, c)
                .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
            u_coms.push(u);
        }

        let mut ct_scaled_components = Vec::new();
        for bcast in broadcasts {
            let (c1_a, c1_b, c1_c) = &bcast.ct_scaled_c1_abc;
            let (c2_a, c2_b, c2_c) = &bcast.ct_scaled_c2_abc;
            let c1 = qfi_from_abc(c1_a, c1_b, c1_c)
                .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
            let c2 = qfi_from_abc(c2_a, c2_b, c2_c)
                .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
            ct_scaled_components.push((c1, c2));
        }

        // -----------------------------------------------------------
        // Compute Z_tilde_j = r * C_tilde_j_scaled, add Enc(0, H(m))
        // -----------------------------------------------------------
        let mut z_components = Vec::new();
        for (c1, c2) in &ct_scaled_components {
            let z_c1 = setup
                .exp_bytes(c1, &r_bytes)
                .map_err(|e| TecdsaError::Other(format!("exp_bytes: {e}")))?;
            let z_c2 = setup
                .exp_bytes(c2, &r_bytes)
                .map_err(|e| TecdsaError::Other(format!("exp_bytes: {e}")))?;
            z_components.push((z_c1, z_c2));
        }

        let f_m = setup
            .power_of_f_bytes(&m_bytes)
            .map_err(|e| TecdsaError::Other(format!("power_of_f_bytes: {e}")))?;
        let (old_c1, old_c2) = z_components.remove(0);
        let new_z0_c2 = setup
            .compose(&old_c2, &f_m)
            .map_err(|e| TecdsaError::Other(format!("compose: {e}")))?;
        z_components.insert(0, (old_c1, new_z0_c2));

        // -----------------------------------------------------------
        // Scaled Decryption #1 public data: u * k
        // -----------------------------------------------------------
        let (kt_a1, kt_a2) = aggregate_ciphertext_components(&setup, &kt_components)
            .map_err(|e| TecdsaError::Other(format!("agg_ct: {e}")))?;
        let u_b_agg = aggregate_commitments(&setup, &u_coms)
            .map_err(|e| TecdsaError::Other(format!("agg_com: {e}")))?;

        let sd1_public = ScaledDecryptPublic {
            a1: kt_a1,
            a2: kt_a2,
            b_agg: u_b_agg,
        };

        // -----------------------------------------------------------
        // Scaled Decryption #2 public data: u * (H(m) + r*x)
        // -----------------------------------------------------------
        let (z_a1, z_a2) = aggregate_ciphertext_components(&setup, &z_components)
            .map_err(|e| TecdsaError::Other(format!("agg_ct z: {e}")))?;
        let u_b_agg2 = aggregate_commitments(&setup, &u_coms)
            .map_err(|e| TecdsaError::Other(format!("agg_com z: {e}")))?;

        let sd2_public = ScaledDecryptPublic {
            a1: z_a1,
            a2: z_a2,
            b_agg: u_b_agg2,
        };

        // -----------------------------------------------------------
        // Compute THIS party's F_i for both scaled decryptions
        // -----------------------------------------------------------

        // SD1 input: alpha_i, beta_i, b_i = u_i
        let sd1_input = ScaledDecryptPartyInput {
            alpha_i: my_presign.alpha_i.clone(),
            beta_i: my_presign.beta_i.clone(),
            b_i: tecdsa_curve::conv::scalar_to_bytes(&my_presign.u_i),
        };
        let f_i_1 = compute_f_share(&setup, &sd1_input, &sd1_public)
            .map_err(|e| TecdsaError::Other(format!("compute_f_share SD1: {e}")))?;

        // SD2 input: alpha_z_i = r * l_i * delta_i, beta_i, b_i = u_i
        let alpha_z = {
            let r_val = Integer::from_digits(&r_bytes, Order::Msf);
            let lid_val = Integer::from_digits(&my_presign.l_i_delta_i, Order::Msf);
            Integer::from(&r_val * &lid_val).to_digits::<u8>(Order::Msf)
        };
        let sd2_input = ScaledDecryptPartyInput {
            alpha_i: alpha_z,
            beta_i: my_presign.beta_i.clone(),
            b_i: tecdsa_curve::conv::scalar_to_bytes(&my_presign.u_i),
        };
        let f_i_2 = compute_f_share(&setup, &sd2_input, &sd2_public)
            .map_err(|e| TecdsaError::Other(format!("compute_f_share SD2: {e}")))?;

        // -----------------------------------------------------------
        // Serialize F_i shares and queue broadcast
        // -----------------------------------------------------------
        let f_i_1_abc =
            qfi_to_abc(&f_i_1).map_err(|e| TecdsaError::Other(format!("qfi_to_abc: {e}")))?;
        let f_i_2_abc =
            qfi_to_abc(&f_i_2).map_err(|e| TecdsaError::Other(format!("qfi_to_abc: {e}")))?;

        let payload = TroutFSharePayload {
            f_i_1_abc,
            f_i_2_abc,
        };

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: TroutSignMsg::FShares(payload),
        }];

        // Store own F-shares
        let mut received = BTreeMap::new();
        received.insert(my_id, ReceivedFShare { f_i_1, f_i_2 });

        let state = Round1State { received, outgoing };

        Ok(Self {
            round: SignRound::Round1(state),
            my_id,
            all_parties,
            finalize: Some(FinalizeData {
                r_scalar,
                public_key: share.public_key,
                message: *message,
                setup,
            }),
            ia_report: None,
        })
    }

    /// Simulation-mode constructor (backward compatible).
    ///
    /// Takes ALL parties' presign outputs and immediately computes the
    /// signature via `sign_round2()`. The resulting machine is already done.
    pub fn new_simulation(
        all_presigns: &[TroutPresignOutput],
        message: &DataToSign<k256::Secp256k1>,
        share: &TroutKeyShare,
        setup: &ClSetup,
        cl_pk: &ClPublicKey,
    ) -> tecdsa_core::Result<Self> {
        match sign_round2(all_presigns, message, share, setup, cl_pk) {
            Ok(sig) => Ok(Self {
                round: SignRound::Done(sig),
                my_id: PartyId(0),
                all_parties: Vec::new(),
                finalize: None,
                ia_report: None,
            }),
            Err(e) => Err(TecdsaError::Other(format!("sign_round2 failed: {e}"))),
        }
    }

    /// Deserialize a received F-share payload into Qfi elements.
    fn deserialize_fshares(payload: &TroutFSharePayload) -> Result<(Qfi, Qfi), TecdsaError> {
        let (a1, b1, c1) = &payload.f_i_1_abc;
        let f_i_1 = qfi_from_abc(a1, b1, c1)
            .map_err(|e| TecdsaError::Other(format!("deser f_i_1: {e}")))?;
        let (a2, b2, c2) = &payload.f_i_2_abc;
        let f_i_2 = qfi_from_abc(a2, b2, c2)
            .map_err(|e| TecdsaError::Other(format!("deser f_i_2: {e}")))?;
        Ok((f_i_1, f_i_2))
    }

    /// Finalize: aggregate all F-shares and compute the ECDSA signature.
    fn finalize_signature(
        &self,
        state: Round1State,
    ) -> tecdsa_core::Result<Signature<k256::Secp256k1>> {
        let fin = self
            .finalize
            .as_ref()
            .ok_or_else(|| TecdsaError::Other("finalize data missing".into()))?;

        // Collect F-shares in order
        let mut f1_shares = Vec::new();
        let mut f2_shares = Vec::new();
        for fshare in state.received.into_values() {
            f1_shares.push(fshare.f_i_1);
            f2_shares.push(fshare.f_i_2);
        }

        // Aggregate and solve SD1: u*k
        let uk = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(
            &aggregate_and_solve(&fin.setup, &f1_shares)
                .map_err(|e| TecdsaError::Other(format!("agg_solve SD1: {e}")))?,
        );

        // Aggregate and solve SD2: u*(H(m) + r*x)
        let u_mx = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(
            &aggregate_and_solve(&fin.setup, &f2_shares)
                .map_err(|e| TecdsaError::Other(format!("agg_solve SD2: {e}")))?,
        );

        // Compute s = (u*k)^{-1} * u*(H(m)+r*x)
        let uk_inv = uk
            .invert()
            .into_option()
            .ok_or_else(|| TecdsaError::Other("u*k is zero, cannot invert".into()))?;

        let s = uk_inv * u_mx;
        let s = low_s_normalize::<k256::Secp256k1>(s);

        let sig = Signature { r: fin.r_scalar, s };

        // Verify the signature
        verify_ecdsa::<k256::Secp256k1>(&sig, &fin.public_key, &fin.message)
            .map_err(|e| TecdsaError::InvalidProof(format!("final verification: {e}")))?;

        Ok(sig)
    }
}

impl StateMachine for TroutSignMachine {
    type Output = Signature<k256::Secp256k1>;
    type Inbound = TroutSignMsg;
    type Outbound = TroutSignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let round = std::mem::replace(&mut self.round, SignRound::Poisoned);

        match round {
            SignRound::Round1(mut state) => {
                let TroutSignMsg::FShares(payload) = msg;

                if !self.all_parties.contains(&from) {
                    self.round = SignRound::Round1(state);
                    return Err(TecdsaError::Other(format!("unknown party: {from}")));
                }

                if state.received.contains_key(&from) {
                    self.round = SignRound::Round1(state);
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }

                let (f_i_1, f_i_2) = match Self::deserialize_fshares(&payload) {
                    Ok(pair) => pair,
                    Err(e) => {
                        self.round = SignRound::Round1(state);
                        return Err(e);
                    }
                };

                state.received.insert(from, ReceivedFShare { f_i_1, f_i_2 });

                if state.received.len() == self.all_parties.len() {
                    let output = self.finalize_signature(state)?;
                    self.round = SignRound::Done(output);
                } else {
                    self.round = SignRound::Round1(state);
                }
            }
            SignRound::Done(_) => {
                self.round = SignRound::Done(Signature {
                    r: k256::Scalar::ZERO,
                    s: k256::Scalar::ZERO,
                });
                return Err(TecdsaError::Other("sign already complete".into()));
            }
            SignRound::Poisoned => {
                return Err(TecdsaError::Other("sign machine is poisoned".into()));
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            SignRound::Round1(s) => std::mem::take(&mut s.outgoing),
            SignRound::Done(_) | SignRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, SignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            SignRound::Done(output) => Ok(output),
            _ => Err(TecdsaError::Other("sign not complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            SignRound::Round1(_) => 1,
            SignRound::Done(_) => 2,
            SignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        self.ia_report.as_ref()
    }
}
