// SPDX-License-Identifier: GPL-3.0-or-later
//! TX25 presign state machine implementation.

use std::collections::BTreeMap;

use zeroize::Zeroize;

use tecdsa_class_group::bicycl_glue::{BicyclPublicKey, BicyclQfi, ClSetup};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use crate::error::Tx25Error;
use crate::key_share::Tx25KeyShare;
use crate::mpmta::mpmta_round1;
use crate::pvss::pvss_distribute;

use super::msg::{
    R1Payload, R2Payload, SerREncProof, SerRShProof, SerializedClCt, SerializedQfi, Tx25PresignMsg,
};
use super::rounds::{
    finalize, my_idx, n_others, point_from_bytes, transition_r1_to_r2, PresignRound, ReceivedR1,
    ReceivedR2, Round1State,
};
use super::{KeyMaterial, Tx25Presignature};

// ---------------------------------------------------------------------------
// TX25 presigning state machine
// ---------------------------------------------------------------------------

/// TX25 presigning state machine (2 rounds + offline output computation).
///
/// Implements the presign protocol from TX25 Section 4.2 using CL-based
/// public-checked MtA (MPMtA) for multiplicative-to-additive conversion
/// and PVSS for distributed randomness generation.
///
/// Since bicycl-rs v0.2.2, `ClSetup` is `Send`, so it is stored directly
/// in the machine and reused across round transitions.
pub struct Tx25PresignMachine {
    pub(crate) round: PresignRound,
    pub(crate) setup: ClSetup,
    pub(crate) key_mat: KeyMaterial,
}

impl Tx25PresignMachine {
    /// Create a new TX25 presign state machine.
    ///
    /// Immediately runs presign Round 1:
    /// 1. Sample gamma_i
    /// 2. MPMtA1 for gamma_i (encrypt + R_Enc proof)
    /// 3. PVSS ShareDist for k_i shares
    /// 4. Queue Round 1 broadcast
    ///
    /// # Arguments
    ///
    /// * `my_id` - This party's identifier.
    /// * `all_parties` - All signing party identifiers (must be sorted).
    /// * `key_share` - Key share from keygen.
    /// * `setup` - CL-HSM setup context.
    ///
    /// # Errors
    ///
    /// Returns an error if this party is not in `all_parties` or if
    /// CL operations fail.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        key_share: &Tx25KeyShare,
        mut setup: ClSetup,
    ) -> Result<Self, Tx25Error> {
        if !all_parties.contains(&my_id) {
            return Err(Tx25Error::InvalidInput(
                "my_id not found in all_parties".into(),
            ));
        }

        let my_idx_val = my_idx(&all_parties, my_id)
            .ok_or_else(|| Tx25Error::InvalidInput("my_id not in all_parties".into()))?;
        let threshold = key_share.threshold;

        // TX25 requires honest majority: n >= 2t - 1.
        let n_parties = all_parties.len() as u16;
        if n_parties < 2 * threshold - 1 {
            return Err(Tx25Error::InvalidInput(format!(
                "TX25 requires n >= 2t-1 for honest majority: n={n_parties}, t={threshold}"
            )));
        }

        // Extract key material (ClSecretKey -> decimal, ClPublicKey -> inner).
        let sk_decimal = setup
            .sk_to_bytes(key_share.cl_sk.inner())
            .map_err(|e| Tx25Error::InvalidInput(format!("sk_to_bytes: {e}")))?;
        let raw_pks: Vec<BicyclPublicKey> = key_share
            .cl_pks
            .iter()
            .map(|pk| {
                let qfi = setup.pk_element(pk.inner())?;
                setup.pk_from_qfi(&qfi)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let key_mat = KeyMaterial {
            sk_decimal,
            raw_pks,
            x_i: key_share.secret_share,
            public_key: key_share.public_key,
            public_shares: key_share.public_shares.clone(),
            threshold,
        };

        let mut rng = rand::thread_rng();

        // --- Step 1: Sample gamma_i ---
        let gamma_i = k256::Secp256k1::random_scalar(&mut rng);

        // --- Step 2: MPMtA Round 1 for gamma_i ---
        let gamma_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&gamma_i);
        let my_pk = &key_mat.raw_pks[my_idx_val];
        let mpmta_r1 = mpmta_round1(&mut setup, my_pk, &gamma_bytes)?;

        // --- Step 3: PVSS ShareDist for k_i ---
        let party_ids_u16: Vec<u16> = all_parties.iter().map(|p| p.0).collect();

        let pvss_out = pvss_distribute(
            &mut setup,
            &party_ids_u16,
            &key_mat.raw_pks,
            threshold,
            my_idx_val,
            &mut rng,
        )?;

        // --- Step 4: Build Round 1 message ---
        let c_gamma_ser = SerializedClCt::from_bicycl_ct(&setup, &mpmta_r1.ciphertext)
            .map_err(|e| Tx25Error::InvalidInput(format!("serialize c_gamma: {e}")))?;

        let r_enc_proof_ser = SerREncProof::from_proof(&setup, &mpmta_r1.proof)
            .map_err(|e| Tx25Error::InvalidInput(format!("serialize r_enc_proof: {e}")))?;

        let pvss_c1_ser = SerializedQfi::from_qfi(&setup, &pvss_out.c1)
            .map_err(|e| Tx25Error::InvalidInput(format!("serialize pvss_c1: {e}")))?;

        let pvss_c2s_ser: Vec<SerializedQfi> = pvss_out
            .c2s
            .iter()
            .map(|c2| {
                SerializedQfi::from_qfi(&setup, c2)
                    .map_err(|e| Tx25Error::InvalidInput(format!("serialize pvss_c2: {e}")))
            })
            .collect::<Result<_, _>>()?;

        let pvss_proof_ser = SerRShProof::from_proof(&pvss_out.proof);

        let r1_payload = R1Payload {
            c_gamma: c_gamma_ser,
            r_enc_proof: r_enc_proof_ser,
            pvss_c1: pvss_c1_ser,
            pvss_c2s: pvss_c2s_ser,
            pvss_proof: pvss_proof_ser,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r1_payload, bincode::config::standard())
            .map_err(|e| Tx25Error::InvalidInput(format!("serialize R1 payload: {e}")))?;

        // Queue Round 1 broadcast to all other parties.
        let mut outgoing = Vec::new();
        for &party in &all_parties {
            if party != my_id {
                outgoing.push(Outgoing {
                    to: Recipient::Party(party),
                    msg: Tx25PresignMsg::Round1(payload_bytes.clone()),
                });
            }
        }

        // Store our own Round 1 data. The CL objects are moved here.
        let own_pvss_share = pvss_out.secret_share;
        let mut received = BTreeMap::new();
        received.insert(
            my_id,
            ReceivedR1 {
                c_gamma: mpmta_r1.ciphertext,
                r_enc_proof: mpmta_r1.proof,
                pvss_c1: pvss_out.c1,
                pvss_c2s: pvss_out.c2s,
                pvss_proof: pvss_out.proof,
            },
        );

        let state = Round1State {
            my_id,
            all_parties,
            gamma_i,
            own_pvss_share,
            received,
            outgoing,
        };

        Ok(Self {
            round: PresignRound::Round1(state),
            setup,
            key_mat,
        })
    }
}

// ---------------------------------------------------------------------------
// StateMachine implementation
// ---------------------------------------------------------------------------

impl StateMachine for Tx25PresignMachine {
    type Output = Tx25Presignature;
    type Inbound = Tx25PresignMsg;
    type Outbound = Tx25PresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        // Reject messages from self.
        let my_id = match &self.round {
            PresignRound::Round1(s) => s.my_id,
            PresignRound::Round2(s) => s.my_id,
            _ => PartyId(u16::MAX),
        };
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let round = std::mem::replace(&mut self.round, PresignRound::Poisoned);

        match round {
            PresignRound::Round1(mut state) => {
                if let Tx25PresignMsg::Round1(data) = msg {
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }

                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    // Deserialise R1 payload.
                    let (payload, _): (R1Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| {
                                self.round = PresignRound::Poisoned;
                                TecdsaError::Other(format!("deserialize R1 payload: {e}"))
                            })?;

                    // Reconstruct CL objects.
                    let c_gamma = payload.c_gamma.to_bicycl_ct(&self.setup).map_err(|e| {
                        TecdsaError::Other(format!("reconstruct c_gamma from party {from}: {e}"))
                    })?;

                    let r_enc_proof = payload.r_enc_proof.to_proof(&self.setup).map_err(|e| {
                        TecdsaError::Other(format!(
                            "reconstruct r_enc_proof from party {from}: {e}"
                        ))
                    })?;

                    let pvss_c1 = payload.pvss_c1.to_qfi(&self.setup).map_err(|e| {
                        TecdsaError::Other(format!("reconstruct pvss_c1 from party {from}: {e}"))
                    })?;

                    let pvss_c2s: Vec<BicyclQfi> = payload
                        .pvss_c2s
                        .iter()
                        .map(|s| {
                            s.to_qfi(&self.setup).map_err(|e| {
                                TecdsaError::Other(format!(
                                    "reconstruct pvss_c2 from party {from}: {e}"
                                ))
                            })
                        })
                        .collect::<Result<_, _>>()?;

                    let pvss_proof = payload.pvss_proof.to_proof();

                    state.received.insert(
                        from,
                        ReceivedR1 {
                            c_gamma,
                            r_enc_proof,
                            pvss_c1,
                            pvss_c2s,
                            pvss_proof,
                        },
                    );

                    // Check if all Round 1 messages collected.
                    if state.received.len() == state.all_parties.len() {
                        let r2_state = transition_r1_to_r2(state, &mut self.setup, &self.key_mat)?;
                        self.round = PresignRound::Round2(r2_state);
                    } else {
                        self.round = PresignRound::Round1(state);
                    }
                } else {
                    self.round = PresignRound::Round1(state);
                    return Err(TecdsaError::Other(
                        "unexpected message type in round 1".into(),
                    ));
                }
            }

            PresignRound::Round2(mut state) => {
                if let Tx25PresignMsg::Round2(data) = msg {
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }

                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    // Deserialise R2 payload.
                    let (payload, _): (R2Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| {
                                TecdsaError::Other(format!("deserialize R2 payload: {e}"))
                            })?;

                    let n = state.all_parties.len();
                    if payload.mta_outputs.len() != n {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "R2 mta_outputs length mismatch: expected {n}, got {}",
                            payload.mta_outputs.len()
                        )));
                    }

                    // Reconstruct per-party MtA ciphertexts and points.
                    let mut kg_c_alphas = Vec::with_capacity(n);
                    let mut xg_c_alphas = Vec::with_capacity(n);
                    let mut b_pts = Vec::with_capacity(n);
                    let mut b_hat_pts = Vec::with_capacity(n);

                    for (j, mta) in payload.mta_outputs.iter().enumerate() {
                        let kg_ca = mta.c_alpha.to_bicycl_ct(&self.setup).map_err(|e| {
                            TecdsaError::Other(format!(
                                "reconstruct kg c_alpha[{j}] from party {from}: {e}"
                            ))
                        })?;
                        let xg_ca = mta.c_alpha_hat.to_bicycl_ct(&self.setup).map_err(|e| {
                            TecdsaError::Other(format!(
                                "reconstruct xg c_alpha[{j}] from party {from}: {e}"
                            ))
                        })?;
                        let bp =
                            point_from_bytes(&mta.b_point_bytes, &format!("B[{j}] from {from}"))
                                .map_err(TecdsaError::Other)?;
                        let bhp = point_from_bytes(
                            &mta.b_hat_point_bytes,
                            &format!("B_hat[{j}] from {from}"),
                        )
                        .map_err(TecdsaError::Other)?;

                        kg_c_alphas.push(kg_ca);
                        xg_c_alphas.push(xg_ca);
                        b_pts.push(bp);
                        b_hat_pts.push(bhp);
                    }

                    let r_point =
                        point_from_bytes(&payload.r_point_bytes, &format!("R from {from}"))
                            .map_err(TecdsaError::Other)?;

                    let pd = payload.pd.to_qfi(&self.setup).map_err(|e| {
                        TecdsaError::Other(format!("reconstruct pd from party {from}: {e}"))
                    })?;

                    let pd_c1 = payload.pd_c1.to_qfi(&self.setup).map_err(|e| {
                        TecdsaError::Other(format!("reconstruct pd_c1 from party {from}: {e}"))
                    })?;

                    let dec_dl_proof = payload.dec_dl_proof.to_proof(&self.setup).map_err(|e| {
                        TecdsaError::Other(format!(
                            "reconstruct dec_dl_proof from party {from}: {e}"
                        ))
                    })?;

                    let kg_proof = payload.kg_proof.to_proof(&self.setup).map_err(|e| {
                        TecdsaError::Other(format!("reconstruct kg_proof from party {from}: {e}"))
                    })?;

                    let xg_proof = payload.xg_proof.to_proof(&self.setup).map_err(|e| {
                        TecdsaError::Other(format!("reconstruct xg_proof from party {from}: {e}"))
                    })?;

                    state.received.insert(
                        from,
                        ReceivedR2 {
                            kg_c_alphas,
                            xg_c_alphas,
                            b_points: b_pts,
                            b_hat_points: b_hat_pts,
                            r_point,
                            pd,
                            pd_c1,
                            dec_dl_proof,
                            kg_proof,
                            xg_proof,
                        },
                    );

                    // Check if all Round 2 messages from other parties collected.
                    if state.received.len() == n_others(&state.all_parties) {
                        let presignature = finalize(&state, &self.setup, &self.key_mat)?;
                        // Zeroize secrets before dropping Round2State
                        state.gamma_i.zeroize();
                        state.k_i.zeroize();
                        self.round = PresignRound::Done(presignature);
                    } else {
                        self.round = PresignRound::Round2(state);
                    }
                } else {
                    self.round = PresignRound::Round2(state);
                    return Err(TecdsaError::Other(
                        "unexpected message type in round 2".into(),
                    ));
                }
            }

            PresignRound::Done(_) => {
                return Err(TecdsaError::Other(
                    "presign already complete, no more messages expected".into(),
                ));
            }

            PresignRound::Poisoned => {
                return Err(TecdsaError::Other(
                    "presign machine is in poisoned state (previous transition failed)".into(),
                ));
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRound::Round1(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Round2(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Done(_) | PresignRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, PresignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            PresignRound::Done(presig) => Ok(presig),
            _ => Err(TecdsaError::Other("presign not complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            PresignRound::Round1(_) => 1,
            PresignRound::Round2(_) => 2,
            PresignRound::Done(_) => 3,
            PresignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
