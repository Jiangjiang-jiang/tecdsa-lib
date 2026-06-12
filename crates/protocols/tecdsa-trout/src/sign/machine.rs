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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TroutSignMsg {
    FShares(TroutFSharePayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TroutFSharePayload {
    pub f_i_1_abc: (String, String, String),
    pub f_i_2_abc: (String, String, String),
}

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

struct FinalizeData {
    r_scalar: k256::Scalar,
    public_key: k256::ProjectivePoint,
    message: DataToSign<k256::Secp256k1>,
    setup: ClSetup,
}

pub struct TroutSignMachine {
    round: SignRound,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    finalize: Option<FinalizeData>,
    ia_report: Option<IaReport>,
}

impl TroutSignMachine {
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
        let r_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&r_scalar);
        let m_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(message.digest());
        let broadcasts = &my_presign.all_broadcasts;

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

        let (kt_a1, kt_a2) = aggregate_ciphertext_components(&setup, &kt_components)
            .map_err(|e| TecdsaError::Other(format!("agg_ct: {e}")))?;
        let u_b_agg = aggregate_commitments(&setup, &u_coms)
            .map_err(|e| TecdsaError::Other(format!("agg_com: {e}")))?;

        let sd1_public = ScaledDecryptPublic {
            a1: kt_a1,
            a2: kt_a2,
            b_agg: u_b_agg,
        };

        let (z_a1, z_a2) = aggregate_ciphertext_components(&setup, &z_components)
            .map_err(|e| TecdsaError::Other(format!("agg_ct z: {e}")))?;
        let u_b_agg2 = aggregate_commitments(&setup, &u_coms)
            .map_err(|e| TecdsaError::Other(format!("agg_com z: {e}")))?;

        let sd2_public = ScaledDecryptPublic {
            a1: z_a1,
            a2: z_a2,
            b_agg: u_b_agg2,
        };

        let sd1_input = ScaledDecryptPartyInput {
            alpha_i: my_presign.alpha_i.clone(),
            beta_i: my_presign.beta_i.clone(),
            b_i: tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&my_presign.u_i),
        };
        let f_i_1 = compute_f_share(&setup, &sd1_input, &sd1_public)
            .map_err(|e| TecdsaError::Other(format!("compute_f_share SD1: {e}")))?;

        let alpha_z = {
            let r_val = Integer::from_digits(&r_bytes, Order::Msf);
            let lid_val = Integer::from_digits(&my_presign.l_i_delta_i, Order::Msf);
            Integer::from(&r_val * &lid_val).to_digits::<u8>(Order::Msf)
        };
        let sd2_input = ScaledDecryptPartyInput {
            alpha_i: alpha_z,
            beta_i: my_presign.beta_i.clone(),
            b_i: tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&my_presign.u_i),
        };
        let f_i_2 = compute_f_share(&setup, &sd2_input, &sd2_public)
            .map_err(|e| TecdsaError::Other(format!("compute_f_share SD2: {e}")))?;

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

    fn deserialize_fshares(payload: &TroutFSharePayload) -> Result<(Qfi, Qfi), TecdsaError> {
        let (a1, b1, c1) = &payload.f_i_1_abc;
        let f_i_1 = qfi_from_abc(a1, b1, c1)
            .map_err(|e| TecdsaError::Other(format!("deser f_i_1: {e}")))?;
        let (a2, b2, c2) = &payload.f_i_2_abc;
        let f_i_2 = qfi_from_abc(a2, b2, c2)
            .map_err(|e| TecdsaError::Other(format!("deser f_i_2: {e}")))?;
        Ok((f_i_1, f_i_2))
    }

    fn finalize_signature(
        &self,
        state: Round1State,
    ) -> tecdsa_core::Result<Signature<k256::Secp256k1>> {
        let fin = self
            .finalize
            .as_ref()
            .ok_or_else(|| TecdsaError::Other("finalize data missing".into()))?;

        let mut f1_shares = Vec::new();
        let mut f2_shares = Vec::new();
        for fshare in state.received.into_values() {
            f1_shares.push(fshare.f_i_1);
            f2_shares.push(fshare.f_i_2);
        }

        let uk = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(
            &aggregate_and_solve(&fin.setup, &f1_shares)
                .map_err(|e| TecdsaError::Other(format!("agg_solve SD1: {e}")))?,
        );

        let u_mx = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(
            &aggregate_and_solve(&fin.setup, &f2_shares)
                .map_err(|e| TecdsaError::Other(format!("agg_solve SD2: {e}")))?,
        );

        let uk_inv = uk
            .invert()
            .into_option()
            .ok_or_else(|| TecdsaError::Other("u*k is zero, cannot invert".into()))?;

        let s = uk_inv * u_mx;
        let s = low_s_normalize::<k256::Secp256k1>(s);

        let sig = Signature { r: fin.r_scalar, s };

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
