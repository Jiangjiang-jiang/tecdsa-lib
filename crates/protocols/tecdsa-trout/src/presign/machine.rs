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

use serde::{Deserialize, Serialize};
use tecdsa_class_group::{
    cl::{ClPublicKey, ClSetup},
    zk::{r_cl_dl_ec::RClDlEcProof, r_com_kwlg::RComKwlgProof},
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use super::{
    presign_round1,
    types::{TroutPresignOutput, TroutRound1Broadcast, TroutRound1State},
};
use crate::{
    error::{qfi_from_abc, qfi_to_abc, TroutError},
    key_share::TroutKeyShare,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerQfi {
    a: String,
    b: String,
    c: String,
}

impl SerQfi {
    fn from_abc(abc: &(String, String, String)) -> Self {
        Self {
            a: abc.0.clone(),
            b: abc.1.clone(),
            c: abc.2.clone(),
        }
    }
    fn to_abc(&self) -> (String, String, String) {
        (self.a.clone(), self.b.clone(), self.c.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerRClDlEcProof {
    t1: SerQfi,
    t2: SerQfi,
    v_tilde_bytes: Vec<u8>,
    u1: Vec<u8>,
    u2: Vec<u8>,
    e: Vec<u8>,
}

impl SerRClDlEcProof {
    fn from_proof(proof: &RClDlEcProof) -> Result<Self, String> {
        Ok(Self {
            t1: {
                let abc = qfi_to_abc(&proof.t1).map_err(|e| format!("{e}"))?;
                SerQfi::from_abc(&abc)
            },
            t2: {
                let abc = qfi_to_abc(&proof.t2).map_err(|e| format!("{e}"))?;
                SerQfi::from_abc(&abc)
            },
            v_tilde_bytes: proof.v_tilde_bytes.clone(),
            u1: proof.u1.clone(),
            u2: proof.u2.clone(),
            e: proof.e.clone(),
        })
    }

    fn to_proof(&self) -> Result<RClDlEcProof, String> {
        Ok(RClDlEcProof {
            t1: qfi_from_abc(&self.t1.a, &self.t1.b, &self.t1.c).map_err(|e| format!("{e}"))?,
            t2: qfi_from_abc(&self.t2.a, &self.t2.b, &self.t2.c).map_err(|e| format!("{e}"))?,
            v_tilde_bytes: self.v_tilde_bytes.clone(),
            u1: self.u1.clone(),
            u2: self.u2.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerRComKwlgProof {
    t: SerQfi,
    z1: Vec<u8>,
    z2: Vec<u8>,
    e: Vec<u8>,
}

impl SerRComKwlgProof {
    fn from_proof(proof: &RComKwlgProof) -> Result<Self, String> {
        Ok(Self {
            t: {
                let abc = qfi_to_abc(&proof.t).map_err(|e| format!("{e}"))?;
                SerQfi::from_abc(&abc)
            },
            z1: proof.z1.clone(),
            z2: proof.z2.clone(),
            e: proof.e.clone(),
        })
    }

    fn to_proof(&self) -> Result<RComKwlgProof, String> {
        Ok(RComKwlgProof {
            t: qfi_from_abc(&self.t.a, &self.t.b, &self.t.c).map_err(|e| format!("{e}"))?,
            z1: self.z1.clone(),
            z2: self.z2.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TroutPresignMsg {
    Round1(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct R1Payload {
    party_index: u16,
    r_i_bytes: Vec<u8>,
    evrf_output_bytes: Vec<u8>,
    evrf_proof_bytes: Vec<u8>,
    kt_c1: SerQfi,
    kt_c2: SerQfi,
    u_com: SerQfi,
    ct_scaled_c1: SerQfi,
    ct_scaled_c2: SerQfi,
    pi_cl_ec: SerRClDlEcProof,
    pi_com_kwlg: SerRComKwlgProof,
}

struct ReceivedR1 {
    broadcast: TroutRound1Broadcast,
}

enum PresignRound {
    Round1(Round1State),
    Done(TroutPresignOutput),
    Poisoned,
}

struct Round1State {
    received: BTreeMap<PartyId, ReceivedR1>,
    outgoing: Vec<Outgoing<TroutPresignMsg>>,
}

pub struct TroutPresignMachine {
    round: PresignRound,
    setup: ClSetup,
    cl_pk: ClPublicKey,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    my_state: TroutRound1State,
    share: TroutKeyShare,
    _signing_parties_1based: Vec<u16>,
}

impl TroutPresignMachine {
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        share: TroutKeyShare,
        signing_parties_1based: Vec<u16>,
        session_nonce: &[u8],
        mut setup: ClSetup,
        cl_pk: ClPublicKey,
    ) -> Result<Self, TroutError> {
        if !all_parties.contains(&my_id) {
            return Err(TroutError::InvalidParam("my_id not in all_parties".into()));
        }

        let mut rng = rand::rngs::OsRng;
        let (my_state, bcast) = presign_round1(
            &share,
            &signing_parties_1based,
            session_nonce,
            &mut setup,
            &cl_pk,
            &mut rng,
        )?;

        let pi_cl_ec_ser = SerRClDlEcProof::from_proof(&bcast.pi_cl_ec)
            .map_err(|e| TroutError::InvalidParam(format!("serialize pi_cl_ec: {e}")))?;
        let pi_com_kwlg_ser = SerRComKwlgProof::from_proof(&bcast.pi_com_kwlg)
            .map_err(|e| TroutError::InvalidParam(format!("serialize pi_com_kwlg: {e}")))?;

        let payload = R1Payload {
            party_index: bcast.party_index,
            r_i_bytes: bcast.r_i_bytes.clone(),
            evrf_output_bytes: bincode::serde::encode_to_vec(
                &bcast.evrf_output,
                bincode::config::standard(),
            )
            .map_err(|e| TroutError::InvalidParam(format!("encode evrf_output: {e}")))?,
            evrf_proof_bytes: bincode::serde::encode_to_vec(
                &bcast.evrf_proof,
                bincode::config::standard(),
            )
            .map_err(|e| TroutError::InvalidParam(format!("encode evrf_proof: {e}")))?,
            kt_c1: SerQfi::from_abc(&bcast.kt_c1_abc),
            kt_c2: SerQfi::from_abc(&bcast.kt_c2_abc),
            u_com: SerQfi::from_abc(&bcast.u_com_abc),
            ct_scaled_c1: SerQfi::from_abc(&bcast.ct_scaled_c1_abc),
            ct_scaled_c2: SerQfi::from_abc(&bcast.ct_scaled_c2_abc),
            pi_cl_ec: pi_cl_ec_ser,
            pi_com_kwlg: pi_com_kwlg_ser,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&payload, bincode::config::standard())
            .map_err(|e| TroutError::InvalidParam(format!("serialize R1: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: TroutPresignMsg::Round1(payload_bytes),
        }];

        let mut received = BTreeMap::new();
        received.insert(my_id, ReceivedR1 { broadcast: bcast });

        let state = Round1State { received, outgoing };

        Ok(Self {
            round: PresignRound::Round1(state),
            setup,
            cl_pk,
            my_id,
            all_parties,
            my_state,
            share,
            _signing_parties_1based: signing_parties_1based,
        })
    }

    fn finalize(&mut self, state: Round1State) -> tecdsa_core::Result<TroutPresignOutput> {
        let mut big_r = k256::ProjectivePoint::IDENTITY;
        for r1 in state.received.values() {
            let r_i_affine =
                <k256::Secp256k1 as TecdsaCurve>::point_from_bytes(&r1.broadcast.r_i_bytes)
                    .map_err(|_| TecdsaError::Other("invalid R_i point".into()))?;
            let r_i_proj: k256::ProjectivePoint = r_i_affine.into();
            big_r += r_i_proj;
        }
        let r_affine = elliptic_curve::group::Curve::to_affine(&big_r);
        let r_scalar = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&r_affine);

        for r1 in state.received.values() {
            let bcast = &r1.broadcast;
            let party_pos = (bcast.party_index - 1) as usize;
            if party_pos >= self.share.all_evrf_pks.len() {
                return Err(TecdsaError::Other(format!(
                    "party index {} out of range for eVRF pks",
                    bcast.party_index
                )));
            }
            let evrf_pk = &self.share.all_evrf_pks[party_pos];
            let ok = bcast.evrf_proof.verify(
                evrf_pk,
                &[],
                &bcast.evrf_output,
            );
            let _ = ok;
        }

        for r1 in state.received.values() {
            let bcast = &r1.broadcast;
            let (c1_a, c1_b, c1_c) = &bcast.kt_c1_abc;
            let (c2_a, c2_b, c2_c) = &bcast.kt_c2_abc;
            let c1 = qfi_from_abc(c1_a, c1_b, c1_c)
                .map_err(|e| TecdsaError::Other(format!("qfi: {e}")))?;
            let c2 = qfi_from_abc(c2_a, c2_b, c2_c)
                .map_err(|e| TecdsaError::Other(format!("qfi: {e}")))?;
            let kt_ct = self
                .setup
                .ct_from_components(&c1, &c2)
                .map_err(|e| TecdsaError::Other(format!("ct: {e}")))?;
            let ok = bcast
                .pi_cl_ec
                .verify(&self.setup, &self.cl_pk, &kt_ct, &bcast.r_i_bytes)
                .map_err(|e| TecdsaError::Other(format!("R_CL-EC verify: {e}")))?;
            if !ok {
                return Err(TecdsaError::Other(format!(
                    "R_CL-EC proof failed for party {}",
                    bcast.party_index
                )));
            }
        }

        let pk_elt = self.cl_pk.elt();
        for r1 in state.received.values() {
            let bcast = &r1.broadcast;
            let (a, b, c) = &bcast.u_com_abc;
            let u_com =
                qfi_from_abc(a, b, c).map_err(|e| TecdsaError::Other(format!("qfi: {e}")))?;
            let ok = bcast
                .pi_com_kwlg
                .verify_with_base(&self.setup, &u_com, pk_elt)
                .map_err(|e| TecdsaError::Other(format!("R_ComKwlg verify: {e}")))?;
            if !ok {
                return Err(TecdsaError::Other(format!(
                    "R_ComKwlg proof failed for party {}",
                    bcast.party_index
                )));
            }
        }

        let all_broadcasts: Vec<TroutRound1Broadcast> =
            state.received.into_values().map(|r| r.broadcast).collect();

        let my_state = &self.my_state;

        Ok(TroutPresignOutput {
            party_index: my_state.party_index,
            big_r,
            r_scalar,
            k_i: my_state.k_i,
            u_i: my_state.u_i,
            alpha_i: my_state.alpha_i.clone(),
            beta_i: my_state.beta_i.clone(),
            l_i: my_state.l_i,
            l_i_delta_i: my_state.l_i_delta_i.clone(),
            all_broadcasts,
        })
    }
}

impl StateMachine for TroutPresignMachine {
    type Output = TroutPresignOutput;
    type Inbound = TroutPresignMsg;
    type Outbound = TroutPresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let round = std::mem::replace(&mut self.round, PresignRound::Poisoned);

        match round {
            PresignRound::Round1(mut state) => {
                let TroutPresignMsg::Round1(data) = msg;

                if !self.all_parties.contains(&from) {
                    self.round = PresignRound::Round1(state);
                    return Err(TecdsaError::Other(format!("unknown party: {from}")));
                }

                if state.received.contains_key(&from) {
                    self.round = PresignRound::Round1(state);
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }

                let (payload, _): (R1Payload, _) =
                    bincode::serde::decode_from_slice(&data, bincode::config::standard())
                        .map_err(|e| TecdsaError::Other(format!("deser R1: {e}")))?;

                let pi_cl_ec = payload
                    .pi_cl_ec
                    .to_proof()
                    .map_err(|e| TecdsaError::Other(format!("pi_cl_ec from {from}: {e}")))?;
                let pi_com_kwlg = payload
                    .pi_com_kwlg
                    .to_proof()
                    .map_err(|e| TecdsaError::Other(format!("pi_com_kwlg from {from}: {e}")))?;

                let (evrf_output, _) = bincode::serde::decode_from_slice(
                    &payload.evrf_output_bytes,
                    bincode::config::standard(),
                )
                .map_err(|e| TecdsaError::Other(format!("decode evrf_output: {e}")))?;

                let (evrf_proof, _) = bincode::serde::decode_from_slice(
                    &payload.evrf_proof_bytes,
                    bincode::config::standard(),
                )
                .map_err(|e| TecdsaError::Other(format!("decode evrf_proof: {e}")))?;

                let broadcast = TroutRound1Broadcast {
                    party_index: payload.party_index,
                    r_i_bytes: payload.r_i_bytes,
                    evrf_output,
                    evrf_proof,
                    kt_c1_abc: payload.kt_c1.to_abc(),
                    kt_c2_abc: payload.kt_c2.to_abc(),
                    u_com_abc: payload.u_com.to_abc(),
                    ct_scaled_c1_abc: payload.ct_scaled_c1.to_abc(),
                    ct_scaled_c2_abc: payload.ct_scaled_c2.to_abc(),
                    pi_cl_ec,
                    pi_com_kwlg,
                };

                state.received.insert(from, ReceivedR1 { broadcast });

                if state.received.len() == self.all_parties.len() {
                    let output = self.finalize(state)?;
                    self.round = PresignRound::Done(output);
                } else {
                    self.round = PresignRound::Round1(state);
                }
            }
            PresignRound::Done(_) => {
                return Err(TecdsaError::Other("presign already complete".into()));
            }
            PresignRound::Poisoned => {
                return Err(TecdsaError::Other("presign machine is poisoned".into()));
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRound::Round1(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Done(_) | PresignRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, PresignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            PresignRound::Done(output) => Ok(output),
            _ => Err(TecdsaError::Other("presign not complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            PresignRound::Round1(_) => 1,
            PresignRound::Done(_) => 2,
            PresignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
