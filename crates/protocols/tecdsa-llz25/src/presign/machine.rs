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
    cl::{ClPublicKey as ClHsmqkPublicKey, ClSetup, Qfi},
    zk::{r_cl_dl_ec::RClDlEcProof, r_ped_ec::RPedEcProof},
};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use super::{
    compute_presign_coefficients, presign_round1, verify_presign_message, PresignCoefficients,
    PresignMessage, PresignState,
};
use crate::{error::Llz25Error, key_share::Llz25KeyShare};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerRClDlEcProof {
    t1: Vec<u8>,
    t2: Vec<u8>,
    v_tilde_bytes: Vec<u8>,
    u1: Vec<u8>,
    u2: Vec<u8>,
    e: Vec<u8>,
}

impl SerRClDlEcProof {
    fn from_proof(proof: &RClDlEcProof) -> Result<Self, String> {
        Ok(Self {
            t1: proof.t1.to_bytes(),
            t2: proof.t2.to_bytes(),
            v_tilde_bytes: proof.v_tilde_bytes.clone(),
            u1: proof.u1.clone(),
            u2: proof.u2.clone(),
            e: proof.e.clone(),
        })
    }

    fn to_proof(&self) -> Result<RClDlEcProof, String> {
        Ok(RClDlEcProof {
            t1: Qfi::from_bytes(&self.t1),
            t2: Qfi::from_bytes(&self.t2),
            v_tilde_bytes: self.v_tilde_bytes.clone(),
            u1: self.u1.clone(),
            u2: self.u2.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerRPedEcProof {
    c_tilde: Vec<u8>,
    v_tilde_bytes: Vec<u8>,
    s_r: Vec<u8>,
    s_v: Vec<u8>,
    e: Vec<u8>,
}

impl SerRPedEcProof {
    fn from_proof(proof: &RPedEcProof) -> Result<Self, String> {
        Ok(Self {
            c_tilde: proof.c_tilde.to_bytes(),
            v_tilde_bytes: proof.v_tilde_bytes.clone(),
            s_r: proof.s_r.clone(),
            s_v: proof.s_v.clone(),
            e: proof.e.clone(),
        })
    }

    fn to_proof(&self) -> Result<RPedEcProof, String> {
        Ok(RPedEcProof {
            c_tilde: Qfi::from_bytes(&self.c_tilde),
            v_tilde_bytes: self.v_tilde_bytes.clone(),
            s_r: self.s_r.clone(),
            s_v: self.s_v.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerCiphertext {
    c1: Vec<u8>,
    c2: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Llz25PresignMsg {
    Round1(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct R1Payload {
    big_k_bytes: Vec<u8>,
    big_gamma_bytes: Vec<u8>,
    pe_k: SerCiphertext,
    pe_gamma: Vec<u8>,
    proof_cl: SerRClDlEcProof,
    proof_ped: SerRPedEcProof,
}

pub struct Llz25Presignature {
    pub my_state: PresignState,
    pub coefficients: PresignCoefficients,
    pub all_messages: Vec<PresignMessage>,
    pub key_share: Llz25KeyShare,
    pub cl_setup_seed: String,
    pub use_128bit: bool,
    pub quorum_indices: Vec<u16>,
    pub my_pos: usize,
    pub pe_x_components: Vec<(Vec<u8>, Vec<u8>)>,
}

impl std::fmt::Debug for Llz25Presignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Llz25Presignature")
            .field("quorum_indices", &self.quorum_indices)
            .field("my_pos", &self.my_pos)
            .finish_non_exhaustive()
    }
}

struct ReceivedR1 {
    message: PresignMessage,
}

enum PresignRound {
    Round1(Round1State),
    Done(Llz25Presignature),
    Poisoned,
}

struct Round1State {
    received: BTreeMap<PartyId, ReceivedR1>,
    outgoing: Vec<Outgoing<Llz25PresignMsg>>,
}

pub struct Llz25PresignMachine {
    round: PresignRound,
    setup: ClSetup,
    pk_crs: ClHsmqkPublicKey,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    my_state: PresignState,
    key_share: Llz25KeyShare,
    quorum_indices: Vec<u16>,
    my_pos: usize,
}

impl Llz25PresignMachine {
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        key_share: Llz25KeyShare,
        quorum_indices: Vec<u16>,
        my_pos: usize,
        mut setup: ClSetup,
        pk_crs: ClHsmqkPublicKey,
    ) -> Result<Self, Llz25Error> {
        if !all_parties.contains(&my_id) {
            return Err(Llz25Error::Protocol("my_id not in all_parties".into()));
        }

        let (my_message, my_state) = presign_round1(&mut setup, &pk_crs)?;

        use elliptic_curve::group::GroupEncoding;
        let big_k_bytes = my_message.big_k.to_bytes().to_vec();
        let big_gamma_bytes = my_message.big_gamma.to_bytes().to_vec();

        let (pe_k_c1, pe_k_c2) = setup
            .ct_components(&my_message.pe_k)
            .map_err(|e| Llz25Error::ClassGroup(format!("ct_components: {e}")))?;
        let pe_k_c1_bytes = pe_k_c1.to_bytes();
        let pe_k_c2_bytes = pe_k_c2.to_bytes();

        let pe_gamma_bytes = my_message.pe_gamma.to_bytes();

        let proof_cl_ser = SerRClDlEcProof::from_proof(&my_message.proof_cl)
            .map_err(|e| Llz25Error::Protocol(format!("serialize proof_cl: {e}")))?;
        let proof_ped_ser = SerRPedEcProof::from_proof(&my_message.proof_ped)
            .map_err(|e| Llz25Error::Protocol(format!("serialize proof_ped: {e}")))?;

        let payload = R1Payload {
            big_k_bytes,
            big_gamma_bytes,
            pe_k: SerCiphertext {
                c1: pe_k_c1_bytes,
                c2: pe_k_c2_bytes,
            },
            pe_gamma: pe_gamma_bytes,
            proof_cl: proof_cl_ser,
            proof_ped: proof_ped_ser,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&payload, bincode::config::standard())
            .map_err(|e| Llz25Error::Protocol(format!("serialize R1: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Llz25PresignMsg::Round1(payload_bytes),
        }];

        let mut received = BTreeMap::new();
        received.insert(
            my_id,
            ReceivedR1 {
                message: my_message,
            },
        );

        let state = Round1State { received, outgoing };

        Ok(Self {
            round: PresignRound::Round1(state),
            setup,
            pk_crs,
            my_id,
            all_parties,
            my_state,
            key_share,
            quorum_indices,
            my_pos,
        })
    }

    fn deserialize_r1(&self, data: &[u8]) -> Result<PresignMessage, TecdsaError> {
        let (payload, _): (R1Payload, _) =
            bincode::serde::decode_from_slice(data, bincode::config::standard())
                .map_err(|e| TecdsaError::Other(format!("deser R1: {e}")))?;

        let big_k = point_from_bytes(&payload.big_k_bytes)?;
        let big_gamma = point_from_bytes(&payload.big_gamma_bytes)?;

        let pe_k_c1 = Qfi::from_bytes(&payload.pe_k.c1);
        let pe_k_c2 = Qfi::from_bytes(&payload.pe_k.c2);
        let pe_k = self
            .setup
            .ct_from_components(&pe_k_c1, &pe_k_c2)
            .map_err(|e| TecdsaError::Other(format!("pe_k ct: {e}")))?;

        let pe_gamma = Qfi::from_bytes(&payload.pe_gamma);

        let proof_cl = payload
            .proof_cl
            .to_proof()
            .map_err(|e| TecdsaError::Other(format!("proof_cl: {e}")))?;
        let proof_ped = payload
            .proof_ped
            .to_proof()
            .map_err(|e| TecdsaError::Other(format!("proof_ped: {e}")))?;

        Ok(PresignMessage {
            big_k,
            big_gamma,
            pe_k,
            pe_gamma,
            proof_cl,
            proof_ped,
        })
    }

    fn finalize(&mut self, state: Round1State) -> tecdsa_core::Result<Llz25Presignature> {
        for (&pid, r1) in &state.received {
            if pid == self.my_id {
                continue;
            }
            let valid = verify_presign_message(&self.setup, &self.pk_crs, &r1.message)
                .map_err(|e| TecdsaError::Other(format!("verify presign from {pid}: {e}")))?;
            if !valid {
                return Err(TecdsaError::InvalidProof(format!(
                    "presign ZK proof verification failed for party {pid}"
                )));
            }
        }

        let all_messages: Vec<PresignMessage> =
            state.received.into_values().map(|r| r.message).collect();

        let pe_x_components: Vec<(Vec<u8>, Vec<u8>)> = self
            .quorum_indices
            .iter()
            .map(|&idx| {
                let pos = (idx - 1) as usize;
                self.key_share.all_pe_x_components[pos].clone()
            })
            .collect();

        let my_state = std::mem::replace(
            &mut self.my_state,
            PresignState {
                k_i: k256::Scalar::ZERO,
                gamma_i: k256::Scalar::ZERO,
                st_k_bytes: Vec::new(),
                st_gamma_r_bytes: Vec::new(),
                st_gamma_x_bytes: Vec::new(),
            },
        );

        let pe_x_list: Vec<_> = pe_x_components
            .iter()
            .map(|(c1_bytes, c2_bytes)| {
                let c1 = Qfi::from_bytes(c1_bytes);
                let c2 = Qfi::from_bytes(c2_bytes);
                self.setup
                    .ct_from_components(&c1, &c2)
                    .map_err(|e| TecdsaError::Other(format!("pe_x ct: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let coefficients = compute_presign_coefficients(
            &mut self.setup,
            &self.key_share,
            &my_state,
            &all_messages,
            &pe_x_list,
            &self.quorum_indices,
            self.my_pos,
        )
        .map_err(|e| TecdsaError::Other(format!("compute_presign_coefficients: {e}")))?;

        let key_share_clone = Llz25KeyShare {
            party_index: self.key_share.party_index,
            secret_share: self.key_share.secret_share,
            public_key: self.key_share.public_key,
            public_shares: self.key_share.public_shares.clone(),
            st_x_bytes: self.key_share.st_x_bytes.clone(),
            pe_x_components: self.key_share.pe_x_components.clone(),
            all_pe_x_components: self.key_share.all_pe_x_components.clone(),
            cl_setup_seed: self.key_share.cl_setup_seed.clone(),
            use_128bit_security: self.key_share.use_128bit_security,
            threshold: self.key_share.threshold,
            total: self.key_share.total,
        };

        Ok(Llz25Presignature {
            my_state,
            coefficients,
            all_messages,
            key_share: key_share_clone,
            cl_setup_seed: self.key_share.cl_setup_seed.clone(),
            use_128bit: self.key_share.use_128bit_security,
            quorum_indices: self.quorum_indices.clone(),
            my_pos: self.my_pos,
            pe_x_components,
        })
    }
}

fn point_from_bytes(bytes: &[u8]) -> Result<k256::ProjectivePoint, TecdsaError> {
    use tecdsa_curve::TecdsaCurve;
    let affine = <k256::Secp256k1 as TecdsaCurve>::point_from_bytes(bytes)
        .map_err(|_| TecdsaError::Other("invalid EC point".into()))?;
    Ok(affine.into())
}

impl StateMachine for Llz25PresignMachine {
    type Output = Llz25Presignature;
    type Inbound = Llz25PresignMsg;
    type Outbound = Llz25PresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let round = std::mem::replace(&mut self.round, PresignRound::Poisoned);

        match round {
            PresignRound::Round1(mut state) => {
                let Llz25PresignMsg::Round1(data) = msg;

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

                let message = match self.deserialize_r1(&data) {
                    Ok(m) => m,
                    Err(e) => {
                        self.round = PresignRound::Round1(state);
                        return Err(e);
                    }
                };

                state.received.insert(from, ReceivedR1 { message });

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
