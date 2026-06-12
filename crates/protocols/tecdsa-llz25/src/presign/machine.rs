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

//! StateMachine wrapper for the LLZ25 presigning protocol.
//!
//! Wraps the pure `presign_round1` / `verify_presign_message` functions into
//! a `StateMachine` that collects broadcasts from all parties, verifies ZK
//! proofs, and produces an `Llz25Presignature`.

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

// ---------------------------------------------------------------------------
// Serialized proofs (QFI elements as compact binary `Qfi::to_bytes`)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Serialized ciphertext (pe_k is ClHsmqkCiphertext, pe_gamma is Qfi)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerCiphertext {
    c1: Vec<u8>,
    c2: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Wire message types
// ---------------------------------------------------------------------------

/// Presign wire message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Llz25PresignMsg {
    /// Round 1 broadcast: serialized presign message + proofs.
    Round1(Vec<u8>),
}

/// Serialized payload for Round 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R1Payload {
    /// K_i = k_i * G (compressed point bytes).
    big_k_bytes: Vec<u8>,
    /// Gamma_i = gamma_i * G (compressed point bytes).
    big_gamma_bytes: Vec<u8>,
    /// pe_k ciphertext (c1, c2) as compact binary QFI encodings.
    pe_k: SerCiphertext,
    /// pe_gamma commitment (single QFI, compact binary encoding).
    pe_gamma: Vec<u8>,
    /// R_{CL-DL-EC} proof for (pe_k, K_i).
    proof_cl: SerRClDlEcProof,
    /// R_{Ped-EC} proof for (pe_gamma, Gamma_i).
    proof_ped: SerRPedEcProof,
}

// ---------------------------------------------------------------------------
// Presignature output
// ---------------------------------------------------------------------------

/// Output of the presigning phase, consumed by the sign phase.
///
/// Contains this party's secret presign state, all parties' broadcast
/// messages (verified), and the key share needed for signing.
pub struct Llz25Presignature {
    /// This party's presign secret state (k_i, gamma_i, NIM states).
    pub my_state: PresignState,
    /// Message-independent signing coefficients, with all NIM decoding already
    /// done offline. The online sign phase only needs these (plus the public
    /// key and presign messages).
    pub coefficients: PresignCoefficients,
    /// All parties' verified presign messages, ordered by party position.
    pub all_messages: Vec<PresignMessage>,
    /// This party's key share (needed for signing).
    pub key_share: Llz25KeyShare,
    /// CL setup seed (for recreating ClSetup in sign phase).
    pub cl_setup_seed: String,
    /// Whether to use 128-bit CL params.
    pub use_128bit: bool,
    /// 1-based party indices of the signing quorum.
    pub quorum_indices: Vec<u16>,
    /// This party's 0-based position in the quorum.
    pub my_pos: usize,
    /// pe_x ciphertext components for each quorum party, needed for sign phase.
    /// Each entry is (c1, c2) as compact binary QFI encodings.
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

// ---------------------------------------------------------------------------
// State machine internals
// ---------------------------------------------------------------------------

/// Received Round 1 data from a single party.
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

// ---------------------------------------------------------------------------
// Public state machine
// ---------------------------------------------------------------------------

/// StateMachine wrapper for LLZ25 presigning.
///
/// After construction, the machine is in Round 1. It broadcasts its own
/// presign message and waits to receive broadcasts from all other parties.
/// Once all broadcasts are received and ZK proofs verified, it transitions
/// to Done with an `Llz25Presignature`.
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
    /// Create a new presign state machine.
    ///
    /// Immediately runs `presign_round1` and queues the broadcast message.
    ///
    /// # Arguments
    /// - `my_id`: this party's ID (1-based PartyId)
    /// - `all_parties`: all participating party IDs (1-based)
    /// - `key_share`: this party's key share from keygen
    /// - `quorum_indices`: 1-based party indices of the signing quorum
    /// - `my_pos`: this party's 0-based position in the quorum
    /// - `setup`: CL-HSM setup (consumed)
    /// - `pk_crs`: the CRS public key for NIM encoding
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

        // Run presign Round 1.
        let (my_message, my_state) = presign_round1(&mut setup, &pk_crs)?;

        // Serialize the broadcast message.
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

        // Store our own broadcast.
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

    /// Deserialize an R1 payload into a `PresignMessage`.
    fn deserialize_r1(&self, data: &[u8]) -> Result<PresignMessage, TecdsaError> {
        let (payload, _): (R1Payload, _) =
            bincode::serde::decode_from_slice(data, bincode::config::standard())
                .map_err(|e| TecdsaError::Other(format!("deser R1: {e}")))?;

        // Deserialize EC points.
        let big_k = point_from_bytes(&payload.big_k_bytes)?;
        let big_gamma = point_from_bytes(&payload.big_gamma_bytes)?;

        // Deserialize pe_k ciphertext.
        let pe_k_c1 = Qfi::from_bytes(&payload.pe_k.c1);
        let pe_k_c2 = Qfi::from_bytes(&payload.pe_k.c2);
        let pe_k = self
            .setup
            .ct_from_components(&pe_k_c1, &pe_k_c2)
            .map_err(|e| TecdsaError::Other(format!("pe_k ct: {e}")))?;

        // Deserialize pe_gamma QFI.
        let pe_gamma = Qfi::from_bytes(&payload.pe_gamma);

        // Deserialize proofs.
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

    /// Finalize: verify all ZK proofs and build the presignature output.
    fn finalize(&mut self, state: Round1State) -> tecdsa_core::Result<Llz25Presignature> {
        // Verify ZK proofs for all received messages (except our own, already trusted).
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

        // Collect messages in party order.
        let all_messages: Vec<PresignMessage> =
            state.received.into_values().map(|r| r.message).collect();

        // Collect pe_x components for the quorum parties.
        let pe_x_components: Vec<(Vec<u8>, Vec<u8>)> = self
            .quorum_indices
            .iter()
            .map(|&idx| {
                let pos = (idx - 1) as usize;
                self.key_share.all_pe_x_components[pos].clone()
            })
            .collect();

        // Take ownership of my_state by swapping with a dummy.
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

        // Reconstruct pe_{x,j} ciphertexts for the quorum, then perform ALL NIM
        // decoding offline (message-independent) and fold it into the signing
        // coefficients consumed by the online sign phase.
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

        // Clone key_share fields we need.
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

/// Deserialize compressed EC point bytes to `k256::ProjectivePoint`.
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
