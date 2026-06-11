// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 presigning protocol (DRG-based, WMY23 Figure 5).
//!
//! Produces a message-independent [`Wmy23Presignature`] using the paper's
//! three presign phases:
//!
//! 1. **DRG (Phase 1):** Round 1 broadcasts the DRG.Gen public material
//!    for both `k_i` and `gamma_i` (Pedersen VSS commitments, CL
//!    ciphertext, R_Enc-PC proof) plus a hash commitment to
//!    `Gamma_i = gamma_i * G`, and sends the Pedersen VSS shares P2P.
//!    On the Round 1 -> 2 transition each party runs DRG.GenVf
//!    (VSS share check + R_Enc-PC verification) and DRG.Comb.
//! 2. **MtAwc (Phase 2):** Round 2 decommits `Gamma_i` and sends the
//!    MtAwc Alice ciphertexts of `hat_k_i` and `hat_x_i`; Round 3 answers
//!    with the MtAwc Bob response ciphertexts.
//! 3. **Share revelation (Phase 3):** Round 4 broadcasts `delta_i` and
//!    `D_i = Gamma^{hat_k_i}`. Finalization checks
//!    `g^delta == prod_j D_j` and reconstructs `R = Gamma^{1/delta}`.
//!
//! ## Serialization
//!
//! All class-group elements (ciphertext components, proof commitments)
//! travel as compact binary `Qfi::to_bytes()` blobs; EC points as 33-byte
//! compressed SEC1; scalars as 32-byte big-endian. Payloads are encoded
//! with `bincode`.
//!
//! Reference: Wong, Ma, Yin, Chow. "Real Threshold ECDSA." NDSS 2023.

pub mod rounds;
pub mod types;

use std::collections::BTreeMap;

use elliptic_curve::{group::GroupEncoding, PrimeField};
use serde::{Deserialize, Serialize};
use tecdsa_class_group::{
    cl::{ClCiphertext, ClSetup, Qfi},
    drg::PedersenVssShare,
    zk::r_enc_pc::REncPcProof,
};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};
pub use types::Wmy23Presignature;

use crate::key_share::Wmy23KeyShare;
use rounds::{
    DrgPresignR1Bcast, DrgPresignR1P2P, DrgPresignR1State, DrgPresignR2Bcast, DrgPresignR2State,
    DrgPresignR3Data, DrgPresignR4State,
};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Messages exchanged during WMY23 presigning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wmy23PresignMsg {
    /// Round 1 broadcast part: DRG.Gen public data + Gamma commitment
    /// (serialised [`R1BcastPayload`]).
    Round1Bcast(Vec<u8>),
    /// Round 1 P2P part: Pedersen VSS shares for the recipient
    /// (serialised [`R1P2pPayload`]).
    Round1P2p(Vec<u8>),
    /// Round 2 (per recipient): Gamma decommit + MtAwc Alice ciphertexts.
    Round2(Vec<u8>),
    /// Round 3 (per recipient): MtAwc Bob response ciphertexts.
    Round3(Vec<u8>),
    /// Round 4 broadcast: revealed `delta_i` + `D_i`.
    Round4(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Binary serialization helpers (Qfi::to_bytes / from_bytes based)
// ---------------------------------------------------------------------------

/// A CL ciphertext serialised as two compact binary QFI blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedClCt {
    c1: Vec<u8>,
    c2: Vec<u8>,
}

impl SerializedClCt {
    fn from_ct(ct: &ClCiphertext) -> Self {
        Self {
            c1: ct.c1().to_bytes(),
            c2: ct.c2().to_bytes(),
        }
    }

    fn to_ct(&self) -> ClCiphertext {
        ClCiphertext::new(Qfi::from_bytes(&self.c1), Qfi::from_bytes(&self.c2))
    }
}

/// An R_Enc-PC proof serialised with binary QFI commitments.
///
/// The Fiat-Shamir transcript hashes the `Qfi` values themselves (via the
/// CL setup), and `Qfi::from_bytes(to_bytes(q)) == q`, so prover and
/// verifier stay transcript-symmetric across serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedREncPc {
    r_pc: Vec<u8>,
    r_c0: Vec<u8>,
    r_c1: Vec<u8>,
    z1: Vec<u8>,
    z2: Vec<u8>,
    z3: Vec<u8>,
    e: Vec<u8>,
}

impl SerializedREncPc {
    fn from_proof(p: &REncPcProof) -> Self {
        Self {
            r_pc: p.r_pc_bytes.clone(),
            r_c0: p.r_c0.to_bytes(),
            r_c1: p.r_c1.to_bytes(),
            z1: p.z1.clone(),
            z2: p.z2.clone(),
            z3: p.z3.clone(),
            e: p.e.clone(),
        }
    }

    fn to_proof(&self) -> REncPcProof {
        REncPcProof {
            r_pc_bytes: self.r_pc.clone(),
            r_c0: Qfi::from_bytes(&self.r_c0),
            r_c1: Qfi::from_bytes(&self.r_c1),
            z1: self.z1.clone(),
            z2: self.z2.clone(),
            z3: self.z3.clone(),
            e: self.e.clone(),
        }
    }
}

/// A Pedersen VSS share serialised as two 32-byte scalars.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedVssShare {
    /// Recipient's local 1-based index.
    index: u16,
    value: Vec<u8>,
    randomness: Vec<u8>,
}

impl SerializedVssShare {
    fn from_share(s: &PedersenVssShare) -> Self {
        Self {
            index: s.index,
            value: s.value.to_repr().to_vec(),
            randomness: s.randomness.to_repr().to_vec(),
        }
    }

    fn to_share(&self) -> Result<PedersenVssShare, String> {
        Ok(PedersenVssShare {
            index: self.index,
            value: scalar_from_bytes(&self.value, "vss value")?,
            randomness: scalar_from_bytes(&self.randomness, "vss randomness")?,
        })
    }
}

/// Deserialize a 32-byte big-endian scalar.
fn scalar_from_bytes(bytes: &[u8], label: &str) -> Result<k256::Scalar, String> {
    if bytes.len() != 32 {
        return Err(format!("invalid scalar length for {label}"));
    }
    let mut repr = k256::FieldBytes::default();
    repr.copy_from_slice(bytes);
    Option::from(k256::Scalar::from_repr(repr)).ok_or_else(|| format!("invalid scalar: {label}"))
}

/// Deserialize a compressed EC point from bytes.
fn point_from_bytes(bytes: &[u8], label: &str) -> Result<k256::ProjectivePoint, String> {
    let repr = k256::CompressedPoint::try_from(bytes)
        .map_err(|e| format!("invalid point bytes ({label}): {e}"))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| format!("invalid EC point: {label}"))
}

fn points_to_bytes(points: &[k256::ProjectivePoint]) -> Vec<Vec<u8>> {
    points.iter().map(|p| p.to_bytes().to_vec()).collect()
}

fn points_from_bytes(
    bytes: &[Vec<u8>],
    label: &str,
) -> Result<Vec<k256::ProjectivePoint>, String> {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| point_from_bytes(b, &format!("{label}[{i}]")))
        .collect()
}

// ---------------------------------------------------------------------------
// Round payloads
// ---------------------------------------------------------------------------

/// Round 1 broadcast payload: DRG.Gen public data for k and gamma.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R1BcastPayload {
    /// Hash commitment to `Gamma_i`.
    commitment: [u8; 32],
    /// Pedersen VSS polynomial commitments for k_i (33-byte points).
    k_commitments: Vec<Vec<u8>>,
    /// Pedersen VSS polynomial commitments for gamma_i.
    gamma_commitments: Vec<Vec<u8>>,
    /// CL ciphertext of k_i under the sender's key.
    k_ct: SerializedClCt,
    /// R_Enc-PC proof for the k ciphertext.
    k_proof: SerializedREncPc,
    /// CL ciphertext of gamma_i under the sender's key.
    gamma_ct: SerializedClCt,
    /// R_Enc-PC proof for the gamma ciphertext.
    gamma_proof: SerializedREncPc,
}

/// Round 1 P2P payload: the recipient's Pedersen VSS shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R1P2pPayload {
    k_share: SerializedVssShare,
    gamma_share: SerializedVssShare,
}

/// Round 2 payload (per recipient): decommit + MtAwc Alice ciphertexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R2Payload {
    /// Commitment nonce (32 bytes).
    nonce: [u8; 32],
    /// Gamma point bytes (compressed).
    gamma_point_bytes: Vec<u8>,
    /// MtAwc Alice ciphertext of `hat_k_i` addressed to the recipient.
    ct_k: SerializedClCt,
    /// MtAwc Alice ciphertext of `hat_x_i` addressed to the recipient.
    ct_x: SerializedClCt,
}

/// Round 3 payload (per recipient): MtAwc Bob responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R3Payload {
    /// MtAwc response ciphertext c_alpha for the gamma MtA.
    gamma_c_alpha: SerializedClCt,
    /// g^beta point for gamma MtA (compressed bytes).
    gamma_g_beta_bytes: Vec<u8>,
    /// MtAwc response ciphertext c_alpha for the key MtA.
    x_c_alpha: SerializedClCt,
    /// g^nu point for key MtA (compressed bytes).
    x_g_beta_bytes: Vec<u8>,
}

/// Round 4 broadcast payload: share revelation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R4Payload {
    /// Revealed `delta_i` (32-byte scalar).
    delta_i: Vec<u8>,
    /// `D_i = Gamma^{hat_k_i}` (33-byte point).
    big_d_i: Vec<u8>,
}

fn encode<T: Serialize>(value: &T, label: &str) -> tecdsa_core::Result<Vec<u8>> {
    bincode::serde::encode_to_vec(value, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("serialize {label}: {e}")))
}

fn decode<T: serde::de::DeserializeOwned>(data: &[u8], label: &str) -> tecdsa_core::Result<T> {
    let (value, _) = bincode::serde::decode_from_slice(data, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("deserialize {label}: {e}")))?;
    Ok(value)
}

// ---------------------------------------------------------------------------
// Internal per-party received data
// ---------------------------------------------------------------------------

/// Received Round 2 data from a single party.
struct ReceivedR2 {
    nonce: [u8; 32],
    gamma_point_bytes: Vec<u8>,
    /// MtAwc Alice ciphertext of the sender's `hat_k_j`, addressed to us.
    ct_k: ClCiphertext,
    /// MtAwc Alice ciphertext of the sender's `hat_x_j`, addressed to us.
    ct_x: ClCiphertext,
}

/// Received Round 3 data from a single party (MtAwc Bob response).
struct ReceivedR3 {
    gamma_c_alpha: ClCiphertext,
    gamma_g_beta: k256::ProjectivePoint,
    x_c_alpha: ClCiphertext,
    x_g_beta: k256::ProjectivePoint,
}

/// Received Round 4 data from a single party (share revelation).
struct ReceivedR4 {
    delta_i: k256::Scalar,
    big_d_i: k256::ProjectivePoint,
}

// ---------------------------------------------------------------------------
// State machine internal states
// ---------------------------------------------------------------------------

/// Round 1 state: waiting for DRG broadcasts + VSS shares from all parties.
struct Round1State {
    key_share: Wmy23KeyShare,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    r1_state: DrgPresignR1State,
    /// Own Round 1 broadcast (kept for the local view of `r1_bcasts`).
    my_bcast: DrgPresignR1Bcast,
    /// Received Round 1 broadcasts from other parties.
    bcasts: BTreeMap<PartyId, DrgPresignR1Bcast>,
    /// Received Round 1 P2P shares from other parties.
    p2ps: BTreeMap<PartyId, DrgPresignR1P2P>,
    outgoing: Vec<Outgoing<Wmy23PresignMsg>>,
}

/// Round 2 state: waiting for decommits + MtAwc Alice ciphertexts.
struct Round2State {
    key_share: Wmy23KeyShare,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    /// Round 1 hash commitments of all parties (local order).
    r1_commitments: Vec<[u8; 32]>,
    r1_state: DrgPresignR1State,
    r2_state: DrgPresignR2State,
    /// Own full Round 2 broadcast (per-recipient ciphertext vectors).
    my_r2_bcast: DrgPresignR2Bcast,
    received: BTreeMap<PartyId, ReceivedR2>,
    outgoing: Vec<Outgoing<Wmy23PresignMsg>>,
}

/// Round 3 state: waiting for MtAwc Bob responses.
struct Round3State {
    key_share: Wmy23KeyShare,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    r1_commitments: Vec<[u8; 32]>,
    r1_state: DrgPresignR1State,
    r2_state: DrgPresignR2State,
    /// All parties' Round 2 broadcasts in local order (own entry is
    /// complete; others carry only the ciphertexts addressed to us).
    r2_bcasts: Vec<DrgPresignR2Bcast>,
    /// Own MtAwc Bob outputs (with real betas).
    my_r3: DrgPresignR3Data,
    received: BTreeMap<PartyId, ReceivedR3>,
    outgoing: Vec<Outgoing<Wmy23PresignMsg>>,
}

/// Round 4 state: waiting for revealed delta_i / D_i from all parties.
struct Round4State {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    r4_state: DrgPresignR4State,
    received: BTreeMap<PartyId, ReceivedR4>,
    outgoing: Vec<Outgoing<Wmy23PresignMsg>>,
}

/// The internal round state for the presign state machine.
enum PresignRound {
    Round1(Round1State),
    Round2(Round2State),
    Round3(Round3State),
    Round4(Round4State),
    Done(Wmy23Presignature),
    Poisoned,
}

// ---------------------------------------------------------------------------
// PresignConfig
// ---------------------------------------------------------------------------

/// Configuration for the WMY23 presign state machine.
pub struct PresignConfig {
    /// The key share from keygen.
    pub key_share: Wmy23KeyShare,
    /// This party's identifier.
    pub my_id: PartyId,
    /// All signing party identifiers in consistent order.
    pub signer_parties: Vec<PartyId>,
    /// Pre-created CL setup (stored directly in the machine since
    /// bicycl-rs v0.2.2 makes `ClSetup` `Send`).
    pub cl_setup: ClSetup,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Global 1-based keygen indices of the quorum, in signer order.
///
/// By convention WMY23 uses `PartyId(i)` for the party whose global
/// 1-based keygen index is `i`.
fn signer_ids(all_parties: &[PartyId]) -> Vec<u16> {
    all_parties.iter().map(|p| p.0).collect()
}

/// Number of other parties (total - 1).
fn n_others(all_parties: &[PartyId]) -> usize {
    all_parties.len() - 1
}

/// 0-based local position of `party` within the quorum.
fn local_pos(all_parties: &[PartyId], party: PartyId) -> Option<usize> {
    all_parties.iter().position(|p| *p == party)
}

// ---------------------------------------------------------------------------
// WMY23 presigning state machine
// ---------------------------------------------------------------------------

/// WMY23 presigning state machine (4 rounds, DRG-based).
///
/// Round structure (offline):
///
/// | Round | Phase (paper) | Content |
/// |-------|---------------|---------|
/// | 1 | DRG Gen | VSS commitments, CL ct + R_Enc-PC proofs (bcast), VSS shares (P2P) |
/// | 2 | DRG GenVf/Comb + MtA | Gamma decommit + MtAwc Alice ciphertexts |
/// | 3 | MtA | MtAwc Bob responses |
/// | 4 | Reveal | delta_i + D_i broadcast |
///
/// Since bicycl-rs v0.2.2, `ClSetup` is `Send`, so it is stored directly
/// in the machine and reused across round transitions.
pub struct Wmy23PresignMachine {
    round: PresignRound,
    setup: ClSetup,
}

impl Wmy23PresignMachine {
    /// Create a new WMY23 presign state machine.
    ///
    /// Immediately runs presign Round 1 (DRG.Gen for `k_i` and `gamma_i`)
    /// and queues the Round 1 broadcast + P2P share messages.
    ///
    /// # Errors
    ///
    /// Returns an error if this party is not in `signer_parties`, the
    /// quorum is smaller than the key-share threshold, or CL operations
    /// fail.
    pub fn new(config: PresignConfig) -> tecdsa_core::Result<Self> {
        let PresignConfig {
            key_share,
            my_id,
            signer_parties,
            mut cl_setup,
        } = config;

        let my_idx = local_pos(&signer_parties, my_id).ok_or_else(|| {
            TecdsaError::Other("my_id not found in signer_parties".into())
        })?;
        let n = signer_parties.len();
        let threshold = key_share.threshold;
        if usize::from(threshold) > n {
            return Err(TecdsaError::Other(format!(
                "quorum of {n} signers is below the key threshold {threshold}"
            )));
        }

        let ids = signer_ids(&signer_parties);
        let mut rng = rand::thread_rng();

        let (r1_state, my_bcast, p2p) = rounds::drg_presign_round1(
            my_idx,
            n,
            threshold,
            &ids,
            &key_share,
            &mut cl_setup,
            &mut rng,
        )
        .map_err(|e| TecdsaError::Other(format!("drg_presign_round1: {e}")))?;

        // Serialise the broadcast part once.
        let bcast_payload = R1BcastPayload {
            commitment: my_bcast.commitment,
            k_commitments: points_to_bytes(&my_bcast.k_commitments),
            gamma_commitments: points_to_bytes(&my_bcast.gamma_commitments),
            k_ct: SerializedClCt::from_ct(&my_bcast.k_ciphertext),
            k_proof: SerializedREncPc::from_proof(&my_bcast.k_proof),
            gamma_ct: SerializedClCt::from_ct(&my_bcast.gamma_ciphertext),
            gamma_proof: SerializedREncPc::from_proof(&my_bcast.gamma_proof),
        };
        let bcast_bytes = encode(&bcast_payload, "R1 bcast payload")?;

        let mut outgoing = Vec::new();
        outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Wmy23PresignMsg::Round1Bcast(bcast_bytes),
        });
        for (pos, party) in signer_parties.iter().enumerate() {
            if *party == my_id {
                continue;
            }
            let share = p2p[pos]
                .as_ref()
                .ok_or_else(|| TecdsaError::Other("missing P2P share for recipient".into()))?;
            let p2p_payload = R1P2pPayload {
                k_share: SerializedVssShare::from_share(&share.k_share),
                gamma_share: SerializedVssShare::from_share(&share.gamma_share),
            };
            outgoing.push(Outgoing {
                to: Recipient::Party(*party),
                msg: Wmy23PresignMsg::Round1P2p(encode(&p2p_payload, "R1 p2p payload")?),
            });
        }

        let state = Round1State {
            key_share,
            my_id,
            all_parties: signer_parties,
            r1_state,
            my_bcast,
            bcasts: BTreeMap::new(),
            p2ps: BTreeMap::new(),
            outgoing,
        };

        Ok(Self {
            round: PresignRound::Round1(state),
            setup: cl_setup,
        })
    }

    /// Transition from Round 1 to Round 2: DRG.GenVf + DRG.Comb + MtAwc
    /// Alice step 1.
    fn transition_r1_to_r2(
        state: Round1State,
        setup: &mut ClSetup,
    ) -> tecdsa_core::Result<Round2State> {
        let n = state.all_parties.len();
        let my_idx = local_pos(&state.all_parties, state.my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in quorum".into()))?;
        let ids = signer_ids(&state.all_parties);

        // Assemble the local-order views of broadcasts and received shares.
        let mut r1_bcasts: Vec<DrgPresignR1Bcast> = Vec::with_capacity(n);
        let mut received_p2p: Vec<Option<DrgPresignR1P2P>> = Vec::with_capacity(n);
        for (pos, party) in state.all_parties.iter().enumerate() {
            if pos == my_idx {
                r1_bcasts.push(state.my_bcast.clone());
                received_p2p.push(None);
            } else {
                let b = state.bcasts.get(party).ok_or_else(|| {
                    TecdsaError::Other(format!("missing R1 broadcast from {party}"))
                })?;
                let p = state.p2ps.get(party).ok_or_else(|| {
                    TecdsaError::Other(format!("missing R1 shares from {party}"))
                })?;
                r1_bcasts.push(b.clone());
                received_p2p.push(Some(p.clone()));
            }
        }

        let (r2_state, my_r2_bcast) = rounds::drg_presign_round2(
            &state.r1_state,
            &r1_bcasts,
            &received_p2p,
            &ids,
            &state.key_share,
            setup,
        )
        .map_err(|e| TecdsaError::Other(format!("drg_presign_round2: {e}")))?;

        // Queue Round 2 messages: each counterparty gets its own MtAwc
        // Alice ciphertexts plus the Gamma decommitment.
        let mut outgoing = Vec::new();
        for (pos, party) in state.all_parties.iter().enumerate() {
            if pos == my_idx {
                continue;
            }
            let ct_k = my_r2_bcast.c_gamma[pos]
                .as_ref()
                .ok_or_else(|| TecdsaError::Other("missing R2 k ciphertext".into()))?;
            let ct_x = my_r2_bcast.c_x[pos]
                .as_ref()
                .ok_or_else(|| TecdsaError::Other("missing R2 x ciphertext".into()))?;
            let payload = R2Payload {
                nonce: my_r2_bcast.nonce,
                gamma_point_bytes: my_r2_bcast.gamma_point_bytes.clone(),
                ct_k: SerializedClCt::from_ct(ct_k),
                ct_x: SerializedClCt::from_ct(ct_x),
            };
            outgoing.push(Outgoing {
                to: Recipient::Party(*party),
                msg: Wmy23PresignMsg::Round2(encode(&payload, "R2 payload")?),
            });
        }

        let r1_commitments: Vec<[u8; 32]> = r1_bcasts.iter().map(|b| b.commitment).collect();

        Ok(Round2State {
            key_share: state.key_share,
            my_id: state.my_id,
            all_parties: state.all_parties,
            r1_commitments,
            r1_state: state.r1_state,
            r2_state,
            my_r2_bcast,
            received: BTreeMap::new(),
            outgoing,
        })
    }

    /// Transition from Round 2 to Round 3: MtAwc Bob step.
    fn transition_r2_to_r3(
        state: Round2State,
        setup: &mut ClSetup,
    ) -> tecdsa_core::Result<Round3State> {
        let n = state.all_parties.len();
        let my_idx = local_pos(&state.all_parties, state.my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in quorum".into()))?;
        let ids = signer_ids(&state.all_parties);
        let mut rng = rand::thread_rng();

        // Build the local-order view of Round 2 broadcasts: own entry is
        // the full per-recipient vector; for other parties only the
        // ciphertexts addressed to us are populated.
        let mut my_r2_bcast = Some(state.my_r2_bcast);
        let mut r2_bcasts: Vec<DrgPresignR2Bcast> = Vec::with_capacity(n);
        for (pos, party) in state.all_parties.iter().enumerate() {
            if pos == my_idx {
                r2_bcasts.push(
                    my_r2_bcast
                        .take()
                        .ok_or_else(|| TecdsaError::Other("own R2 bcast already taken".into()))?,
                );
                continue;
            }
            let r2 = state
                .received
                .get(party)
                .ok_or_else(|| TecdsaError::Other(format!("missing R2 data from {party}")))?;
            let mut c_gamma: Vec<Option<ClCiphertext>> = vec![None; n];
            let mut c_x: Vec<Option<ClCiphertext>> = vec![None; n];
            c_gamma[my_idx] = Some(r2.ct_k.clone());
            c_x[my_idx] = Some(r2.ct_x.clone());
            r2_bcasts.push(DrgPresignR2Bcast {
                nonce: r2.nonce,
                gamma_point_bytes: r2.gamma_point_bytes.clone(),
                c_gamma,
                c_x,
            });
        }

        let my_r3 = rounds::drg_presign_round3_bob(
            &state.r2_state,
            &state.r1_state,
            &ids,
            &state.key_share,
            &r2_bcasts,
            setup,
            &mut rng,
        )
        .map_err(|e| TecdsaError::Other(format!("drg_presign_round3_bob: {e}")))?;

        // Queue Round 3 messages (each Alice gets her Bob responses).
        let mut outgoing = Vec::new();
        for (pos, party) in state.all_parties.iter().enumerate() {
            if pos == my_idx {
                continue;
            }
            let gamma_bob = my_r3.gamma_bob_outputs[pos]
                .as_ref()
                .ok_or_else(|| TecdsaError::Other("missing gamma bob output".into()))?;
            let x_bob = my_r3.x_bob_outputs[pos]
                .as_ref()
                .ok_or_else(|| TecdsaError::Other("missing x bob output".into()))?;
            let payload = R3Payload {
                gamma_c_alpha: SerializedClCt::from_ct(&gamma_bob.c_alpha),
                gamma_g_beta_bytes: gamma_bob.g_beta.to_bytes().to_vec(),
                x_c_alpha: SerializedClCt::from_ct(&x_bob.c_alpha),
                x_g_beta_bytes: x_bob.g_beta.to_bytes().to_vec(),
            };
            outgoing.push(Outgoing {
                to: Recipient::Party(*party),
                msg: Wmy23PresignMsg::Round3(encode(&payload, "R3 payload")?),
            });
        }

        Ok(Round3State {
            key_share: state.key_share,
            my_id: state.my_id,
            all_parties: state.all_parties,
            r1_commitments: state.r1_commitments,
            r1_state: state.r1_state,
            r2_state: state.r2_state,
            r2_bcasts,
            my_r3,
            received: BTreeMap::new(),
            outgoing,
        })
    }

    /// Transition from Round 3 to Round 4: decrypt MtAwc responses and
    /// reveal `delta_i` / `D_i` (Phase 3).
    fn transition_r3_to_r4(
        state: Round3State,
        setup: &mut ClSetup,
    ) -> tecdsa_core::Result<Round4State> {
        let n = state.all_parties.len();
        let my_idx = local_pos(&state.all_parties, state.my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in quorum".into()))?;
        let ids = signer_ids(&state.all_parties);
        let mut rng = rand::thread_rng();

        // Build the local-order view of Round 3 data. Received entries
        // carry only (c_alpha, g_beta); beta is never transmitted, so it
        // is zero-filled and unused by the round function.
        let mut my_r3 = Some(state.my_r3);
        let mut r3_datas: Vec<DrgPresignR3Data> = Vec::with_capacity(n);
        for (pos, party) in state.all_parties.iter().enumerate() {
            if pos == my_idx {
                r3_datas.push(
                    my_r3
                        .take()
                        .ok_or_else(|| TecdsaError::Other("own R3 data already taken".into()))?,
                );
                continue;
            }
            let r3 = state
                .received
                .get(party)
                .ok_or_else(|| TecdsaError::Other(format!("missing R3 data from {party}")))?;
            let mut gamma_bob_outputs: Vec<Option<crate::mtawc::MtAwcBobOutput>> = vec![];
            let mut x_bob_outputs: Vec<Option<crate::mtawc::MtAwcBobOutput>> = vec![];
            for k in 0..n {
                if k == my_idx {
                    gamma_bob_outputs.push(Some(crate::mtawc::MtAwcBobOutput {
                        c_alpha: r3.gamma_c_alpha.clone(),
                        g_beta: r3.gamma_g_beta,
                        beta: k256::Scalar::ZERO,
                    }));
                    x_bob_outputs.push(Some(crate::mtawc::MtAwcBobOutput {
                        c_alpha: r3.x_c_alpha.clone(),
                        g_beta: r3.x_g_beta,
                        beta: k256::Scalar::ZERO,
                    }));
                } else {
                    gamma_bob_outputs.push(None);
                    x_bob_outputs.push(None);
                }
            }
            r3_datas.push(DrgPresignR3Data {
                gamma_bob_outputs,
                x_bob_outputs,
            });
        }

        let (r4_state, _phase3) = rounds::drg_presign_round4_compute(
            &state.r1_state,
            &state.r1_commitments,
            &state.r2_state,
            &state.r2_bcasts,
            &r3_datas,
            &ids,
            &state.key_share,
            setup,
            &mut rng,
        )
        .map_err(|e| TecdsaError::Other(format!("drg_presign_round4_compute: {e}")))?;

        // Broadcast delta_i + D_i.
        let payload = R4Payload {
            delta_i: r4_state.delta_i.to_repr().to_vec(),
            big_d_i: r4_state.big_d_i.to_bytes().to_vec(),
        };
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Wmy23PresignMsg::Round4(encode(&payload, "R4 payload")?),
        }];

        // Store own revelation.
        let mut received = BTreeMap::new();
        received.insert(
            state.my_id,
            ReceivedR4 {
                delta_i: r4_state.delta_i,
                big_d_i: r4_state.big_d_i,
            },
        );

        Ok(Round4State {
            my_id: state.my_id,
            all_parties: state.all_parties,
            r4_state,
            received,
            outgoing,
        })
    }

    /// Finalize: reconstruct delta and R to produce the presignature.
    fn finalize_r4(state: &Round4State) -> tecdsa_core::Result<Wmy23Presignature> {
        let mut all_delta = Vec::with_capacity(state.all_parties.len());
        let mut all_big_d = Vec::with_capacity(state.all_parties.len());
        for party in &state.all_parties {
            let r4 = state
                .received
                .get(party)
                .ok_or_else(|| TecdsaError::Other(format!("missing R4 data from {party}")))?;
            all_delta.push(r4.delta_i);
            all_big_d.push(r4.big_d_i);
        }

        rounds::drg_presign_finalize(&state.r4_state, &all_delta, &all_big_d)
            .map_err(|e| TecdsaError::Other(format!("drg_presign_finalize: {e}")))
    }
}

impl StateMachine for Wmy23PresignMachine {
    type Output = Wmy23Presignature;
    type Inbound = Wmy23PresignMsg;
    type Outbound = Wmy23PresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        // Reject messages from self.
        let my_id = match &self.round {
            PresignRound::Round1(s) => s.my_id,
            PresignRound::Round2(s) => s.my_id,
            PresignRound::Round3(s) => s.my_id,
            PresignRound::Round4(s) => s.my_id,
            _ => PartyId(u16::MAX),
        };
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        // Take the current round state, replacing with Poisoned temporarily.
        let round = std::mem::replace(&mut self.round, PresignRound::Poisoned);

        match round {
            PresignRound::Round1(mut state) => {
                if local_pos(&state.all_parties, from).is_none() {
                    self.round = PresignRound::Round1(state);
                    return Err(TecdsaError::Other(format!("unknown party: {from}")));
                }
                let my_idx = local_pos(&state.all_parties, state.my_id)
                    .ok_or_else(|| TecdsaError::Other("my_id not in quorum".into()))?;

                match msg {
                    Wmy23PresignMsg::Round1Bcast(data) => {
                        if state.bcasts.contains_key(&from) {
                            self.round = PresignRound::Round1(state);
                            return Err(TecdsaError::Other(format!(
                                "duplicate R1 broadcast from party {from}"
                            )));
                        }
                        let payload: R1BcastPayload = decode(&data, "R1 bcast payload")?;
                        let bcast = DrgPresignR1Bcast {
                            commitment: payload.commitment,
                            k_commitments: points_from_bytes(
                                &payload.k_commitments,
                                "k commitments",
                            )
                            .map_err(TecdsaError::Other)?,
                            gamma_commitments: points_from_bytes(
                                &payload.gamma_commitments,
                                "gamma commitments",
                            )
                            .map_err(TecdsaError::Other)?,
                            k_ciphertext: payload.k_ct.to_ct(),
                            k_proof: payload.k_proof.to_proof(),
                            gamma_ciphertext: payload.gamma_ct.to_ct(),
                            gamma_proof: payload.gamma_proof.to_proof(),
                        };
                        state.bcasts.insert(from, bcast);
                    }
                    Wmy23PresignMsg::Round1P2p(data) => {
                        if state.p2ps.contains_key(&from) {
                            self.round = PresignRound::Round1(state);
                            return Err(TecdsaError::Other(format!(
                                "duplicate R1 shares from party {from}"
                            )));
                        }
                        let payload: R1P2pPayload = decode(&data, "R1 p2p payload")?;
                        let k_share = payload.k_share.to_share().map_err(TecdsaError::Other)?;
                        let gamma_share =
                            payload.gamma_share.to_share().map_err(TecdsaError::Other)?;
                        let expected_index = (my_idx + 1) as u16;
                        if k_share.index != expected_index || gamma_share.index != expected_index {
                            self.round = PresignRound::Round1(state);
                            return Err(TecdsaError::Other(format!(
                                "R1 share from party {from} has wrong recipient index"
                            )));
                        }
                        state.p2ps.insert(
                            from,
                            DrgPresignR1P2P {
                                k_share,
                                gamma_share,
                            },
                        );
                    }
                    _ => {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(
                            "unexpected message type in round 1".into(),
                        ));
                    }
                }

                let expected = n_others(&state.all_parties);
                if state.bcasts.len() == expected && state.p2ps.len() == expected {
                    let r2_state = Self::transition_r1_to_r2(state, &mut self.setup)?;
                    self.round = PresignRound::Round2(r2_state);
                } else {
                    self.round = PresignRound::Round1(state);
                }
            }

            PresignRound::Round2(mut state) => {
                if let Wmy23PresignMsg::Round2(data) = msg {
                    if local_pos(&state.all_parties, from).is_none() {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }
                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let payload: R2Payload = decode(&data, "R2 payload")?;
                    state.received.insert(
                        from,
                        ReceivedR2 {
                            nonce: payload.nonce,
                            gamma_point_bytes: payload.gamma_point_bytes,
                            ct_k: payload.ct_k.to_ct(),
                            ct_x: payload.ct_x.to_ct(),
                        },
                    );

                    if state.received.len() == n_others(&state.all_parties) {
                        let r3_state = Self::transition_r2_to_r3(state, &mut self.setup)?;
                        self.round = PresignRound::Round3(r3_state);
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

            PresignRound::Round3(mut state) => {
                if let Wmy23PresignMsg::Round3(data) = msg {
                    if local_pos(&state.all_parties, from).is_none() {
                        self.round = PresignRound::Round3(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }
                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round3(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let payload: R3Payload = decode(&data, "R3 payload")?;
                    let gamma_g_beta = point_from_bytes(
                        &payload.gamma_g_beta_bytes,
                        &format!("gamma_g_beta from {from}"),
                    )
                    .map_err(TecdsaError::Other)?;
                    let x_g_beta =
                        point_from_bytes(&payload.x_g_beta_bytes, &format!("x_g_beta from {from}"))
                            .map_err(TecdsaError::Other)?;

                    state.received.insert(
                        from,
                        ReceivedR3 {
                            gamma_c_alpha: payload.gamma_c_alpha.to_ct(),
                            gamma_g_beta,
                            x_c_alpha: payload.x_c_alpha.to_ct(),
                            x_g_beta,
                        },
                    );

                    if state.received.len() == n_others(&state.all_parties) {
                        let r4_state = Self::transition_r3_to_r4(state, &mut self.setup)?;
                        self.round = PresignRound::Round4(r4_state);
                    } else {
                        self.round = PresignRound::Round3(state);
                    }
                } else {
                    self.round = PresignRound::Round3(state);
                    return Err(TecdsaError::Other(
                        "unexpected message type in round 3".into(),
                    ));
                }
            }

            PresignRound::Round4(mut state) => {
                if let Wmy23PresignMsg::Round4(data) = msg {
                    if local_pos(&state.all_parties, from).is_none() {
                        self.round = PresignRound::Round4(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }
                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round4(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let payload: R4Payload = decode(&data, "R4 payload")?;
                    let delta_i = scalar_from_bytes(&payload.delta_i, "delta_i")
                        .map_err(TecdsaError::Other)?;
                    let big_d_i =
                        point_from_bytes(&payload.big_d_i, &format!("D_i from {from}"))
                            .map_err(TecdsaError::Other)?;
                    state.received.insert(from, ReceivedR4 { delta_i, big_d_i });

                    if state.received.len() == state.all_parties.len() {
                        let presignature = Self::finalize_r4(&state)?;
                        self.round = PresignRound::Done(presignature);
                    } else {
                        self.round = PresignRound::Round4(state);
                    }
                } else {
                    self.round = PresignRound::Round4(state);
                    return Err(TecdsaError::Other(
                        "unexpected message type in round 4".into(),
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
            PresignRound::Round3(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Round4(s) => std::mem::take(&mut s.outgoing),
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
            PresignRound::Round3(_) => 3,
            PresignRound::Round4(_) => 4,
            PresignRound::Done(_) => 5,
            PresignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
