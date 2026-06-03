// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 presigning protocol (Rounds 1-4).
//!
//! Produces a message-independent [`Wmy23Presignature`] using CL-based MtAwc
//! for multiplicative-to-additive conversion.
//!
//! ## Protocol Rounds (from WMY23, Section 3.3)
//!
//! 1. **Nonce commitment:** each party samples $k_i, \gamma_i$, broadcasts
//!    a commitment to $\Gamma_i = \gamma_i \cdot G$.
//! 2. **Decommit + MtAwc Alice step 1:** decommit $\Gamma_i$, encrypt
//!    $\gamma_i$ and $x_i$ under own CL key.  Broadcast decommit +
//!    serialised CL ciphertexts.
//! 3. **MtAwc Bob step:** for each counterparty $j$, homomorphically
//!    compute $k_i \cdot \gamma_j$ and $k_i \cdot x_j$.  Broadcast
//!    response ciphertexts.
//! 4. **MtAwc Alice step 2 + finalize:** decrypt $\alpha$ values, compute
//!    $\delta_i$ and $\sigma_i$, broadcast $\delta_i$.  After collecting
//!    all $\delta_j$ values, reconstruct $R$.
//!
//! ## StateMachine implementation
//!
//! With bicycl-rs v0.2.2, all CL types including `ClSetup` implement `Send`.
//! The presign machine stores the `ClSetup` directly and uses it across
//! round transitions, eliminating the per-round setup recreation overhead.
//!
//! CL ciphertexts in **messages** are serialised as QFI abc-decimal tuples
//! `(String, String, String)` per component, since CL types do not implement
//! serde.  Ciphertexts in **internal state** are stored as `ClCiphertext`
//! directly (they are `Send`).
//!
//! Reference: Wang, Mei, Yu. "Real Threshold ECDSA." NDSS 2023, Section 3.3.

pub mod rounds;
pub mod types;

use std::collections::BTreeMap;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic, PrimeField};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_class_group::cl::{ClCiphertext, ClSetup, Qfi};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};
pub use types::Wmy23Presignature;

use crate::{
    key_share::Wmy23KeyShare,
    mtawc::{self, MtAwcAliceState},
};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Messages exchanged during WMY23 presigning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wmy23PresignMsg {
    /// Round 1: commitment (32 bytes).
    Round1(Vec<u8>),
    /// Round 2: decommit + MtAwc Alice step1 ciphertexts (serialised).
    Round2(Vec<u8>),
    /// Round 3: MtAwc Bob response ciphertexts (serialised).
    Round3(Vec<u8>),
    /// Round 4: delta_i scalar (32 bytes).
    Round4(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Serialised CL ciphertext for messages
// ---------------------------------------------------------------------------

/// A CL ciphertext serialised as two compact binary QFI blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedClCt {
    c1: Vec<u8>,
    c2: Vec<u8>,
}

impl SerializedClCt {
    /// Serialise a `ClCiphertext` using the given `ClSetup` context.
    fn from_ct(ct: &ClCiphertext) -> Result<Self, String> {
        Ok(Self {
            c1: ct.c1().to_bytes(),
            c2: ct.c2().to_bytes(),
        })
    }

    /// Reconstruct a `ClCiphertext` from serialised form.
    fn to_ct(&self) -> Result<ClCiphertext, String> {
        let c1 = Qfi::from_bytes(&self.c1);
        let c2 = Qfi::from_bytes(&self.c2);
        Ok(ClCiphertext::new(c1, c2))
    }
}

// ---------------------------------------------------------------------------
// Round 2 message payload
// ---------------------------------------------------------------------------

/// Serialised Round 2 message: decommit + MtAwc Alice step1 ciphertexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R2Payload {
    /// Commitment nonce (32 bytes).
    nonce: [u8; 32],
    /// Gamma point bytes (compressed).
    gamma_point_bytes: Vec<u8>,
    /// MtAwc ciphertext for gamma_i (encrypted under sender's CL key).
    ct_gamma: SerializedClCt,
    /// MtAwc ciphertext for x_i (encrypted under sender's CL key).
    ct_x: SerializedClCt,
}

// ---------------------------------------------------------------------------
// Round 3 message payload
// ---------------------------------------------------------------------------

/// Serialised Round 3 message: MtAwc Bob response for one counterparty.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R3Payload {
    /// MtAwc response ciphertext c_alpha for the gamma MtA.
    gamma_c_alpha: SerializedClCt,
    /// g^beta point for gamma MtA (compressed bytes).
    gamma_g_beta_bytes: Vec<u8>,
    /// MtAwc response ciphertext c_alpha for the key MtA.
    x_c_alpha: SerializedClCt,
    /// g^beta point for key MtA (compressed bytes).
    x_g_beta_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Internal per-party received data
// ---------------------------------------------------------------------------

/// Received Round 2 data from a single party (ciphertexts reconstructed).
struct ReceivedR2 {
    nonce: [u8; 32],
    gamma_point_bytes: Vec<u8>,
    /// CL ciphertext of gamma_j under party j's key.
    ct_gamma: ClCiphertext,
    /// CL ciphertext of x_j under party j's key.
    ct_x: ClCiphertext,
}

/// Received Round 3 data from a single party (MtAwc Bob output).
struct ReceivedR3 {
    /// MtAwc Bob output for gamma MtA.
    gamma_c_alpha: ClCiphertext,
    gamma_g_beta: k256::ProjectivePoint,
    /// MtAwc Bob output for key MtA.
    x_c_alpha: ClCiphertext,
    x_g_beta: k256::ProjectivePoint,
}

// ---------------------------------------------------------------------------
// State machine internal states
// ---------------------------------------------------------------------------

/// Round 1 state: waiting for commitments from all parties.
struct Round1State {
    key_share: Wmy23KeyShare,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    /// Nonce share k_i.
    k_i: k256::Scalar,
    /// Mask share gamma_i.
    gamma_i: k256::Scalar,
    /// Gamma point = gamma_i * G.
    gamma_point_i: k256::ProjectivePoint,
    /// Commitment nonce.
    nonce: [u8; 32],
    /// Received commitments from all parties (including self).
    received: BTreeMap<PartyId, [u8; 32]>,
    /// Outgoing messages.
    outgoing: Vec<Outgoing<Wmy23PresignMsg>>,
}

/// Round 2 state: waiting for decommits + MtAwc Alice ciphertexts.
struct Round2State {
    key_share: Wmy23KeyShare,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    k_i: k256::Scalar,
    gamma_i: k256::Scalar,
    /// All commitments (from Round 1), indexed by PartyId.
    commitments: BTreeMap<PartyId, [u8; 32]>,
    /// MtAwc Alice states for gamma MtA (from our own step1).
    gamma_alice_state: MtAwcAliceState,
    /// MtAwc Alice states for key MtA (from our own step1).
    x_alice_state: MtAwcAliceState,
    /// Received R2 messages.
    received: BTreeMap<PartyId, ReceivedR2>,
    outgoing: Vec<Outgoing<Wmy23PresignMsg>>,
}

/// Round 3 state: waiting for MtAwc Bob responses.
struct Round3State {
    key_share: Wmy23KeyShare,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    k_i: k256::Scalar,
    gamma_i: k256::Scalar,
    /// Our own Bob beta values for gamma MtA (one per counterparty).
    gamma_betas: BTreeMap<PartyId, k256::Scalar>,
    /// Our own Bob beta values for key MtA (one per counterparty).
    x_betas: BTreeMap<PartyId, k256::Scalar>,
    /// MtAwc Alice states for gamma MtA (kept for Round 4 decryption).
    gamma_alice_state: MtAwcAliceState,
    /// MtAwc Alice states for key MtA.
    x_alice_state: MtAwcAliceState,
    /// All decommitted gamma points, indexed by party.
    gamma_points: BTreeMap<PartyId, k256::ProjectivePoint>,
    /// Received R3 data from other parties.
    received: BTreeMap<PartyId, ReceivedR3>,
    outgoing: Vec<Outgoing<Wmy23PresignMsg>>,
}

/// Round 4 state: waiting for delta_i values from all parties.
struct Round4State {
    _my_id: PartyId,
    all_parties: Vec<PartyId>,
    k_i: k256::Scalar,
    sigma_i: k256::Scalar,
    /// All gamma points (for reconstructing Gamma).
    gamma_points: BTreeMap<PartyId, k256::ProjectivePoint>,
    /// Received delta_i values.
    deltas: BTreeMap<PartyId, k256::Scalar>,
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

/// Deserialize a compressed EC point from bytes.
fn point_from_bytes(bytes: &[u8], label: &str) -> Result<k256::ProjectivePoint, String> {
    let repr = k256::CompressedPoint::try_from(bytes)
        .map_err(|e| format!("invalid point bytes ({label}): {e}"))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| format!("invalid EC point: {label}"))
}

/// Get this party's index in the all_parties list.
fn my_idx(all_parties: &[PartyId], my_id: PartyId) -> Option<usize> {
    all_parties.iter().position(|p| *p == my_id)
}

/// Number of other parties (total - 1).
fn n_others(all_parties: &[PartyId]) -> usize {
    all_parties.len() - 1
}

// ---------------------------------------------------------------------------
// WMY23 presigning state machine
// ---------------------------------------------------------------------------

/// WMY23 presigning state machine (4 rounds).
///
/// Implements the simplified presign variant using CL-based MtAwc for
/// multiplicative-to-additive conversion.
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
    /// Immediately runs presign Round 1 (sample k_i, gamma_i, commit) and
    /// queues the Round 1 commitment broadcast.
    ///
    /// # Arguments
    ///
    /// * `config` - Presign configuration (key share, party info, CL setup).
    ///
    /// # Errors
    ///
    /// Returns an error if this party is not in `signer_parties`.
    pub fn new(config: PresignConfig) -> tecdsa_core::Result<Self> {
        let PresignConfig {
            key_share,
            my_id,
            signer_parties,
            cl_setup,
        } = config;

        if !signer_parties.contains(&my_id) {
            return Err(TecdsaError::Other(
                "my_id not found in signer_parties".into(),
            ));
        }

        let mut rng = rand::thread_rng();

        // Sample k_i and gamma_i
        let k_i = k256::Secp256k1::random_scalar(&mut rng);
        let gamma_i = k256::Secp256k1::random_scalar(&mut rng);
        let gamma_point_i =
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * gamma_i;

        // Commit: H(nonce || gamma_point_bytes)
        let gamma_point_bytes = gamma_point_i.to_bytes();
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let commitment: [u8; 32] = Sha256::new()
            .chain_update(nonce)
            .chain_update(gamma_point_bytes)
            .finalize()
            .into();

        // Queue Round 1 broadcast
        let mut outgoing = Vec::new();
        let payload = commitment.to_vec();
        for party in &signer_parties {
            if *party != my_id {
                outgoing.push(Outgoing {
                    to: Recipient::Party(*party),
                    msg: Wmy23PresignMsg::Round1(payload.clone()),
                });
            }
        }

        // Store our own commitment
        let mut received = BTreeMap::new();
        received.insert(my_id, commitment);

        let state = Round1State {
            key_share,
            my_id,
            all_parties: signer_parties,
            k_i,
            gamma_i,
            gamma_point_i,
            nonce,
            received,
            outgoing,
        };

        Ok(Self {
            round: PresignRound::Round1(state),
            setup: cl_setup,
        })
    }

    /// Transition from Round 1 to Round 2.
    ///
    /// Uses the stored `ClSetup` to run MtAwc Alice step 1.
    fn transition_r1_to_r2(
        state: Round1State,
        setup: &mut ClSetup,
    ) -> tecdsa_core::Result<Round2State> {
        let my_idx_val = my_idx(&state.all_parties, state.my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;
        let my_pk = &state.key_share.cl_pks[my_idx_val];

        // MtAwc Alice step 1: encrypt k_i (gamma MtA) and x_i (key MtA)
        // Paper convention: Alice holds k, Bob holds gamma.
        let (gamma_alice_state, ct_gamma) = mtawc::mtawc_alice_step1(setup, my_pk, &state.k_i)
            .map_err(|e| TecdsaError::Other(format!("mtawc_alice_step1 gamma: {e}")))?;
        let (x_alice_state, ct_x) =
            mtawc::mtawc_alice_step1(setup, my_pk, &state.key_share.secret_share)
                .map_err(|e| TecdsaError::Other(format!("mtawc_alice_step1 x: {e}")))?;

        // Serialise ciphertexts for the message
        let ct_gamma_ser = SerializedClCt::from_ct(&ct_gamma)
            .map_err(|e| TecdsaError::Other(format!("serialize ct_gamma: {e}")))?;
        let ct_x_ser = SerializedClCt::from_ct(&ct_x)
            .map_err(|e| TecdsaError::Other(format!("serialize ct_x: {e}")))?;

        let r2_payload = R2Payload {
            nonce: state.nonce,
            gamma_point_bytes: state.gamma_point_i.to_bytes().to_vec(),
            ct_gamma: ct_gamma_ser,
            ct_x: ct_x_ser,
        };
        let payload_bytes = bincode::serde::encode_to_vec(&r2_payload, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize R2 payload: {e}")))?;

        // Store our own R2 data
        let mut received_r2 = BTreeMap::new();
        received_r2.insert(
            state.my_id,
            ReceivedR2 {
                nonce: state.nonce,
                gamma_point_bytes: state.gamma_point_i.to_bytes().to_vec(),
                ct_gamma,
                ct_x,
            },
        );

        // Queue Round 2 messages to all other parties
        let mut outgoing = Vec::new();
        for party in &state.all_parties {
            if *party != state.my_id {
                outgoing.push(Outgoing {
                    to: Recipient::Party(*party),
                    msg: Wmy23PresignMsg::Round2(payload_bytes.clone()),
                });
            }
        }

        Ok(Round2State {
            key_share: state.key_share,
            my_id: state.my_id,
            all_parties: state.all_parties,
            k_i: state.k_i,
            gamma_i: state.gamma_i,
            commitments: state.received,
            gamma_alice_state,
            x_alice_state,
            received: received_r2,
            outgoing,
        })
    }

    /// Transition from Round 2 to Round 3.
    ///
    /// Uses the stored `ClSetup` to run MtAwc Bob step for each
    /// counterparty.
    fn transition_r2_to_r3(
        state: Round2State,
        setup: &mut ClSetup,
    ) -> tecdsa_core::Result<Round3State> {
        let mut rng = rand::thread_rng();

        // First verify all commitments
        for (&party_id, r2) in &state.received {
            let expected_commitment = state.commitments.get(&party_id).ok_or_else(|| {
                TecdsaError::Other(format!("missing commitment for party {party_id}"))
            })?;
            let recomputed: [u8; 32] = Sha256::new()
                .chain_update(r2.nonce)
                .chain_update(&r2.gamma_point_bytes)
                .finalize()
                .into();
            if bool::from(!recomputed.ct_eq(expected_commitment)) {
                return Err(TecdsaError::Other(format!(
                    "gamma commitment verification failed for party {party_id}"
                )));
            }
        }

        // Collect gamma points
        let mut gamma_points = BTreeMap::new();
        for (&party_id, r2) in &state.received {
            let gp = point_from_bytes(&r2.gamma_point_bytes, &format!("gamma point {party_id}"))
                .map_err(TecdsaError::Other)?;
            gamma_points.insert(party_id, gp);
        }

        // MtAwc Bob step: for each other party j (Alice), we (Bob) compute
        // homomorphic products.
        // Gamma MtA: Bob uses gamma_i (paper convention: Bob holds gamma).
        // Key MtA: Bob uses k_i.
        let mut gamma_betas = BTreeMap::new();
        let mut x_betas = BTreeMap::new();
        let mut outgoing = Vec::new();

        for &party_j in &state.all_parties {
            if party_j == state.my_id {
                continue;
            }

            let j_idx = my_idx(&state.all_parties, party_j)
                .ok_or_else(|| TecdsaError::Other(format!("party {party_j} not found")))?;
            let pk_j = &state.key_share.cl_pks[j_idx];

            let r2_j = state.received.get(&party_j).ok_or_else(|| {
                TecdsaError::Other(format!("missing R2 data from party {party_j}"))
            })?;

            // MtAwc Bob for gamma_i * k_j (paper convention: Bob holds gamma)
            let gamma_bob = mtawc::mtawc_bob(setup, pk_j, &r2_j.ct_gamma, &state.gamma_i, &mut rng)
                .map_err(|e| {
                    TecdsaError::Other(format!("mtawc_bob gamma for party {party_j}: {e}"))
                })?;

            // MtAwc Bob for k_i * x_j (key MtA unchanged)
            let x_bob = mtawc::mtawc_bob(setup, pk_j, &r2_j.ct_x, &state.k_i, &mut rng)
                .map_err(|e| TecdsaError::Other(format!("mtawc_bob x for party {party_j}: {e}")))?;

            // Serialise Bob outputs for the message to party j
            let gamma_c_alpha_ser = SerializedClCt::from_ct(&gamma_bob.c_alpha)
                .map_err(|e| TecdsaError::Other(format!("serialize gamma_c_alpha: {e}")))?;
            let x_c_alpha_ser = SerializedClCt::from_ct(&x_bob.c_alpha)
                .map_err(|e| TecdsaError::Other(format!("serialize x_c_alpha: {e}")))?;

            let r3_payload = R3Payload {
                gamma_c_alpha: gamma_c_alpha_ser,
                gamma_g_beta_bytes: gamma_bob.g_beta.to_bytes().to_vec(),
                x_c_alpha: x_c_alpha_ser,
                x_g_beta_bytes: x_bob.g_beta.to_bytes().to_vec(),
            };
            let payload_bytes =
                bincode::serde::encode_to_vec(&r3_payload, bincode::config::standard())
                    .map_err(|e| TecdsaError::Other(format!("serialize R3 payload: {e}")))?;

            // Store Bob's beta values for Round 4
            gamma_betas.insert(party_j, gamma_bob.beta);
            x_betas.insert(party_j, x_bob.beta);

            // Send R3 message to party j (each party gets their specific message)
            outgoing.push(Outgoing {
                to: Recipient::Party(party_j),
                msg: Wmy23PresignMsg::Round3(payload_bytes),
            });
        }

        Ok(Round3State {
            key_share: state.key_share,
            my_id: state.my_id,
            all_parties: state.all_parties,
            k_i: state.k_i,
            gamma_i: state.gamma_i,
            gamma_betas,
            x_betas,
            gamma_alice_state: state.gamma_alice_state,
            x_alice_state: state.x_alice_state,
            gamma_points,
            received: BTreeMap::new(),
            outgoing,
        })
    }

    /// Transition from Round 3 to Round 4.
    ///
    /// Uses the stored `ClSetup` to decrypt alpha values, then applies
    /// Phase 3 zero-sharing to construct structured delta shares.
    ///
    /// **Phase 3 (WMY23 Figure 5):** Delta shares are blinded with a
    /// zero-sharing `{theta_{ij}}` so individual shares reveal nothing,
    /// while the sum is preserved. The party broadcasts its own `delta_i`
    /// (sum of its structured shares) for reconstruction.
    fn transition_r3_to_r4(
        state: Round3State,
        setup: &mut ClSetup,
    ) -> tecdsa_core::Result<Round4State> {
        let my_idx_val = my_idx(&state.all_parties, state.my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;
        let my_pk = &state.key_share.cl_pks[my_idx_val];
        let n = state.all_parties.len();

        // Collect per-counterparty MtAwc shares
        let mut alphas = BTreeMap::new(); // alpha_{ij}: I am Alice, j is Bob (gamma MtA)
        let mut mu_sum = k256::Scalar::ZERO; // key MtA

        for (&party_j, r3) in &state.received {
            // Party j was Bob, I was Alice.
            let alpha_out = mtawc::mtawc_alice_step2_no_gb_check(
                setup,
                my_pk,
                &state.key_share.cl_sk,
                &r3.gamma_c_alpha,
                &r3.gamma_g_beta,
                &state.gamma_alice_state,
            )
            .map_err(|e| {
                TecdsaError::Other(format!("mtawc_alice_step2 gamma for party {party_j}: {e}"))
            })?;
            alphas.insert(party_j, alpha_out.alpha);

            let mu_out = mtawc::mtawc_alice_step2_no_gb_check(
                setup,
                my_pk,
                &state.key_share.cl_sk,
                &r3.x_c_alpha,
                &r3.x_g_beta,
                &state.x_alice_state,
            )
            .map_err(|e| {
                TecdsaError::Other(format!("mtawc_alice_step2 x for party {party_j}: {e}"))
            })?;
            mu_sum += mu_out.alpha;
        }

        let nu_sum: k256::Scalar = state.x_betas.values().copied().sum();

        // --- Phase 3: Zero-sharing + structured delta shares ---
        // WMY23 Figure 5, Phase 3, Step 3: {theta_{ij}} <- SS.Share(0)
        let mut rng = rand::thread_rng();
        let theta = rounds::share_zero(n, &mut rng);

        // Build structured delta shares indexed by party position.
        // delta_{ii} = k_i * gamma_i + theta_{ii}
        // delta_{ij} = alpha_{ij} + beta_{ji} + theta_{ij} (for j != i)
        let mut delta_i = k256::Scalar::ZERO;
        for (pos, &party_j) in state.all_parties.iter().enumerate() {
            let share = if party_j == state.my_id {
                // Self share: k_i * gamma_i + theta_{ii}
                state.k_i * state.gamma_i + theta[pos]
            } else {
                // Cross share: alpha_{ij} + beta_{ji} + theta_{ij}
                let alpha_ij = alphas.get(&party_j).copied().unwrap_or(k256::Scalar::ZERO);
                let beta_ji = state
                    .gamma_betas
                    .get(&party_j)
                    .copied()
                    .unwrap_or(k256::Scalar::ZERO);
                alpha_ij + beta_ji + theta[pos]
            };
            delta_i += share;
        }

        // sigma_i = k_i * x_i + sum(mu_{ij}) + sum(nu_{ji})
        let sigma_i = state.k_i * state.key_share.secret_share + mu_sum + nu_sum;

        // Broadcast delta_i (= sum of structured shares, same value as before
        // since sum(theta_{ij}) = 0)
        let delta_bytes = delta_i.to_repr().to_vec();
        let mut outgoing = Vec::new();
        for party in &state.all_parties {
            if *party != state.my_id {
                outgoing.push(Outgoing {
                    to: Recipient::Party(*party),
                    msg: Wmy23PresignMsg::Round4(delta_bytes.clone()),
                });
            }
        }

        // Store our own delta_i
        let mut deltas = BTreeMap::new();
        deltas.insert(state.my_id, delta_i);

        Ok(Round4State {
            _my_id: state.my_id,
            all_parties: state.all_parties,
            k_i: state.k_i,
            sigma_i,
            gamma_points: state.gamma_points,
            deltas,
            outgoing,
        })
    }

    /// Finalize: reconstruct delta, Gamma, and R to produce the presignature.
    fn finalize_r4(state: &Round4State) -> tecdsa_core::Result<Wmy23Presignature> {
        // delta = sum(delta_j)
        let delta: k256::Scalar = state.deltas.values().copied().sum();

        // delta^{-1}
        let delta_inv = delta
            .invert()
            .into_option()
            .ok_or_else(|| TecdsaError::Other("delta is zero, cannot invert".into()))?;

        // Gamma = sum(Gamma_j)
        let gamma_sum: k256::ProjectivePoint = state.gamma_points.values().fold(
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
            |acc, gp| acc + gp,
        );

        // R = delta^{-1} * Gamma
        let big_r = gamma_sum * delta_inv;

        // r = x_coord(R) mod q
        let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine());

        Ok(Wmy23Presignature {
            k_i: state.k_i,
            big_r,
            r_x,
            sigma_i: state.sigma_i,
            n_signers: state.all_parties.len(),
        })
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
            PresignRound::Round4(s) => s._my_id,
            _ => PartyId(u16::MAX),
        };
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        // Take the current round state, replacing with Poisoned temporarily.
        let round = std::mem::replace(&mut self.round, PresignRound::Poisoned);

        match round {
            PresignRound::Round1(mut state) => {
                if let Wmy23PresignMsg::Round1(data) = msg {
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
                    if data.len() != 32 {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other("invalid R1 commitment length".into()));
                    }
                    let mut commitment = [0u8; 32];
                    commitment.copy_from_slice(&data);
                    state.received.insert(from, commitment);

                    // Check if all commitments collected
                    if state.received.len() == state.all_parties.len() {
                        let r2_state = Self::transition_r1_to_r2(state, &mut self.setup)?;
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
                if let Wmy23PresignMsg::Round2(data) = msg {
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

                    // Deserialise R2 payload
                    let (payload, _): (R2Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| {
                                TecdsaError::Other(format!("deserialize R2 payload: {e}"))
                            })?;

                    let ct_gamma = payload.ct_gamma.to_ct().map_err(|e| {
                        TecdsaError::Other(format!("reconstruct ct_gamma from party {from}: {e}"))
                    })?;
                    let ct_x = payload.ct_x.to_ct().map_err(|e| {
                        TecdsaError::Other(format!("reconstruct ct_x from party {from}: {e}"))
                    })?;

                    state.received.insert(
                        from,
                        ReceivedR2 {
                            nonce: payload.nonce,
                            gamma_point_bytes: payload.gamma_point_bytes,
                            ct_gamma,
                            ct_x,
                        },
                    );

                    // Check if all R2 data collected
                    if state.received.len() == state.all_parties.len() {
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
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRound::Round3(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }
                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round3(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    // Deserialise R3 payload
                    let (payload, _): (R3Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| {
                                TecdsaError::Other(format!("deserialize R3 payload: {e}"))
                            })?;

                    let gamma_c_alpha = payload.gamma_c_alpha.to_ct().map_err(|e| {
                        TecdsaError::Other(format!(
                            "reconstruct gamma_c_alpha from party {from}: {e}"
                        ))
                    })?;
                    let gamma_g_beta = point_from_bytes(
                        &payload.gamma_g_beta_bytes,
                        &format!("gamma_g_beta from {from}"),
                    )
                    .map_err(TecdsaError::Other)?;

                    let x_c_alpha = payload.x_c_alpha.to_ct().map_err(|e| {
                        TecdsaError::Other(format!("reconstruct x_c_alpha from party {from}: {e}"))
                    })?;
                    let x_g_beta =
                        point_from_bytes(&payload.x_g_beta_bytes, &format!("x_g_beta from {from}"))
                            .map_err(TecdsaError::Other)?;

                    state.received.insert(
                        from,
                        ReceivedR3 {
                            gamma_c_alpha,
                            gamma_g_beta,
                            x_c_alpha,
                            x_g_beta,
                        },
                    );

                    // Check if all R3 data collected (from all other parties)
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
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRound::Round4(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }
                    if state.deltas.contains_key(&from) {
                        self.round = PresignRound::Round4(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }
                    if data.len() != 32 {
                        self.round = PresignRound::Round4(state);
                        return Err(TecdsaError::Other("invalid R4 delta_i length".into()));
                    }

                    let mut repr = k256::FieldBytes::default();
                    repr.copy_from_slice(&data);
                    let delta_j = k256::Scalar::from_repr(repr)
                        .into_option()
                        .ok_or_else(|| TecdsaError::Other("invalid scalar in delta_i".into()))?;
                    state.deltas.insert(from, delta_j);

                    // Check if all delta values collected
                    if state.deltas.len() == state.all_parties.len() {
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
