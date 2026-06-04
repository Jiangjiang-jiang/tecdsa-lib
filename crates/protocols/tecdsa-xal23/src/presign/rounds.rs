// SPDX-License-Identifier: MIT OR Apache-2.0
//! XAL23 presign round state types and transition logic.
//!
//! Four rounds following the GG18 structure with JL MtA:
//!
//! 1. Commit to Gamma_i + sender_encrypt for gamma and w MtA.
//! 2. Decommit Gamma_i + receiver_compute for both MtA channels.
//! 3. sender_decrypt + compute delta_i, broadcast delta_i.
//! 4. Reconstruct delta, compute R, output presignature.

#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::{Curve as CurveGroup, Group, GroupEncoding},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{
    conv::{biguint_to_scalar, curve_order, scalar_to_biguint},
    TecdsaCurve,
};
use tecdsa_joye_libert::mta::{JlMtA, JlMtaSenderState, JlMtaSetup};
use tecdsa_protocol::{state_machine::Outgoing, MtA, PartyId, Recipient};

use super::msg::{
    R1BroadcastPayload, R1P2pPayload, R2BroadcastPayload, R2P2pPayload, R3BroadcastPayload,
    Xal23PresignMsg,
};
use super::Xal23Presignature;
use crate::key_share::Xal23KeyShare;

// ---------------------------------------------------------------------------
// Helper: scalar (de)serialization
// ---------------------------------------------------------------------------

fn scalar_to_bytes<C: TecdsaCurve>(s: &C::Scalar) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let repr = s.to_repr();
    let slice: &[u8] = repr.as_ref();
    slice.to_vec()
}

pub(crate) fn scalar_from_bytes<C: TecdsaCurve>(bytes: &[u8]) -> tecdsa_core::Result<C::Scalar>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut fb = FieldBytes::<C>::default();
    if bytes.len() != fb.len() {
        return Err(TecdsaError::Other(format!(
            "invalid scalar length: expected {}, got {}",
            fb.len(),
            bytes.len()
        )));
    }
    fb.copy_from_slice(bytes);
    <C::Scalar as PrimeField>::from_repr(fb)
        .into_option()
        .ok_or_else(|| TecdsaError::Other("invalid scalar encoding".into()))
}

/// Decode a compressed/uncompressed SEC1-encoded EC point from bytes.
fn point_from_bytes<C: TecdsaCurve>(
    bytes: &[u8],
    label: &str,
) -> tecdsa_core::Result<C::ProjectivePoint>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let affine = C::point_from_bytes(bytes)
        .map_err(|_| TecdsaError::Other(format!("invalid EC point ({label})")))?;
    Ok(C::ProjectivePoint::from(affine))
}

// ---------------------------------------------------------------------------
// Round 1 state
// ---------------------------------------------------------------------------

/// State after Round 1 construction: waiting for peers' R1 messages.
pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub key_share: Xal23KeyShare<C>,
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    /// Nonce share k_i.
    pub k_i: C::Scalar,
    /// Mask share gamma_i.
    pub gamma_i: C::Scalar,
    /// Gamma point = gamma_i * G.
    pub gamma_point_i: C::ProjectivePoint,
    /// Signing share w_i = x_i (additive sharing).
    pub w_i: C::Scalar,
    /// Per-peer MtA sender states for gamma_i.
    pub gamma_sender_states: BTreeMap<PartyId, JlMtaSenderState>,
    /// Per-peer MtA sender states for w_i.
    pub w_sender_states: BTreeMap<PartyId, JlMtaSenderState>,
    /// Received R1 broadcast commitments.
    pub commitments: BTreeMap<PartyId, [u8; 32]>,
    /// Received R1 P2P MtA sender messages.
    pub r1_p2p: BTreeMap<PartyId, R1P2pPayload>,
    /// MtA statistical security parameter s.
    pub s: u32,
    /// MtA statistical security parameter t.
    pub t: u32,
    /// Outgoing messages queued by this round.
    pub outgoing: Vec<Outgoing<Xal23PresignMsg>>,
}

// ---------------------------------------------------------------------------
// Round 2 state
// ---------------------------------------------------------------------------

/// State after R1 -> R2 transition: waiting for peers' R2 messages.
pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub key_share: Xal23KeyShare<C>,
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub k_i: C::Scalar,
    pub gamma_i: C::Scalar,
    pub gamma_point_i: C::ProjectivePoint,
    pub w_i: C::Scalar,
    /// Per-peer MtA sender states for gamma_i (kept for R3 decrypt).
    pub gamma_sender_states: BTreeMap<PartyId, JlMtaSenderState>,
    /// Per-peer MtA sender states for w_i (kept for R3 decrypt).
    pub w_sender_states: BTreeMap<PartyId, JlMtaSenderState>,
    /// R1 commitments from all parties.
    pub commitments: BTreeMap<PartyId, [u8; 32]>,
    /// alpha_kg[j]: my alpha from receiver_compute(k_i, gamma_ct_j).
    pub alpha_kg: BTreeMap<PartyId, BigUint>,
    /// mu_kw[j]: my mu from receiver_compute(k_i, w_ct_j).
    pub mu_kw: BTreeMap<PartyId, BigUint>,
    /// Received R2 broadcast (gamma points).
    pub r2_bcast: BTreeMap<PartyId, R2BroadcastPayload>,
    /// Received R2 P2P (receiver messages).
    pub r2_p2p: BTreeMap<PartyId, R2P2pPayload>,
    pub s: u32,
    pub t: u32,
    pub outgoing: Vec<Outgoing<Xal23PresignMsg>>,
}

// ---------------------------------------------------------------------------
// Round 3 state
// ---------------------------------------------------------------------------

/// State after R2 -> R3 transition: waiting for peers' R3 delta broadcasts.
pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub k_i: C::Scalar,
    pub sigma_i: C::Scalar,
    /// All Gamma_j points (from R2 decommit).
    pub gamma_points: BTreeMap<PartyId, C::ProjectivePoint>,
    /// Received delta_j values.
    pub deltas: BTreeMap<PartyId, C::Scalar>,
    /// The public key (from key share).
    pub public_key: C::ProjectivePoint,
    pub outgoing: Vec<Outgoing<Xal23PresignMsg>>,
}

// ---------------------------------------------------------------------------
// Done state
// ---------------------------------------------------------------------------

/// Terminal state holding the completed presignature.
pub(crate) enum PresignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Round3(Round3State<C>),
    Done(Xal23Presignature<C>),
    Poisoned,
}

// ---------------------------------------------------------------------------
// Round 1 construction
// ---------------------------------------------------------------------------

/// Construct Round 1 state: sample k_i, gamma_i, commit, sender_encrypt.
pub(crate) fn build_round1<C: TecdsaCurve>(
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    key_share: &Xal23KeyShare<C>,
    s: u32,
    t: u32,
    rng: &mut impl rand_core::CryptoRngCore,
) -> tecdsa_core::Result<Round1State<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if !all_parties.contains(&my_id) {
        return Err(TecdsaError::Other("my_id not in all_parties".into()));
    }

    let my_idx = key_share.party_index as usize;

    // Sample k_i, gamma_i
    let k_i = C::random_scalar(rng);
    let gamma_i = C::random_scalar(rng);
    let gamma_point_i = C::generator() * gamma_i;

    // Signing share: additive sharing, w_i = x_i directly.
    let w_i = key_share.secret_share;

    // Commitment = SHA-256(compressed Gamma_i bytes)
    let gamma_point_bytes = gamma_point_i.to_bytes();
    let commitment: [u8; 32] = Sha256::new()
        .chain_update(gamma_point_bytes)
        .finalize()
        .into();

    // MtA setup and sender_encrypt for each peer
    let q = curve_order::<C>();
    let q_bytes = q.to_bytes_be();
    let gamma_i_bytes = scalar_to_biguint::<C>(&gamma_i).to_bytes_be();
    let w_i_bytes = scalar_to_biguint::<C>(&w_i).to_bytes_be();

    let mut gamma_sender_states = BTreeMap::new();
    let mut w_sender_states = BTreeMap::new();
    let mut outgoing = Vec::new();

    // Store own commitment
    let mut commitments = BTreeMap::new();
    commitments.insert(my_id, commitment);

    for &peer in &all_parties {
        if peer == my_id {
            continue;
        }

        // Build setup: encrypt under OWN key so WE can decrypt later in R3.
        let setup = JlMtaSetup {
            pk: key_share.jl_pks[my_idx].clone(),
            pk0: key_share.jl_pks[my_idx].clone(),
            sk: key_share.jl_sk.clone(),
            s,
            t,
        };

        // sender_encrypt for gamma_i
        let (gamma_msg, gamma_state) = JlMtA::sender_encrypt(&setup, &gamma_i_bytes, &q_bytes, rng)
            .map_err(|e| TecdsaError::Other(format!("gamma sender_encrypt: {e}")))?;
        gamma_sender_states.insert(peer, gamma_state);

        // sender_encrypt for w_i
        let (w_msg, w_state) = JlMtA::sender_encrypt(&setup, &w_i_bytes, &q_bytes, rng)
            .map_err(|e| TecdsaError::Other(format!("w sender_encrypt: {e}")))?;
        w_sender_states.insert(peer, w_state);

        // Queue R1 broadcast (commitment) to each peer
        outgoing.push(Outgoing {
            to: Recipient::Party(peer),
            msg: Xal23PresignMsg::R1Broadcast(R1BroadcastPayload { commitment }),
        });

        // Queue R1 P2P (sender messages) to each peer
        outgoing.push(Outgoing {
            to: Recipient::Party(peer),
            msg: Xal23PresignMsg::R1P2p(R1P2pPayload {
                gamma_sender_msg: gamma_msg,
                w_sender_msg: w_msg,
            }),
        });
    }

    Ok(Round1State {
        key_share: key_share.clone(),
        my_id,
        all_parties,
        k_i,
        gamma_i,
        gamma_point_i,
        w_i,
        gamma_sender_states,
        w_sender_states,
        commitments,
        r1_p2p: BTreeMap::new(),
        s,
        t,
        outgoing,
    })
}

// ---------------------------------------------------------------------------
// Round 1 -> Round 2 transition
// ---------------------------------------------------------------------------

/// Transition from Round 1 to Round 2.
///
/// After collecting all R1 messages, perform receiver_compute for each peer's
/// gamma and w ciphertexts using own k_i, then queue R2 messages.
pub(crate) fn transition_r1_to_r2<C: TecdsaCurve>(
    state: Round1State<C>,
    rng: &mut impl rand_core::CryptoRngCore,
) -> tecdsa_core::Result<Round2State<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q = curve_order::<C>();
    let q_bytes = q.to_bytes_be();
    let k_i_bytes = scalar_to_biguint::<C>(&state.k_i).to_bytes_be();

    let mut alpha_kg = BTreeMap::new();
    let mut mu_kw = BTreeMap::new();
    let mut outgoing = Vec::new();

    // Broadcast decommitment: Gamma_i point bytes
    let gamma_point_bytes = state.gamma_point_i.to_bytes().as_ref().to_vec();
    for &peer in &state.all_parties {
        if peer == state.my_id {
            continue;
        }
        outgoing.push(Outgoing {
            to: Recipient::Party(peer),
            msg: Xal23PresignMsg::R2Broadcast(R2BroadcastPayload {
                gamma_point_bytes: gamma_point_bytes.clone(),
            }),
        });
    }

    // For each peer j: receiver_compute(k_i, gamma_ct_j) and receiver_compute(k_i, w_ct_j)
    for (&peer, r1_payload) in &state.r1_p2p {
        // The sender encrypted under THEIR key, so we need their pk for receiver_compute.
        let peer_idx = state
            .all_parties
            .iter()
            .position(|p| *p == peer)
            .ok_or_else(|| TecdsaError::Other(format!("peer {peer} not in all_parties")))?;
        // Map party ID to key_share index. Peer's PartyId encodes their party_index.
        let peer_ks_idx = peer.0 as usize;

        let setup = JlMtaSetup {
            pk: state.key_share.jl_pks[peer_ks_idx].clone(),
            pk0: state.key_share.jl_pks[peer_ks_idx].clone(),
            sk: state.key_share.jl_sk.clone(), // not used in receiver_compute
            s: state.s,
            t: state.t,
        };

        // receiver_compute for gamma MtA: alpha_kg[peer] = my alpha
        let (gamma_recv_msg, alpha_bytes) = JlMtA::receiver_compute(
            &setup,
            &k_i_bytes,
            &q_bytes,
            &r1_payload.gamma_sender_msg,
            rng,
        )
        .map_err(|e| TecdsaError::Other(format!("gamma receiver_compute for {peer}: {e}")))?;
        alpha_kg.insert(peer, BigUint::from_bytes_be(&alpha_bytes));

        // receiver_compute for w MtA: mu_kw[peer] = my mu
        let (w_recv_msg, mu_bytes) =
            JlMtA::receiver_compute(&setup, &k_i_bytes, &q_bytes, &r1_payload.w_sender_msg, rng)
                .map_err(|e| TecdsaError::Other(format!("w receiver_compute for {peer}: {e}")))?;
        mu_kw.insert(peer, BigUint::from_bytes_be(&mu_bytes));

        // Queue R2 P2P to peer: receiver messages
        // Note: we send to the SENDER of the ciphertext (= peer) since they need
        // the affine result to decrypt in R3.
        let _ = peer_idx; // used for index lookup above
        outgoing.push(Outgoing {
            to: Recipient::Party(peer),
            msg: Xal23PresignMsg::R2P2p(R2P2pPayload {
                gamma_receiver_msg: gamma_recv_msg,
                w_receiver_msg: w_recv_msg,
            }),
        });
    }

    Ok(Round2State {
        key_share: state.key_share,
        my_id: state.my_id,
        all_parties: state.all_parties,
        k_i: state.k_i,
        gamma_i: state.gamma_i,
        gamma_point_i: state.gamma_point_i,
        w_i: state.w_i,
        gamma_sender_states: state.gamma_sender_states,
        w_sender_states: state.w_sender_states,
        commitments: state.commitments,
        alpha_kg,
        mu_kw,
        r2_bcast: BTreeMap::new(),
        r2_p2p: BTreeMap::new(),
        s: state.s,
        t: state.t,
        outgoing,
    })
}

// ---------------------------------------------------------------------------
// Round 2 -> Round 3 transition
// ---------------------------------------------------------------------------

/// Transition from Round 2 to Round 3.
///
/// Verify commitments, decrypt MtA results, compute delta_i and sigma_i,
/// broadcast delta_i.
pub(crate) fn transition_r2_to_r3<C: TecdsaCurve>(
    state: Round2State<C>,
) -> tecdsa_core::Result<Round3State<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q = curve_order::<C>();
    let q_bytes = q.to_bytes_be();
    let my_idx = state.key_share.party_index as usize;

    // Collect Gamma points. Start with own.
    let mut gamma_points: BTreeMap<PartyId, C::ProjectivePoint> = BTreeMap::new();
    gamma_points.insert(state.my_id, state.gamma_point_i);

    // Verify commitments and collect gamma points from peers.
    for (&peer, r2_bcast) in &state.r2_bcast {
        let expected_commitment = state
            .commitments
            .get(&peer)
            .ok_or_else(|| TecdsaError::Other(format!("missing R1 commitment for party {peer}")))?;

        // Recompute commitment and verify (constant-time).
        let recomputed: [u8; 32] = Sha256::new()
            .chain_update(&r2_bcast.gamma_point_bytes)
            .finalize()
            .into();
        if bool::from(!recomputed.ct_eq(expected_commitment)) {
            return Err(TecdsaError::Other(format!(
                "commitment verification failed for party {peer}"
            )));
        }

        let gp = point_from_bytes::<C>(&r2_bcast.gamma_point_bytes, &format!("Gamma from {peer}"))?;
        gamma_points.insert(peer, gp);
    }

    // sender_decrypt for each peer's receiver messages.
    // beta_kg[j]: my beta from sender_decrypt(gamma_state_j, receiver_msg from j).
    // nu_kw[j]: my nu from sender_decrypt(w_state_j, receiver_msg from j).
    let mut beta_kg: BTreeMap<PartyId, BigUint> = BTreeMap::new();
    let mut nu_kw: BTreeMap<PartyId, BigUint> = BTreeMap::new();

    // Build setup for own key (decrypt with own sk)
    let setup = JlMtaSetup {
        pk: state.key_share.jl_pks[my_idx].clone(),
        pk0: state.key_share.jl_pks[my_idx].clone(),
        sk: state.key_share.jl_sk.clone(),
        s: state.s,
        t: state.t,
    };

    for (&peer, r2_p2p) in &state.r2_p2p {
        let gamma_state = state
            .gamma_sender_states
            .get(&peer)
            .ok_or_else(|| TecdsaError::Other(format!("missing gamma sender state for {peer}")))?;
        let w_state = state
            .w_sender_states
            .get(&peer)
            .ok_or_else(|| TecdsaError::Other(format!("missing w sender state for {peer}")))?;

        // sender_decrypt for gamma MtA
        let beta_bytes =
            JlMtA::sender_decrypt(&setup, gamma_state, &q_bytes, &r2_p2p.gamma_receiver_msg)
                .map_err(|e| TecdsaError::Other(format!("gamma sender_decrypt for {peer}: {e}")))?;
        beta_kg.insert(peer, BigUint::from_bytes_be(&beta_bytes));

        // sender_decrypt for w MtA
        let nu_bytes = JlMtA::sender_decrypt(&setup, w_state, &q_bytes, &r2_p2p.w_receiver_msg)
            .map_err(|e| TecdsaError::Other(format!("w sender_decrypt for {peer}: {e}")))?;
        nu_kw.insert(peer, BigUint::from_bytes_be(&nu_bytes));
    }

    // Compute delta_i = k_i * gamma_i + sum_j(alpha_kg[j] + beta_kg[j])
    // alpha_kg[j] = my alpha from receiver_compute in R2 (I was receiver)
    // beta_kg[j] = my beta from sender_decrypt in R3 (I was sender-decryptor)
    let mut delta_i = state.k_i * state.gamma_i;
    for &peer in &state.all_parties {
        if peer == state.my_id {
            continue;
        }
        let alpha = state
            .alpha_kg
            .get(&peer)
            .ok_or_else(|| TecdsaError::Other(format!("missing alpha_kg for {peer}")))?;
        let beta = beta_kg
            .get(&peer)
            .ok_or_else(|| TecdsaError::Other(format!("missing beta_kg for {peer}")))?;
        delta_i += biguint_to_scalar::<C>(alpha);
        delta_i += biguint_to_scalar::<C>(beta);
    }

    // Compute sigma_i = k_i * w_i + sum_j(mu_kw[j] + nu_kw[j])
    let mut sigma_i = state.k_i * state.w_i;
    for &peer in &state.all_parties {
        if peer == state.my_id {
            continue;
        }
        let mu = state
            .mu_kw
            .get(&peer)
            .ok_or_else(|| TecdsaError::Other(format!("missing mu_kw for {peer}")))?;
        let nu = nu_kw
            .get(&peer)
            .ok_or_else(|| TecdsaError::Other(format!("missing nu_kw for {peer}")))?;
        sigma_i += biguint_to_scalar::<C>(mu);
        sigma_i += biguint_to_scalar::<C>(nu);
    }

    // Broadcast delta_i
    let delta_bytes = scalar_to_bytes::<C>(&delta_i);
    let mut outgoing = Vec::new();
    for &peer in &state.all_parties {
        if peer == state.my_id {
            continue;
        }
        outgoing.push(Outgoing {
            to: Recipient::Party(peer),
            msg: Xal23PresignMsg::R3Broadcast(R3BroadcastPayload {
                delta_i_bytes: delta_bytes.clone(),
            }),
        });
    }

    // Store own delta
    let mut deltas = BTreeMap::new();
    deltas.insert(state.my_id, delta_i);

    Ok(Round3State {
        my_id: state.my_id,
        all_parties: state.all_parties,
        k_i: state.k_i,
        sigma_i,
        gamma_points,
        deltas,
        public_key: state.key_share.public_key,
        outgoing,
    })
}

// ---------------------------------------------------------------------------
// Round 3 -> Done transition (finalize)
// ---------------------------------------------------------------------------

/// Finalize: reconstruct delta, Gamma, R, and produce the presignature.
pub(crate) fn finalize_r3<C: TecdsaCurve>(
    state: &Round3State<C>,
) -> tecdsa_core::Result<Xal23Presignature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // delta = sum(delta_j)
    let delta: C::Scalar = state
        .deltas
        .values()
        .copied()
        .fold(C::Scalar::ZERO, |a, b| a + b);

    let delta_inv = delta
        .invert()
        .into_option()
        .ok_or_else(|| TecdsaError::Other("delta is zero, cannot invert".into()))?;

    // Gamma = sum(Gamma_j)
    let Gamma: C::ProjectivePoint = state
        .gamma_points
        .values()
        .fold(C::ProjectivePoint::identity(), |acc, g| acc + g);

    // R = Gamma * delta^{-1}
    let R = Gamma * delta_inv;
    let R_affine = R.to_affine();
    let r = C::xcoord_mod_q(&R_affine);

    Ok(Xal23Presignature {
        R,
        r,
        k_i: state.k_i,
        sigma_i: state.sigma_i,
        public_key: state.public_key,
        my_id: state.my_id,
        signer_parties: state.all_parties.clone(),
    })
}
