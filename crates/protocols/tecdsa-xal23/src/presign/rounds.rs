#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::{Curve as CurveGroup, Group, GroupEncoding},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rug::{integer::Order, Integer};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{
    conv::{curve_order, integer_to_scalar, scalar_to_integer},
    TecdsaCurve,
};
use tecdsa_joye_libert::mta::{JlMtA, JlMtaSenderState, JlMtaSetup};
use tecdsa_protocol::{state_machine::Outgoing, MtA, PartyId, Recipient};

use super::{
    msg::{
        R1BroadcastPayload, R1P2pPayload, R2BroadcastPayload, R2P2pPayload, R3BroadcastPayload,
        Xal23PresignMsg,
    },
    Xal23Presignature,
};
use crate::key_share::Xal23KeyShare;

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

pub(crate) struct Round1State<C: TecdsaCurve>
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
    pub gamma_sender_states: BTreeMap<PartyId, JlMtaSenderState>,
    pub w_sender_states: BTreeMap<PartyId, JlMtaSenderState>,
    pub commitments: BTreeMap<PartyId, [u8; 32]>,
    pub r1_p2p: BTreeMap<PartyId, R1P2pPayload>,
    pub s: u32,
    pub t: u32,
    pub outgoing: Vec<Outgoing<Xal23PresignMsg>>,
}

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
    pub gamma_sender_states: BTreeMap<PartyId, JlMtaSenderState>,
    pub w_sender_states: BTreeMap<PartyId, JlMtaSenderState>,
    pub commitments: BTreeMap<PartyId, [u8; 32]>,
    pub alpha_kg: BTreeMap<PartyId, Integer>,
    pub mu_kw: BTreeMap<PartyId, Integer>,
    pub r2_bcast: BTreeMap<PartyId, R2BroadcastPayload>,
    pub r2_p2p: BTreeMap<PartyId, R2P2pPayload>,
    pub s: u32,
    pub t: u32,
    pub outgoing: Vec<Outgoing<Xal23PresignMsg>>,
}

pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub k_i: C::Scalar,
    pub sigma_i: C::Scalar,
    pub gamma_points: BTreeMap<PartyId, C::ProjectivePoint>,
    pub deltas: BTreeMap<PartyId, C::Scalar>,
    pub public_key: C::ProjectivePoint,
    pub outgoing: Vec<Outgoing<Xal23PresignMsg>>,
}

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

    let k_i = C::random_scalar(rng);
    let gamma_i = C::random_scalar(rng);
    let gamma_point_i = C::generator() * gamma_i;

    let w_i = key_share.secret_share;

    let gamma_point_bytes = gamma_point_i.to_bytes();
    let commitment: [u8; 32] = Sha256::new()
        .chain_update(gamma_point_bytes)
        .finalize()
        .into();

    let q = curve_order::<C>();
    let q_bytes = q.to_digits::<u8>(Order::Msf);
    let gamma_i_bytes = scalar_to_integer::<C>(&gamma_i).to_digits::<u8>(Order::Msf);
    let w_i_bytes = scalar_to_integer::<C>(&w_i).to_digits::<u8>(Order::Msf);

    let mut gamma_sender_states = BTreeMap::new();
    let mut w_sender_states = BTreeMap::new();
    let mut outgoing = Vec::new();

    let mut commitments = BTreeMap::new();
    commitments.insert(my_id, commitment);

    for &peer in &all_parties {
        if peer == my_id {
            continue;
        }

        let setup = JlMtaSetup {
            pk: key_share.jl_pks[my_idx].clone(),
            pk0: key_share.jl_pks[my_idx].clone(),
            sk: key_share.jl_sk.clone(),
            s,
            t,
        };

        let (gamma_msg, gamma_state) = JlMtA::sender_encrypt(&setup, &gamma_i_bytes, &q_bytes, rng)
            .map_err(|e| TecdsaError::Other(format!("gamma sender_encrypt: {e}")))?;
        gamma_sender_states.insert(peer, gamma_state);

        let (w_msg, w_state) = JlMtA::sender_encrypt(&setup, &w_i_bytes, &q_bytes, rng)
            .map_err(|e| TecdsaError::Other(format!("w sender_encrypt: {e}")))?;
        w_sender_states.insert(peer, w_state);

        outgoing.push(Outgoing {
            to: Recipient::Party(peer),
            msg: Xal23PresignMsg::R1Broadcast(R1BroadcastPayload { commitment }),
        });

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

pub(crate) fn transition_r1_to_r2<C: TecdsaCurve>(
    state: Round1State<C>,
    rng: &mut impl rand_core::CryptoRngCore,
) -> tecdsa_core::Result<Round2State<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q = curve_order::<C>();
    let q_bytes = q.to_digits::<u8>(Order::Msf);
    let k_i_bytes = scalar_to_integer::<C>(&state.k_i).to_digits::<u8>(Order::Msf);

    let mut alpha_kg = BTreeMap::new();
    let mut mu_kw = BTreeMap::new();
    let mut outgoing = Vec::new();

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

    for (&peer, r1_payload) in &state.r1_p2p {
        let peer_idx = state
            .all_parties
            .iter()
            .position(|p| *p == peer)
            .ok_or_else(|| TecdsaError::Other(format!("peer {peer} not in all_parties")))?;

        let setup = JlMtaSetup {
            pk: state.key_share.jl_pks[peer_idx].clone(),
            pk0: state.key_share.jl_pks[peer_idx].clone(),
            sk: state.key_share.jl_sk.clone(),
            s: state.s,
            t: state.t,
        };

        let (gamma_recv_msg, alpha_bytes) = JlMtA::receiver_compute(
            &setup,
            &k_i_bytes,
            &q_bytes,
            &r1_payload.gamma_sender_msg,
            rng,
        )
        .map_err(|e| TecdsaError::Other(format!("gamma receiver_compute for {peer}: {e}")))?;
        alpha_kg.insert(peer, Integer::from_digits(&alpha_bytes, Order::Msf));

        let (w_recv_msg, mu_bytes) =
            JlMtA::receiver_compute(&setup, &k_i_bytes, &q_bytes, &r1_payload.w_sender_msg, rng)
                .map_err(|e| TecdsaError::Other(format!("w receiver_compute for {peer}: {e}")))?;
        mu_kw.insert(peer, Integer::from_digits(&mu_bytes, Order::Msf));

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

pub(crate) fn transition_r2_to_r3<C: TecdsaCurve>(
    state: Round2State<C>,
) -> tecdsa_core::Result<Round3State<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q = curve_order::<C>();
    let q_bytes = q.to_digits::<u8>(Order::Msf);
    let my_idx = state.key_share.party_index as usize;

    let mut gamma_points: BTreeMap<PartyId, C::ProjectivePoint> = BTreeMap::new();
    gamma_points.insert(state.my_id, state.gamma_point_i);

    for (&peer, r2_bcast) in &state.r2_bcast {
        let expected_commitment = state
            .commitments
            .get(&peer)
            .ok_or_else(|| TecdsaError::Other(format!("missing R1 commitment for party {peer}")))?;

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

    let mut beta_kg: BTreeMap<PartyId, Integer> = BTreeMap::new();
    let mut nu_kw: BTreeMap<PartyId, Integer> = BTreeMap::new();

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

        let beta_bytes =
            JlMtA::sender_decrypt(&setup, gamma_state, &q_bytes, &r2_p2p.gamma_receiver_msg)
                .map_err(|e| TecdsaError::Other(format!("gamma sender_decrypt for {peer}: {e}")))?;
        beta_kg.insert(peer, Integer::from_digits(&beta_bytes, Order::Msf));

        let nu_bytes = JlMtA::sender_decrypt(&setup, w_state, &q_bytes, &r2_p2p.w_receiver_msg)
            .map_err(|e| TecdsaError::Other(format!("w sender_decrypt for {peer}: {e}")))?;
        nu_kw.insert(peer, Integer::from_digits(&nu_bytes, Order::Msf));
    }

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
        delta_i += integer_to_scalar::<C>(alpha);
        delta_i += integer_to_scalar::<C>(beta);
    }

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
        sigma_i += integer_to_scalar::<C>(mu);
        sigma_i += integer_to_scalar::<C>(nu);
    }

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

pub(crate) fn finalize_r3<C: TecdsaCurve>(
    state: &Round3State<C>,
) -> tecdsa_core::Result<Xal23Presignature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let delta: C::Scalar = state
        .deltas
        .values()
        .copied()
        .fold(C::Scalar::ZERO, |a, b| a + b);

    let delta_inv = delta
        .invert()
        .into_option()
        .ok_or_else(|| TecdsaError::Other("delta is zero, cannot invert".into()))?;

    let Gamma: C::ProjectivePoint = state
        .gamma_points
        .values()
        .fold(C::ProjectivePoint::identity(), |acc, g| acc + g);

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
