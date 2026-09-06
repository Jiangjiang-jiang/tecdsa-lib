// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-session signing setup for LN18.
//!
//! LN18 signing requires per-session setup scoped to the signer subset:
//! 1. **Lagrange weighting**: convert Shamir shares to additive shares
//!    for the chosen signers.
//! 2. **Init**: ElGamal DKG for the signer subset (2 rounds).
//! 3. **Input(w_i)**: distribute Lagrange-weighted shares via the Input
//!    sub-protocol (2 rounds).
//! 4. **Paillier + NTilde**: generate Paillier keys and Ring-Pedersen
//!    parameters for each signer.
//!
//! This is analogous to CGGMP20's aux_info phase — protocol-specific
//! setup that runs after keygen but before signing.
//!
//! # Example
//!
//! ```ignore
//! let key_shares = run_keygen(n, t);
//! let signers = vec![PartyId(1), PartyId(2)];
//! let sign_params = build_signing_setup::<C>(&key_shares, &signers, &mut rng)?;
//! // sign_params[i] is ready for Ln18OfflineSignMachine
//! ```

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::zk::mta_range::NTildeParams;
use tecdsa_protocol::PartyId;

use crate::{
    f_mult::{
        init::InitState,
        input::{InputOutput, InputRound1Msg, InputRound2Msg, InputState},
    },
    key_share::Ln18KeyShare,
    sign::rounds::Ln18PresignParams,
};

/// Safe-prime size, in bits, for the Ring-Pedersen modulus `N~`.
///
/// Two primes of this size give a 3072-bit `N~`, matching the 128-bit
/// security profile the rest of the workspace targets. The MtA range proofs
/// exponentiate modulo `N~`, so this also determines their cost -- a smaller
/// modulus makes signing measurably but unrepresentatively faster.
pub const NTILDE_PRIME_BITS: u32 = 1536;

/// Build signing parameters for a signer subset from keygen output.
///
/// This is the canonical setup path for LN18 t-of-n signing. It:
/// 1. Computes Lagrange coefficients for the signer subset
/// 2. Runs Init (ElGamal DKG) with the signers
/// 3. Runs Input(w_i) with Lagrange-weighted shares
/// 4. Generates Paillier keys and NTilde params for each signer
///
/// On success, the returned `Ln18PresignParams` can be passed directly to
/// `Ln18OfflineSignMachine`.
///
/// The Ring-Pedersen modulus uses [`NTILDE_PRIME_BITS`]. Tests that do not
/// need production security can call
/// [`build_signing_setup_with_ntilde_bits`] with a smaller size.
pub fn build_signing_setup<C: TecdsaCurve>(
    key_shares: &[Ln18KeyShare<C>],
    signers: &[PartyId],
    rng: &mut impl CryptoRngCore,
) -> tecdsa_core::Result<Vec<Ln18PresignParams<C>>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    build_signing_setup_with_ntilde_bits(key_shares, signers, NTILDE_PRIME_BITS, rng)
}

/// As [`build_signing_setup`], but with an explicit Ring-Pedersen prime size.
///
/// Exists so tests can trade security for speed; generating two 1536-bit safe
/// primes per signer dominates setup otherwise. Anything other than
/// [`NTILDE_PRIME_BITS`] is for testing only -- the range proofs' soundness
/// rests on `N~` being hard to factor.
pub fn build_signing_setup_with_ntilde_bits<C: TecdsaCurve>(
    key_shares: &[Ln18KeyShare<C>],
    signers: &[PartyId],
    ntilde_prime_bits: u32,
    rng: &mut impl CryptoRngCore,
) -> tecdsa_core::Result<Vec<Ln18PresignParams<C>>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if key_shares.is_empty() {
        return Err(TecdsaError::Other("key_shares must not be empty".into()));
    }
    if signers.is_empty() {
        return Err(TecdsaError::Other("signers must not be empty".into()));
    }

    let public_key = key_shares[0].public_key;
    let n = key_shares[0].n;
    let t = key_shares[0].t;

    // 1. Lagrange coefficients (1-based evaluation points = PartyId values)
    let signer_pts: Vec<u16> = signers.iter().map(|p| p.0).collect();
    let lagrange = tecdsa_vss::lagrange::coefficients::<C>(&signer_pts);
    let weighted: Vec<C::Scalar> = signers
        .iter()
        .enumerate()
        .map(|(pos, pid)| {
            share_for_party(key_shares, *pid).map(|share| share.secret_share * lagrange[pos])
        })
        .collect::<tecdsa_core::Result<_>>()?;

    // 2. Init with signer subset
    let init_outputs = run_init(signers, rng);

    // 3. Paillier + NTilde for each signer
    let mut dks = Vec::with_capacity(signers.len());
    let mut eks = BTreeMap::new();
    let mut ntilde_map = BTreeMap::new();
    for &pid in signers {
        let dk = tecdsa_paillier::keygen(rng).expect("paillier keygen");
        eks.insert(pid, dk.encryption_key().clone());
        dks.push(dk);
        let nt = generate_ntilde(rng, ntilde_prime_bits);
        ntilde_map.insert(pid, nt);
    }

    // 4. Input(w_i) for signer subset
    let stored_x_inputs = run_input(signers, init_outputs[0].elgamal_pk, &weighted, rng);

    // 5. Build params
    let params = signers
        .iter()
        .enumerate()
        .map(|(pos, &pid)| {
            let share = share_for_party(key_shares, pid)?;
            Ok(Ln18PresignParams {
                key_share: Ln18KeyShare {
                    party_index: pid.0,
                    secret_share: share.secret_share,
                    public_key,
                    public_shares: key_shares[0].public_shares.clone(),
                    n,
                    t,
                },
                paillier_dk: dks[pos].clone(),
                paillier_eks: eks.clone(),
                ntilde_params: ntilde_map.clone(),
                init_output: init_outputs[pos].clone(),
                stored_x_input: stored_x_inputs[pos].clone(),
            })
        })
        .collect::<tecdsa_core::Result<_>>()?;

    Ok(params)
}

// --- Internal helpers ---

fn share_for_party<C: TecdsaCurve>(
    key_shares: &[Ln18KeyShare<C>],
    pid: PartyId,
) -> tecdsa_core::Result<&Ln18KeyShare<C>>
where
    FieldBytesSize<C>: ModulusSize,
{
    key_shares
        .iter()
        .find(|share| share.party_index == pid.0)
        .ok_or_else(|| TecdsaError::Other(format!("missing key share for signer {pid}")))
}

fn run_init<C: TecdsaCurve>(
    parties: &[PartyId],
    rng: &mut impl CryptoRngCore,
) -> Vec<crate::f_mult::init::InitOutput<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let s = parties.len();
    let mut states = Vec::with_capacity(s);
    let mut r1_msgs = Vec::with_capacity(s);
    for &pid in parties {
        let (state, msg) = InitState::<C>::new(pid, parties.to_vec(), rng);
        states.push(state);
        r1_msgs.push(msg);
    }
    let mut r2_msgs = Vec::with_capacity(s);
    for i in 0..s {
        let others: Vec<_> = r1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        r2_msgs.push(states[i].handle_round1(&others).expect("init R1"));
    }
    let mut outputs = Vec::with_capacity(s);
    for i in 0..s {
        let others: Vec<_> = r2_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        outputs.push(states[i].finish_round2(&others).expect("init R2"));
    }
    outputs
}

fn run_input<C: TecdsaCurve>(
    parties: &[PartyId],
    elgamal_pk: C::ProjectivePoint,
    values: &[C::Scalar],
    rng: &mut impl CryptoRngCore,
) -> Vec<InputOutput<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let s = parties.len();
    let mut states = Vec::with_capacity(s);
    let mut r1_msgs: Vec<InputRound1Msg> = Vec::with_capacity(s);
    for (i, &pid) in parties.iter().enumerate() {
        let (state, msg) = InputState::<C>::new(pid, parties.to_vec(), elgamal_pk, values[i], rng);
        states.push(state);
        r1_msgs.push(msg);
    }
    let mut r2_msgs: Vec<InputRound2Msg<C>> = Vec::with_capacity(s);
    for i in 0..s {
        let others: Vec<_> = r1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        r2_msgs.push(states[i].handle_round1(&others).expect("input R1"));
    }
    let mut outputs = Vec::with_capacity(s);
    for i in 0..s {
        let others: Vec<_> = r2_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        outputs.push(states[i].finish_round2(&others).expect("input R2"));
    }
    outputs
}

fn generate_ntilde(rng: &mut impl CryptoRngCore) -> NTildeParams {
    use tecdsa_paillier::{backend::Integer, BigIntExt};
    let p = Integer::generate_safe_prime(rng, 256);
    let q = Integer::generate_safe_prime(rng, 256);
    let n_tilde = Integer::from(&p * &q);
    let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);
    let phi_n = (&p - Integer::one()) * (&q - Integer::one());
    let lambda = phi_n.sample_below_ref(rng);
    let h2 = Integer::from(h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod"));
    NTildeParams {
        N_tilde: n_tilde,
        h1,
        h2,
    }
}
