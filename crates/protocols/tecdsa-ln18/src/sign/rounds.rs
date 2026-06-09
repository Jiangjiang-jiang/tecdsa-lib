// SPDX-License-Identifier: MIT OR Apache-2.0
//! LN18 threshold ECDSA signing (Protocol 5.1), split into Presign + OnlineSign.
//!
//! ## Presign (Offline, message-independent) -- 8 rounds
//!
//! Following Section 5.2.1 of the paper, we parallelize the sub-protocols:
//!
//! - **Rounds 1-2: Input(k) || Input(rho)** — both inputs run simultaneously,
//!   sharing the same 2 commitment/decommitment rounds.
//! - **Round 3: Element-out(k).R1 || Mult(k,rho).R1** — element-out and mult
//!   start simultaneously. Element-out completes after this round. MtA (Step 0
//!   of mult) runs before Round 3 as a local computation.
//! - **Rounds 4-8: Mult(k,rho).R2-R6** — mult continues its remaining 5 rounds.
//!
//! Total presign: 2 + 6 = 8 interaction rounds (paper-matching).
//! Output: [`Ln18Presignature`] per party.
//!
//! ## OnlineSign (needs message) -- 6 rounds
//!
//! 4. **Affine** (local): compute alpha = m' + x*r using the stored x input
//!    from KeyGen. No communication.
//! 5. **Mult rho*alpha** (6 rounds): compute additive shares of beta = rho*alpha
//!    via F_mult.mult backed by Paillier MtA (includes checkDH).
//! 6. **Compute s** (local): s = tau^{-1} * beta, normalize to low-S.
//!
//! Total online: 6 interaction rounds.

#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::{Curve as CurveGroup, GroupEncoding},
    ops::LinearCombination,
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{zk::mta_range::NTildeParams, DecryptionKey, EncryptionKey};
use tecdsa_protocol::{
    ecdsa::{low_s_normalize, Signature},
    PartyId,
};

use crate::{
    f_mult::{
        affine::{affine, AffineInput, AffineOutput},
        element_out::{ElementOutMsg, ElementOutState},
        init::InitOutput,
        input::{InputOutput, InputRound1Msg, InputRound2Msg, InputState},
        mult::{
            MultOutput, MultRound1Msg, MultRound1Result, MultRound2Msg, MultRound2Result,
            MultRound3Msg, MultRound3Result, MultRound4Msg, MultRound4Result, MultRound5Msg,
            MultState,
        },
    },
    key_share::{Ln18KeyShare, Ln18Presignature},
    mta::paillier::{MtaRound1Msg, MtaRound2Msg, PaillierMtaState},
};

// ===========================================================================
// Parameter types
// ===========================================================================

/// Parameters needed to run the LN18 signing protocol for a single party.
///
/// For t-of-n signing, use [`sign::build_signing_setup`](crate::sign::build_signing_setup)
/// to construct these from keygen output. It handles Lagrange weighting,
/// per-session Init, and Input(w_i) automatically.
///
/// `stored_x_input` must contain the **Lagrange-weighted** share for this
/// signer subset (via `Input(λ_i · f(party_id))`), not the raw keygen share.
pub struct Ln18PresignParams<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's key share from keygen.
    pub key_share: Ln18KeyShare<C>,
    /// This party's Paillier decryption key.
    pub paillier_dk: DecryptionKey,
    /// Paillier encryption keys for all signer parties.
    pub paillier_eks: BTreeMap<PartyId, EncryptionKey>,
    /// Ring-Pedersen auxiliary parameters for all signer parties.
    pub ntilde_params: BTreeMap<PartyId, NTildeParams>,
    /// Init output for this signing session (ElGamal key material,
    /// scoped to the signer subset).
    pub init_output: InitOutput<C>,
    /// Lagrange-weighted x input for this signer subset, produced by
    /// running `Input(w_i)` where `w_i = λ_i · f(party_id)`.
    pub stored_x_input: InputOutput<C>,
}

/// Legacy alias: `Ln18SignParams` maps to `Ln18PresignParams` for backward compatibility.
pub type Ln18SignParams<C> = Ln18PresignParams<C>;

// ===========================================================================
// Presign (Offline, message-independent)
// ===========================================================================

/// Run the LN18 presign (offline) protocol for all parties in parallel (simulation).
///
/// This produces message-independent [`Ln18Presignature`]s that can later be
/// combined with a message digest in [`ln18_online_sign_parallel`].
///
/// Achieves 8 rounds by parallelizing sub-protocols per Section 5.2.1:
/// - Rounds 1-2: Input(k) || Input(rho) (both inputs share the same 2 rounds)
/// - Round 3: Element-out(k) || Mult(k,rho).R1 (start both simultaneously)
/// - Rounds 4-8: Mult(k,rho).R2-R6 (element-out already done after Round 3)
pub fn ln18_presign_parallel<C: TecdsaCurve>(
    params: &[Ln18PresignParams<C>],
    parties: &[PartyId],
    rng: &mut impl CryptoRngCore,
) -> Vec<Ln18Presignature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]> + GroupEncoding,
{
    let n = parties.len();
    assert_eq!(params.len(), n, "must have one param set per party");

    let elgamal_pk = params[0].init_output.elgamal_pk;
    let pk_shares = &params[0].init_output.elgamal_pk_shares;

    // ---------------------------------------------------------------
    // Rounds 1-2: Input(k) || Input(rho) — both inputs run in parallel,
    // sharing the same 2 commitment/decommitment rounds.
    // ---------------------------------------------------------------
    let k_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();
    let rho_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();

    let (input_k_outputs, input_rho_outputs) =
        run_parallel_input_phases::<C>(parties, elgamal_pk, &k_shares, &rho_shares, rng);

    // ---------------------------------------------------------------
    // MtA (Step 0, no interaction rounds — runs before Round 3)
    // ---------------------------------------------------------------
    let tau_mta_shares = run_paillier_mta::<C>(parties, &k_shares, &rho_shares, params, rng);

    // ---------------------------------------------------------------
    // Round 3: Element-out(k) || Mult(k,rho).R1 — both start simultaneously
    // ---------------------------------------------------------------
    // Create element-out states + messages
    let mut eo_states: Vec<ElementOutState<C>> = Vec::with_capacity(n);
    let mut eo_msgs: Vec<ElementOutMsg<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) = ElementOutState::<C>::new(
            parties[i],
            parties.to_vec(),
            input_k_outputs[i].a_i,
            input_k_outputs[i].s_i,
            input_k_outputs[i].per_party_cts.clone(),
            elgamal_pk,
            rng,
        );
        eo_states.push(state);
        eo_msgs.push(msg);
    }

    // Create mult states + Round-1 messages (simultaneously with element-out)
    let d_shares: Vec<C::Scalar> = params.iter().map(|p| p.init_output.d_i).collect();
    let mut mult_states: Vec<MultState<C>> = Vec::with_capacity(n);
    let mut mult_r1_msgs: Vec<MultRound1Msg<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) = MultState::<C>::new(
            parties[i],
            parties.to_vec(),
            &input_k_outputs[i],
            &input_rho_outputs[i],
            tau_mta_shares[i],
            elgamal_pk,
            d_shares[i],
            pk_shares.to_vec(),
            rng,
        );
        mult_states.push(state);
        mult_r1_msgs.push(msg);
    }

    // --- After Round 3: element-out finishes (1-round protocol), extract R ---
    let mut R_point = None;
    for i in 0..n {
        let others: Vec<_> = eo_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let eo_output = eo_states[i]
            .finish(&others)
            .expect("element-out should succeed");
        if R_point.is_none() {
            R_point = Some(eo_output.element);
        }
    }
    let R = R_point.expect("must have at least one party");

    // Compute r = x-coord(R) mod q
    let r: C::Scalar = C::xcoord_mod_q(&R.to_affine());
    if r.is_zero().into() {
        // Probability 1/q (< 2^{-256}): mathematically negligible.
        panic!("r is zero -- probability < 2^{{-256}}");
    }

    // ---------------------------------------------------------------
    // Rounds 4-8: Mult(k,rho).R2-R6 (element-out is already done)
    // ---------------------------------------------------------------
    let tau_mult_outputs = continue_mult_phase::<C>(&mut mult_states, &mult_r1_msgs, rng);

    // ---------------------------------------------------------------
    // Build presignatures
    // ---------------------------------------------------------------
    let mut presigs = Vec::with_capacity(n);
    for i in 0..n {
        presigs.push(Ln18Presignature {
            R,
            r,
            tau_i: tau_mult_outputs[i].c_i,
            stored_rho_input: input_rho_outputs[i].clone(),
            stored_x_input: params[i].stored_x_input.clone(),
            elgamal_dk: params[i].init_output.d_i,
            elgamal_pk,
            elgamal_pk_shares: pk_shares.clone(),
        });
    }
    presigs
}

// ===========================================================================
// OnlineSign (needs message)
// ===========================================================================

/// Parameters for the online signing phase (Paillier MtA variant).
pub struct Ln18OnlineSignParams<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's Paillier decryption key.
    pub paillier_dk: DecryptionKey,
    /// Paillier encryption keys for all parties.
    pub paillier_eks: BTreeMap<PartyId, EncryptionKey>,
    /// Ring-Pedersen auxiliary parameters for all parties.
    pub ntilde_params: BTreeMap<PartyId, NTildeParams>,
    /// This party's presignature from the offline phase.
    pub presignature: Ln18Presignature<C>,
}

/// Run the LN18 online signing protocol for all parties in parallel (simulation).
///
/// Takes presignatures from [`ln18_presign_parallel`] plus the message digest
/// and produces ECDSA signatures.
///
/// Steps: affine(m'+xr) + mult(rho, alpha) + compute s.
pub fn ln18_online_sign_parallel<C: TecdsaCurve>(
    online_params: &[Ln18OnlineSignParams<C>],
    parties: &[PartyId],
    message_digest: &C::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Vec<Signature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]> + GroupEncoding,
{
    let n = parties.len();
    assert_eq!(online_params.len(), n, "must have one param set per party");

    let r = online_params[0].presignature.r;
    let elgamal_pk = online_params[0].presignature.elgamal_pk;
    let pk_shares = &online_params[0].presignature.elgamal_pk_shares;

    // ---------------------------------------------------------------
    // Step 4: Affine -- compute alpha = m' + x * r (local, no communication)
    // ---------------------------------------------------------------
    let m_prime = *message_digest;
    let mut affine_outputs: Vec<AffineOutput<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let stored_x = &online_params[i].presignature.stored_x_input;
        let aff_input = AffineInput::<C> {
            ciphertext: stored_x.ciphertext.clone(),
            a_i: stored_x.a_i,
            s_i: stored_x.s_i,
            per_party_cts: stored_x.per_party_cts.clone(),
        };
        let output = affine::<C>(aff_input, &r, &m_prime, n as u16);
        affine_outputs.push(output);
    }

    // Convert affine outputs to InputOutput for the next mult phase
    let alpha_as_input: Vec<InputOutput<C>> = affine_outputs
        .into_iter()
        .map(|ao| InputOutput {
            ciphertext: ao.ciphertext,
            a_i: ao.a_i,
            s_i: ao.s_i,
            per_party_cts: ao.per_party_cts,
        })
        .collect();

    // ---------------------------------------------------------------
    // Step 5: Mult(rho, alpha) -> beta shares (beta = rho * alpha = rho*(m'+xr))
    // ---------------------------------------------------------------
    let rho_shares: Vec<C::Scalar> = online_params
        .iter()
        .map(|p| p.presignature.stored_rho_input.a_i)
        .collect();
    let alpha_shares: Vec<C::Scalar> = alpha_as_input.iter().map(|io| io.a_i).collect();

    // Build temporary Ln18PresignParams just for the MtA helper
    let temp_presign_params: Vec<Ln18PresignParams<C>> = online_params
        .iter()
        .map(|op| Ln18PresignParams {
            key_share: Ln18KeyShare {
                party_index: 0,
                secret_share: C::Scalar::ZERO,
                public_key: C::ProjectivePoint::default(),
                public_shares: Vec::new(),
                n: n as u16,
                t: 0,
            },
            paillier_dk: op.paillier_dk.clone(),
            paillier_eks: op.paillier_eks.clone(),
            ntilde_params: op.ntilde_params.clone(),
            init_output: InitOutput {
                d_i: op.presignature.elgamal_dk,
                elgamal_pk: op.presignature.elgamal_pk,
                elgamal_pk_shares: op.presignature.elgamal_pk_shares.clone(),
            },
            stored_x_input: op.presignature.stored_x_input.clone(),
        })
        .collect();

    let beta_mta_shares = run_paillier_mta::<C>(
        parties,
        &rho_shares,
        &alpha_shares,
        &temp_presign_params,
        rng,
    );

    let d_shares: Vec<C::Scalar> = online_params
        .iter()
        .map(|p| p.presignature.elgamal_dk)
        .collect();
    let input_rho_outputs: Vec<InputOutput<C>> = online_params
        .iter()
        .map(|p| p.presignature.stored_rho_input.clone())
        .collect();
    let beta_mult_outputs = run_mult_phase::<C>(
        parties,
        &input_rho_outputs,
        &alpha_as_input,
        &beta_mta_shares,
        elgamal_pk,
        &d_shares,
        pk_shares,
        rng,
    );

    // ---------------------------------------------------------------
    // Step 6: Compute s = tau^{-1} * beta, normalize to low-S
    // ---------------------------------------------------------------
    let tau: C::Scalar = online_params
        .iter()
        .map(|p| p.presignature.tau_i)
        .reduce(|acc, x| acc + x)
        .expect("at least one party");
    let beta: C::Scalar = beta_mult_outputs
        .iter()
        .map(|o| o.c_i)
        .reduce(|acc, x| acc + x)
        .expect("at least one party");

    let tau_inv = tau
        .invert()
        .into_option()
        .expect("tau (k*rho) must be invertible");
    let s_raw = tau_inv * beta;
    let s = low_s_normalize::<C>(s_raw);

    (0..n).map(|_| Signature { r, s }).collect()
}

// ===========================================================================
// FullSign -- 8-round mode with interleaved mult1/mult2
// ===========================================================================

/// Run the LN18 full-sign protocol in 8 rounds with interleaved mult1/mult2.
///
/// When the message `m` is known from the start, we can interleave the two
/// multiplication sub-protocols (mult1 = k*rho, mult2 = rho*alpha) to achieve
/// the paper's optimal 8-round signing:
///
/// | Round | Activity                                                    |
/// |-------|-------------------------------------------------------------|
/// | 1-2   | Input(k) ‖ Input(rho)                                       |
/// | 3     | Element-out(k) ‖ Mult1(k,rho).R1 → get R,r; affine; MtA₂   |
/// | 4     | Mult1.R2 ‖ Mult2.R1                                         |
/// | 5     | Mult1.R3 ‖ Mult2.R2                                         |
/// | 6     | Mult1.R4 ‖ Mult2.R3                                         |
/// | 7     | Mult1.R5 ‖ Mult2.R4                                         |
/// | 8     | Mult1.R6 ‖ Mult2.R5                                         |
///
/// After Round 8: Mult2.R6 (local verify), compute s = tau⁻¹ · beta.
pub fn ln18_full_sign_parallel<C: TecdsaCurve>(
    params: &[Ln18PresignParams<C>],
    parties: &[PartyId],
    message_digest: &C::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Vec<Signature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]> + GroupEncoding,
{
    let n = parties.len();
    assert_eq!(params.len(), n, "must have one param set per party");

    let elgamal_pk = params[0].init_output.elgamal_pk;
    let pk_shares = &params[0].init_output.elgamal_pk_shares;

    // ---------------------------------------------------------------
    // Rounds 1-2: Input(k) || Input(rho) — both inputs run in parallel,
    // sharing the same 2 commitment/decommitment rounds.
    // ---------------------------------------------------------------
    let k_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();
    let rho_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();

    let (input_k_outputs, input_rho_outputs) =
        run_parallel_input_phases::<C>(parties, elgamal_pk, &k_shares, &rho_shares, rng);

    // ---------------------------------------------------------------
    // MtA₁ (Step 0 for mult1: k*rho — no interaction rounds)
    // ---------------------------------------------------------------
    let tau_mta_shares = run_paillier_mta::<C>(parties, &k_shares, &rho_shares, params, rng);

    // ---------------------------------------------------------------
    // Round 3: Element-out(k) || Mult1(k,rho).R1
    // ---------------------------------------------------------------
    let mut eo_states: Vec<ElementOutState<C>> = Vec::with_capacity(n);
    let mut eo_msgs: Vec<ElementOutMsg<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) = ElementOutState::<C>::new(
            parties[i],
            parties.to_vec(),
            input_k_outputs[i].a_i,
            input_k_outputs[i].s_i,
            input_k_outputs[i].per_party_cts.clone(),
            elgamal_pk,
            rng,
        );
        eo_states.push(state);
        eo_msgs.push(msg);
    }

    let d_shares: Vec<C::Scalar> = params.iter().map(|p| p.init_output.d_i).collect();
    let mut mult1_states: Vec<MultState<C>> = Vec::with_capacity(n);
    let mut mult1_r1_msgs: Vec<MultRound1Msg<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) = MultState::<C>::new(
            parties[i],
            parties.to_vec(),
            &input_k_outputs[i],
            &input_rho_outputs[i],
            tau_mta_shares[i],
            elgamal_pk,
            d_shares[i],
            pk_shares.to_vec(),
            rng,
        );
        mult1_states.push(state);
        mult1_r1_msgs.push(msg);
    }

    // --- After Round 3: element-out finishes, extract R ---
    let mut R_point = None;
    for i in 0..n {
        let others: Vec<_> = eo_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let eo_output = eo_states[i]
            .finish(&others)
            .expect("element-out should succeed");
        if R_point.is_none() {
            R_point = Some(eo_output.element);
        }
    }
    let R = R_point.expect("must have at least one party");

    let r: C::Scalar = C::xcoord_mod_q(&R.to_affine());
    if r.is_zero().into() {
        // Probability 1/q (< 2^{-256}): mathematically negligible.
        panic!("r is zero -- probability < 2^{{-256}}");
    }

    // --- Affine: compute alpha = m' + x*r (local, no communication) ---
    let m_prime = *message_digest;
    let mut alpha_as_input: Vec<InputOutput<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let stored_x = &params[i].stored_x_input;
        let aff_input = AffineInput::<C> {
            ciphertext: stored_x.ciphertext.clone(),
            a_i: stored_x.a_i,
            s_i: stored_x.s_i,
            per_party_cts: stored_x.per_party_cts.clone(),
        };
        let output = affine::<C>(aff_input, &r, &m_prime, n as u16);
        alpha_as_input.push(InputOutput {
            ciphertext: output.ciphertext,
            a_i: output.a_i,
            s_i: output.s_i,
            per_party_cts: output.per_party_cts,
        });
    }

    // --- MtA₂ (Step 0 for mult2: rho*alpha — runs between R3 and R4) ---
    let alpha_shares: Vec<C::Scalar> = alpha_as_input.iter().map(|io| io.a_i).collect();
    let beta_mta_shares = run_paillier_mta::<C>(parties, &rho_shares, &alpha_shares, params, rng);

    // --- Create mult2 states (will start R1 in Round 4) ---
    let mut mult2_states: Vec<MultState<C>> = Vec::with_capacity(n);
    let mut mult2_r1_msgs: Vec<MultRound1Msg<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) = MultState::<C>::new(
            parties[i],
            parties.to_vec(),
            &input_rho_outputs[i],
            &alpha_as_input[i],
            beta_mta_shares[i],
            elgamal_pk,
            d_shares[i],
            pk_shares.to_vec(),
            rng,
        );
        mult2_states.push(state);
        mult2_r1_msgs.push(msg);
    }

    // ---------------------------------------------------------------
    // Round 4: Mult1.R2 || Mult2.R1
    // ---------------------------------------------------------------
    // Mult1: process R1 msgs -> produce R2 msgs
    let mut mult1_r2_msgs: Vec<MultRound2Msg<C>> = Vec::with_capacity(n);
    let mut mult1_r1_results: Vec<MultRound1Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult1_r1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r2, r1_res) = mult1_states[i]
            .handle_round1(&others, &mult1_r1_msgs[i], rng)
            .expect("mult1 Round-1 should succeed");
        mult1_r2_msgs.push(r2);
        mult1_r1_results.push(r1_res);
    }
    // Mult2: R1 messages were already produced by MultState::new above.
    // (mult2_r1_msgs are sent in this round)

    // ---------------------------------------------------------------
    // Round 5: Mult1.R3 || Mult2.R2
    // ---------------------------------------------------------------
    // Mult1: handle R2 -> produce R3
    let mut mult1_r3_msgs: Vec<MultRound3Msg<C>> = Vec::with_capacity(n);
    let mut mult1_r2_results: Vec<MultRound2Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult1_r2_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r3, r2_res) = mult1_states[i]
            .handle_round2(&others, &mult1_r1_results[i], rng)
            .expect("mult1 Round-2 should succeed");
        mult1_r3_msgs.push(r3);
        mult1_r2_results.push(r2_res);
    }

    // Mult2: handle R1 -> produce R2
    let mut mult2_r2_msgs: Vec<MultRound2Msg<C>> = Vec::with_capacity(n);
    let mut mult2_r1_results: Vec<MultRound1Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult2_r1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r2, r1_res) = mult2_states[i]
            .handle_round1(&others, &mult2_r1_msgs[i], rng)
            .expect("mult2 Round-1 should succeed");
        mult2_r2_msgs.push(r2);
        mult2_r1_results.push(r1_res);
    }

    // ---------------------------------------------------------------
    // Round 6: Mult1.R4 || Mult2.R3
    // ---------------------------------------------------------------
    // Mult1: handle R3 -> produce R4
    let mut mult1_r4_msgs: Vec<MultRound4Msg<C>> = Vec::with_capacity(n);
    let mut mult1_r3_results: Vec<MultRound3Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult1_r3_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r4, r3_res) = mult1_states[i]
            .handle_round3(&others, &mult1_r3_msgs[i], &mult1_r2_results[i], rng)
            .expect("mult1 Round-3 should succeed");
        mult1_r4_msgs.push(r4);
        mult1_r3_results.push(r3_res);
    }

    // Mult2: handle R2 -> produce R3
    let mut mult2_r3_msgs: Vec<MultRound3Msg<C>> = Vec::with_capacity(n);
    let mut mult2_r2_results: Vec<MultRound2Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult2_r2_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r3, r2_res) = mult2_states[i]
            .handle_round2(&others, &mult2_r1_results[i], rng)
            .expect("mult2 Round-2 should succeed");
        mult2_r3_msgs.push(r3);
        mult2_r2_results.push(r2_res);
    }

    // ---------------------------------------------------------------
    // Round 7: Mult1.R5 || Mult2.R4
    // ---------------------------------------------------------------
    // Mult1: handle R4 -> produce R5
    let mut mult1_r5_msgs: Vec<MultRound5Msg<C>> = Vec::with_capacity(n);
    let mut mult1_r4_results: Vec<MultRound4Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult1_r4_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r5, r4_res) = mult1_states[i]
            .handle_round4(&others, &mult1_r2_results[i], &mult1_r3_results[i], rng)
            .expect("mult1 Round-4 should succeed");
        mult1_r5_msgs.push(r5);
        mult1_r4_results.push(r4_res);
    }

    // Mult2: handle R3 -> produce R4
    let mut mult2_r4_msgs: Vec<MultRound4Msg<C>> = Vec::with_capacity(n);
    let mut mult2_r3_results: Vec<MultRound3Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult2_r3_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r4, r3_res) = mult2_states[i]
            .handle_round3(&others, &mult2_r3_msgs[i], &mult2_r2_results[i], rng)
            .expect("mult2 Round-3 should succeed");
        mult2_r4_msgs.push(r4);
        mult2_r3_results.push(r3_res);
    }

    // ---------------------------------------------------------------
    // Round 8: Mult1.R6 || Mult2.R5
    // ---------------------------------------------------------------
    // Mult1: finish_round5 (R6 = verify c_i proofs, output)
    let mut tau_outputs: Vec<MultOutput<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult1_r5_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let output = mult1_states[i]
            .finish_round5(&others, &mult1_r4_results[i])
            .expect("mult1 Round-5 should succeed");
        tau_outputs.push(output);
    }

    // Mult2: handle R4 -> produce R5
    let mut mult2_r5_msgs: Vec<MultRound5Msg<C>> = Vec::with_capacity(n);
    let mut mult2_r4_results: Vec<MultRound4Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult2_r4_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r5, r4_res) = mult2_states[i]
            .handle_round4(&others, &mult2_r2_results[i], &mult2_r3_results[i], rng)
            .expect("mult2 Round-4 should succeed");
        mult2_r5_msgs.push(r5);
        mult2_r4_results.push(r4_res);
    }

    // ---------------------------------------------------------------
    // After Round 8: Mult2.R6 (local verify), compute s
    // ---------------------------------------------------------------
    let mut beta_outputs: Vec<MultOutput<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = mult2_r5_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let output = mult2_states[i]
            .finish_round5(&others, &mult2_r4_results[i])
            .expect("mult2 Round-5 should succeed");
        beta_outputs.push(output);
    }

    // Compute s = tau^{-1} * beta, normalize to low-S
    let tau: C::Scalar = tau_outputs
        .iter()
        .map(|o| o.c_i)
        .reduce(|acc, x| acc + x)
        .expect("at least one party");
    let beta: C::Scalar = beta_outputs
        .iter()
        .map(|o| o.c_i)
        .reduce(|acc, x| acc + x)
        .expect("at least one party");

    let tau_inv = tau
        .invert()
        .into_option()
        .expect("tau (k*rho) must be invertible");
    let s_raw = tau_inv * beta;
    let s = low_s_normalize::<C>(s_raw);

    (0..n).map(|_| Signature { r, s }).collect()
}

// ===========================================================================
// Legacy combined function (delegates to presign + online sign)
// ===========================================================================

/// Run the full LN18 signing protocol for all parties in parallel (simulation).
///
/// This is a convenience wrapper that calls [`ln18_presign_parallel`] followed
/// by [`ln18_online_sign_parallel`].
pub fn ln18_sign_parallel<C: TecdsaCurve>(
    params: &[Ln18PresignParams<C>],
    parties: &[PartyId],
    message_digest: &C::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Vec<Signature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]> + GroupEncoding,
{
    let presigs = ln18_presign_parallel(params, parties, rng);

    let online_params: Vec<Ln18OnlineSignParams<C>> = params
        .iter()
        .zip(presigs)
        .map(|(p, presig)| Ln18OnlineSignParams {
            paillier_dk: p.paillier_dk.clone(),
            paillier_eks: p.paillier_eks.clone(),
            ntilde_params: p.ntilde_params.clone(),
            presignature: presig,
        })
        .collect();

    ln18_online_sign_parallel(&online_params, parties, message_digest, rng)
}

// ---------------------------------------------------------------------------
// Helper: run the input sub-protocol (2 rounds: commit, decommit+verify)
// for n parties. Retained for use by online sign and tests.
// ---------------------------------------------------------------------------
#[allow(dead_code)]
fn run_input_phase<C: TecdsaCurve>(
    parties: &[PartyId],
    elgamal_pk: C::ProjectivePoint,
    shares: &[C::Scalar],
    rng: &mut impl CryptoRngCore,
) -> Vec<InputOutput<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let n = parties.len();

    // Round 1: commitments
    let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
    let mut input_r1_msgs: Vec<InputRound1Msg> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) =
            InputState::<C>::new(parties[i], parties.to_vec(), elgamal_pk, shares[i], rng);
        input_states.push(state);
        input_r1_msgs.push(msg);
    }

    // Round 2: decommitments
    let mut input_r2_msgs: Vec<InputRound2Msg<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = input_r1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let r2 = input_states[i]
            .handle_round1(&others)
            .expect("input Round-1 should succeed");
        input_r2_msgs.push(r2);
    }

    // Finish: verify decommitments and proofs
    let mut outputs = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = input_r2_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let output = input_states[i]
            .finish_round2(&others)
            .expect("input Round-2 should succeed");
        outputs.push(output);
    }
    outputs
}

// ---------------------------------------------------------------------------
// Helper: run TWO input sub-protocols in parallel (2 shared rounds)
//
// Instead of running input(k) and input(rho) sequentially (4 rounds), both
// inputs share the same 2 commitment/decommitment rounds (2 rounds total).
// ---------------------------------------------------------------------------
fn run_parallel_input_phases<C: TecdsaCurve>(
    parties: &[PartyId],
    elgamal_pk: C::ProjectivePoint,
    shares_a: &[C::Scalar],
    shares_b: &[C::Scalar],
    rng: &mut impl CryptoRngCore,
) -> (Vec<InputOutput<C>>, Vec<InputOutput<C>>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let n = parties.len();

    // Round 1: all parties send commitments for BOTH inputs simultaneously
    let mut states_a: Vec<InputState<C>> = Vec::with_capacity(n);
    let mut r1_msgs_a: Vec<InputRound1Msg> = Vec::with_capacity(n);
    let mut states_b: Vec<InputState<C>> = Vec::with_capacity(n);
    let mut r1_msgs_b: Vec<InputRound1Msg> = Vec::with_capacity(n);
    for i in 0..n {
        let (sa, ma) =
            InputState::<C>::new(parties[i], parties.to_vec(), elgamal_pk, shares_a[i], rng);
        states_a.push(sa);
        r1_msgs_a.push(ma);

        let (sb, mb) =
            InputState::<C>::new(parties[i], parties.to_vec(), elgamal_pk, shares_b[i], rng);
        states_b.push(sb);
        r1_msgs_b.push(mb);
    }

    // Round 2: all parties process Round-1 messages and send decommitments
    // for BOTH inputs simultaneously
    let mut r2_msgs_a: Vec<InputRound2Msg<C>> = Vec::with_capacity(n);
    let mut r2_msgs_b: Vec<InputRound2Msg<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others_a: Vec<_> = r1_msgs_a
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let r2a = states_a[i]
            .handle_round1(&others_a)
            .expect("input(a) Round-1 should succeed");
        r2_msgs_a.push(r2a);

        let others_b: Vec<_> = r1_msgs_b
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let r2b = states_b[i]
            .handle_round1(&others_b)
            .expect("input(b) Round-1 should succeed");
        r2_msgs_b.push(r2b);
    }

    // Finish: verify decommitments and proofs for both inputs
    let mut outputs_a = Vec::with_capacity(n);
    let mut outputs_b = Vec::with_capacity(n);
    for i in 0..n {
        let others_a: Vec<_> = r2_msgs_a
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let oa = states_a[i]
            .finish_round2(&others_a)
            .expect("input(a) Round-2 should succeed");
        outputs_a.push(oa);

        let others_b: Vec<_> = r2_msgs_b
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let ob = states_b[i]
            .finish_round2(&others_b)
            .expect("input(b) Round-2 should succeed");
        outputs_b.push(ob);
    }

    (outputs_a, outputs_b)
}

// ---------------------------------------------------------------------------
// Helper: continue the mult sub-protocol from Round 2 onwards (5 remaining
// rounds), given already-created MultStates and Round-1 messages.
//
// This is used when mult's Round 1 was already sent in a shared round
// (parallel with element-out), and we just need to process the Round-1
// messages and run Rounds 2-6.
// ---------------------------------------------------------------------------
fn continue_mult_phase<C: TecdsaCurve>(
    mult_states: &mut [MultState<C>],
    r1_msgs: &[MultRound1Msg<C>],
    rng: &mut impl CryptoRngCore,
) -> Vec<MultOutput<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let n = mult_states.len();

    // Round 2 (= protocol Round 4): process R1, send (A_i, B_i) + R_EG
    let mut r2_msgs: Vec<MultRound2Msg<C>> = Vec::with_capacity(n);
    let mut r1_results: Vec<MultRound1Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r2, r1_res) = mult_states[i]
            .handle_round1(&others, &r1_msgs[i], rng)
            .expect("mult Round-1 should succeed");
        r2_msgs.push(r2);
        r1_results.push(r1_res);
    }

    // Round 3 (= protocol Round 5): checkDH Round 1
    let mut r3_msgs: Vec<MultRound3Msg<C>> = Vec::with_capacity(n);
    let mut r2_results: Vec<MultRound2Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r2_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r3, r2_res) = mult_states[i]
            .handle_round2(&others, &r1_results[i], rng)
            .expect("mult Round-2 should succeed");
        r3_msgs.push(r3);
        r2_results.push(r2_res);
    }

    // Round 4 (= protocol Round 6): checkDH Round 2
    let mut r4_msgs: Vec<MultRound4Msg<C>> = Vec::with_capacity(n);
    let mut r3_results: Vec<MultRound3Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r3_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r4, r3_res) = mult_states[i]
            .handle_round3(&others, &r3_msgs[i], &r2_results[i], rng)
            .expect("mult Round-3 should succeed");
        r4_msgs.push(r4);
        r3_results.push(r3_res);
    }

    // Round 5 (= protocol Round 7): checkDH verify + send c_i
    let mut r5_msgs: Vec<MultRound5Msg<C>> = Vec::with_capacity(n);
    let mut r4_results: Vec<MultRound4Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r4_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r5, r4_res) = mult_states[i]
            .handle_round4(&others, &r2_results[i], &r3_results[i], rng)
            .expect("mult Round-4 should succeed");
        r5_msgs.push(r5);
        r4_results.push(r4_res);
    }

    // Round 6 (= protocol Round 8): verify c_i proofs, output
    let mut outputs: Vec<MultOutput<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r5_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let output = mult_states[i]
            .finish_round5(&others, &r4_results[i])
            .expect("mult Round-5 should succeed");
        outputs.push(output);
    }

    outputs
}

// ---------------------------------------------------------------------------
// Helper: run Paillier MtA for n parties
// ---------------------------------------------------------------------------
fn run_paillier_mta<C: TecdsaCurve>(
    parties: &[PartyId],
    a_shares: &[C::Scalar],
    b_shares: &[C::Scalar],
    params: &[Ln18PresignParams<C>],
    rng: &mut impl CryptoRngCore,
) -> Vec<C::Scalar>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    let n = parties.len();

    // Round 1
    let mut states: Vec<PaillierMtaState<C>> = Vec::with_capacity(n);
    let mut all_r1_msgs: Vec<Vec<(PartyId, MtaRound1Msg)>> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, r1_msgs) = PaillierMtaState::<C>::new(
            parties[i],
            parties.to_vec(),
            params[i].paillier_dk.clone(),
            params[i].paillier_eks.clone(),
            params[i].ntilde_params.clone(),
            a_shares[i],
            b_shares[i],
            rng,
        );
        states.push(state);
        all_r1_msgs.push(r1_msgs);
    }

    // Round 2
    let mut all_r2_msgs: Vec<Vec<(PartyId, MtaRound2Msg<C>)>> = Vec::with_capacity(n);
    for i in 0..n {
        let mut msgs_for_i: Vec<MtaRound1Msg> = Vec::new();
        for j in 0..n {
            if i == j {
                continue;
            }
            for (dest, msg) in &all_r1_msgs[j] {
                if *dest == parties[i] {
                    msgs_for_i.push(msg.clone());
                }
            }
        }
        let r2_msgs = states[i]
            .handle_round1(&msgs_for_i, rng)
            .expect("MtA Round-1 should succeed");
        all_r2_msgs.push(r2_msgs);
    }

    // Finish
    let mut c_shares = Vec::with_capacity(n);
    for i in 0..n {
        let mut msgs_for_i: Vec<MtaRound2Msg<C>> = Vec::new();
        for j in 0..n {
            if i == j {
                continue;
            }
            for (dest, msg) in &all_r2_msgs[j] {
                if *dest == parties[i] {
                    msgs_for_i.push(msg.clone());
                }
            }
        }
        let c_i = states[i]
            .finish(&msgs_for_i)
            .expect("MtA finish should succeed");
        c_shares.push(c_i);
    }

    c_shares
}

// ---------------------------------------------------------------------------
// Helper: run the mult sub-protocol (6 rounds with checkDH) for n parties
// ---------------------------------------------------------------------------
fn run_mult_phase<C: TecdsaCurve>(
    parties: &[PartyId],
    input_a: &[InputOutput<C>],
    input_b: &[InputOutput<C>],
    mta_c_shares: &[C::Scalar],
    elgamal_pk: C::ProjectivePoint,
    d_shares: &[C::Scalar],
    pk_shares: &[C::ProjectivePoint],
    rng: &mut impl CryptoRngCore,
) -> Vec<MultOutput<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let n = parties.len();

    // Round 1
    let mut mult_states: Vec<MultState<C>> = Vec::with_capacity(n);
    let mut r1_msgs: Vec<MultRound1Msg<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) = MultState::<C>::new(
            parties[i],
            parties.to_vec(),
            &input_a[i],
            &input_b[i],
            mta_c_shares[i],
            elgamal_pk,
            d_shares[i],
            pk_shares.to_vec(),
            rng,
        );
        mult_states.push(state);
        r1_msgs.push(msg);
    }

    // Round 2
    let mut r2_msgs: Vec<MultRound2Msg<C>> = Vec::with_capacity(n);
    let mut r1_results: Vec<MultRound1Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r2, r1_res) = mult_states[i]
            .handle_round1(&others, &r1_msgs[i], rng)
            .expect("mult Round-1 should succeed");
        r2_msgs.push(r2);
        r1_results.push(r1_res);
    }

    // Round 3 (checkDH Round 1)
    let mut r3_msgs: Vec<MultRound3Msg<C>> = Vec::with_capacity(n);
    let mut r2_results: Vec<MultRound2Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r2_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r3, r2_res) = mult_states[i]
            .handle_round2(&others, &r1_results[i], rng)
            .expect("mult Round-2 should succeed");
        r3_msgs.push(r3);
        r2_results.push(r2_res);
    }

    // Round 4 (checkDH Round 2)
    let mut r4_msgs: Vec<MultRound4Msg<C>> = Vec::with_capacity(n);
    let mut r3_results: Vec<MultRound3Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r3_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r4, r3_res) = mult_states[i]
            .handle_round3(&others, &r3_msgs[i], &r2_results[i], rng)
            .expect("mult Round-3 should succeed");
        r4_msgs.push(r4);
        r3_results.push(r3_res);
    }

    // Round 5 (checkDH verify + send c_i)
    let mut r5_msgs: Vec<MultRound5Msg<C>> = Vec::with_capacity(n);
    let mut r4_results: Vec<MultRound4Result<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r4_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let (r5, r4_res) = mult_states[i]
            .handle_round4(&others, &r2_results[i], &r3_results[i], rng)
            .expect("mult Round-4 should succeed");
        r5_msgs.push(r5);
        r4_results.push(r4_res);
    }

    // Round 6 (verify c_i proofs, output)
    let mut outputs: Vec<MultOutput<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r5_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let output = mult_states[i]
            .finish_round5(&others, &r4_results[i])
            .expect("mult Round-5 should succeed");
        outputs.push(output);
    }

    outputs
}

// ===========================================================================
// OT-based sign variant (behind mta-ot feature)
// ===========================================================================

#[cfg(feature = "mta-ot")]
mod ot_sign {
    use elliptic_curve::ops::Reduce;

    use super::*;
    use crate::mta::ot::{OtMtaInitMsg, OtMtaRound1Msg, OtMtaRound2Msg, OtMtaState};

    /// Parameters needed to run the LN18 presign protocol with OT MtA.
    pub struct Ln18OtPresignParams<C: TecdsaCurve>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        /// This party's key share from keygen.
        pub key_share: Ln18KeyShare<C>,
        /// The init output from keygen (ElGamal key material).
        pub init_output: InitOutput<C>,
        /// Stored x input state from KeyGen's input call (identifier 0).
        pub stored_x_input: InputOutput<C>,
    }

    /// Legacy alias for backward compatibility.
    pub type Ln18OtSignParams<C> = Ln18OtPresignParams<C>;

    /// Run the LN18 presign (offline) protocol with OT-based MtA for all parties
    /// in parallel (simulation).
    ///
    /// Achieves 8 rounds by parallelizing sub-protocols per Section 5.2.1:
    /// - Rounds 1-2: Input(k) || Input(rho)
    /// - Round 3: Element-out(k) || Mult(k,rho).R1
    /// - Rounds 4-8: Mult(k,rho).R2-R6
    pub fn ln18_presign_parallel_ot<C: TecdsaCurve>(
        params: &[Ln18OtPresignParams<C>],
        parties: &[PartyId],
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Ln18Presignature<C>>
    where
        FieldBytesSize<C>: ModulusSize,
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
        C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    {
        let n = parties.len();
        assert_eq!(params.len(), n, "must have one param set per party");

        let elgamal_pk = params[0].init_output.elgamal_pk;
        let pk_shares = &params[0].init_output.elgamal_pk_shares;

        // Rounds 1-2: Input(k) || Input(rho) — parallel inputs in 2 shared rounds
        let k_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();
        let rho_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();

        let (input_k_outputs, input_rho_outputs) =
            run_parallel_input_phases::<C>(parties, elgamal_pk, &k_shares, &rho_shares, rng);

        // MtA (Step 0, no interaction rounds — runs before Round 3)
        let tau_mta_shares = run_ot_mta_helper::<C>(parties, &k_shares, &rho_shares, rng);

        // Round 3: Element-out(k) || Mult(k,rho).R1 — both start simultaneously
        let mut eo_states: Vec<ElementOutState<C>> = Vec::with_capacity(n);
        let mut eo_msgs: Vec<ElementOutMsg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = ElementOutState::<C>::new(
                parties[i],
                parties.to_vec(),
                input_k_outputs[i].a_i,
                input_k_outputs[i].s_i,
                input_k_outputs[i].per_party_cts.clone(),
                elgamal_pk,
                rng,
            );
            eo_states.push(state);
            eo_msgs.push(msg);
        }

        // Create mult states + Round-1 messages simultaneously
        let d_shares: Vec<C::Scalar> = params.iter().map(|p| p.init_output.d_i).collect();
        let mut mult_states: Vec<MultState<C>> = Vec::with_capacity(n);
        let mut mult_r1_msgs: Vec<MultRound1Msg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = MultState::<C>::new(
                parties[i],
                parties.to_vec(),
                &input_k_outputs[i],
                &input_rho_outputs[i],
                tau_mta_shares[i],
                elgamal_pk,
                d_shares[i],
                pk_shares.to_vec(),
                rng,
            );
            mult_states.push(state);
            mult_r1_msgs.push(msg);
        }

        // After Round 3: element-out finishes
        let mut R_point = None;
        for i in 0..n {
            let others: Vec<_> = eo_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let eo_output = eo_states[i]
                .finish(&others)
                .expect("element-out should succeed");
            if R_point.is_none() {
                R_point = Some(eo_output.element);
            }
        }
        let R = R_point.expect("must have at least one party");

        let r: C::Scalar = C::xcoord_mod_q(&R.to_affine());
        if r.is_zero().into() {
            // Probability 1/q (< 2^{-256}): mathematically negligible.
            panic!("r is zero -- probability < 2^{{-256}}");
        }

        // Rounds 4-8: Mult(k,rho).R2-R6
        let tau_mult_outputs = continue_mult_phase::<C>(&mut mult_states, &mult_r1_msgs, rng);

        // Build presignatures
        let mut presigs = Vec::with_capacity(n);
        for i in 0..n {
            presigs.push(Ln18Presignature {
                R,
                r,
                tau_i: tau_mult_outputs[i].c_i,
                stored_rho_input: input_rho_outputs[i].clone(),
                stored_x_input: params[i].stored_x_input.clone(),
                elgamal_dk: params[i].init_output.d_i,
                elgamal_pk,
                elgamal_pk_shares: pk_shares.clone(),
            });
        }
        presigs
    }

    /// Parameters for the OT online signing phase.
    pub struct Ln18OtOnlineSignParams<C: TecdsaCurve>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        /// This party's presignature from the offline phase.
        pub presignature: Ln18Presignature<C>,
    }

    /// Run the LN18 online signing protocol with OT-based MtA for all parties
    /// in parallel (simulation).
    pub fn ln18_online_sign_parallel_ot<C: TecdsaCurve>(
        online_params: &[Ln18OtOnlineSignParams<C>],
        parties: &[PartyId],
        message_digest: &C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Signature<C>>
    where
        FieldBytesSize<C>: ModulusSize,
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
        C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    {
        let n = parties.len();
        assert_eq!(online_params.len(), n, "must have one param set per party");

        let r = online_params[0].presignature.r;
        let elgamal_pk = online_params[0].presignature.elgamal_pk;
        let pk_shares = &online_params[0].presignature.elgamal_pk_shares;

        // Step 4: Affine
        let m_prime = *message_digest;
        let mut affine_outputs: Vec<AffineOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let stored_x = &online_params[i].presignature.stored_x_input;
            let aff_input = AffineInput::<C> {
                ciphertext: stored_x.ciphertext.clone(),
                a_i: stored_x.a_i,
                s_i: stored_x.s_i,
                per_party_cts: stored_x.per_party_cts.clone(),
            };
            let output = affine::<C>(aff_input, &r, &m_prime, n as u16);
            affine_outputs.push(output);
        }

        let alpha_as_input: Vec<InputOutput<C>> = affine_outputs
            .into_iter()
            .map(|ao| InputOutput {
                ciphertext: ao.ciphertext,
                a_i: ao.a_i,
                s_i: ao.s_i,
                per_party_cts: ao.per_party_cts,
            })
            .collect();

        // Step 5: Mult(rho, alpha) -> beta shares (using OT MtA)
        let rho_shares: Vec<C::Scalar> = online_params
            .iter()
            .map(|p| p.presignature.stored_rho_input.a_i)
            .collect();
        let alpha_shares: Vec<C::Scalar> = alpha_as_input.iter().map(|io| io.a_i).collect();

        let beta_mta_shares = run_ot_mta_helper::<C>(parties, &rho_shares, &alpha_shares, rng);

        let d_shares: Vec<C::Scalar> = online_params
            .iter()
            .map(|p| p.presignature.elgamal_dk)
            .collect();
        let input_rho_outputs: Vec<InputOutput<C>> = online_params
            .iter()
            .map(|p| p.presignature.stored_rho_input.clone())
            .collect();
        let beta_mult_outputs = run_mult_phase::<C>(
            parties,
            &input_rho_outputs,
            &alpha_as_input,
            &beta_mta_shares,
            elgamal_pk,
            &d_shares,
            pk_shares,
            rng,
        );

        // Step 6: Compute s = tau^{-1} * beta
        let tau: C::Scalar = online_params
            .iter()
            .map(|p| p.presignature.tau_i)
            .reduce(|acc, x| acc + x)
            .expect("at least one party");
        let beta: C::Scalar = beta_mult_outputs
            .iter()
            .map(|o| o.c_i)
            .reduce(|acc, x| acc + x)
            .expect("at least one party");

        let tau_inv = tau
            .invert()
            .into_option()
            .expect("tau (k*rho) must be invertible");
        let s_raw = tau_inv * beta;
        let s = low_s_normalize::<C>(s_raw);

        (0..n).map(|_| Signature { r, s }).collect()
    }

    /// Legacy combined function: presign + online sign with OT MtA.
    pub fn ln18_sign_parallel_ot<C: TecdsaCurve>(
        params: &[Ln18OtPresignParams<C>],
        parties: &[PartyId],
        message_digest: &C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Signature<C>>
    where
        FieldBytesSize<C>: ModulusSize,
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
        C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    {
        let presigs = ln18_presign_parallel_ot(params, parties, rng);

        let online_params: Vec<Ln18OtOnlineSignParams<C>> = presigs
            .into_iter()
            .map(|presig| Ln18OtOnlineSignParams {
                presignature: presig,
            })
            .collect();

        ln18_online_sign_parallel_ot(&online_params, parties, message_digest, rng)
    }

    /// Run the LN18 full-sign protocol in 8 rounds with interleaved mult1/mult2
    /// using OT-based MtA.
    ///
    /// Same structure as [`ln18_full_sign_parallel`](super::ln18_full_sign_parallel)
    /// but uses OT MtA instead of Paillier MtA.
    pub fn ln18_full_sign_parallel_ot<C: TecdsaCurve>(
        params: &[Ln18OtPresignParams<C>],
        parties: &[PartyId],
        message_digest: &C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Signature<C>>
    where
        FieldBytesSize<C>: ModulusSize,
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
        C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    {
        let n = parties.len();
        assert_eq!(params.len(), n, "must have one param set per party");

        let elgamal_pk = params[0].init_output.elgamal_pk;
        let pk_shares = &params[0].init_output.elgamal_pk_shares;

        // Rounds 1-2: Input(k) || Input(rho)
        let k_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();
        let rho_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();

        let (input_k_outputs, input_rho_outputs) =
            run_parallel_input_phases::<C>(parties, elgamal_pk, &k_shares, &rho_shares, rng);

        // MtA_1 (OT): k*rho
        let tau_mta_shares = run_ot_mta_helper::<C>(parties, &k_shares, &rho_shares, rng);

        // Round 3: Element-out(k) || Mult1(k,rho).R1
        let mut eo_states: Vec<ElementOutState<C>> = Vec::with_capacity(n);
        let mut eo_msgs: Vec<ElementOutMsg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = ElementOutState::<C>::new(
                parties[i],
                parties.to_vec(),
                input_k_outputs[i].a_i,
                input_k_outputs[i].s_i,
                input_k_outputs[i].per_party_cts.clone(),
                elgamal_pk,
                rng,
            );
            eo_states.push(state);
            eo_msgs.push(msg);
        }

        let d_shares: Vec<C::Scalar> = params.iter().map(|p| p.init_output.d_i).collect();
        let mut mult1_states: Vec<MultState<C>> = Vec::with_capacity(n);
        let mut mult1_r1_msgs: Vec<MultRound1Msg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = MultState::<C>::new(
                parties[i],
                parties.to_vec(),
                &input_k_outputs[i],
                &input_rho_outputs[i],
                tau_mta_shares[i],
                elgamal_pk,
                d_shares[i],
                pk_shares.to_vec(),
                rng,
            );
            mult1_states.push(state);
            mult1_r1_msgs.push(msg);
        }

        // After Round 3: element-out finishes, extract R
        let mut R_point = None;
        for i in 0..n {
            let others: Vec<_> = eo_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let eo_output = eo_states[i]
                .finish(&others)
                .expect("element-out should succeed");
            if R_point.is_none() {
                R_point = Some(eo_output.element);
            }
        }
        let R = R_point.expect("must have at least one party");

        let r: C::Scalar = C::xcoord_mod_q(&R.to_affine());
        if r.is_zero().into() {
            // Probability 1/q (< 2^{-256}): mathematically negligible.
            panic!("r is zero -- probability < 2^{{-256}}");
        }

        // Affine: compute alpha = m' + x*r (local)
        let m_prime = *message_digest;
        let mut alpha_as_input: Vec<InputOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let stored_x = &params[i].stored_x_input;
            let aff_input = AffineInput::<C> {
                ciphertext: stored_x.ciphertext.clone(),
                a_i: stored_x.a_i,
                s_i: stored_x.s_i,
                per_party_cts: stored_x.per_party_cts.clone(),
            };
            let output = affine::<C>(aff_input, &r, &m_prime, n as u16);
            alpha_as_input.push(InputOutput {
                ciphertext: output.ciphertext,
                a_i: output.a_i,
                s_i: output.s_i,
                per_party_cts: output.per_party_cts,
            });
        }

        // MtA_2 (OT): rho*alpha
        let alpha_shares: Vec<C::Scalar> = alpha_as_input.iter().map(|io| io.a_i).collect();
        let beta_mta_shares = run_ot_mta_helper::<C>(parties, &rho_shares, &alpha_shares, rng);

        // Create mult2 states
        let mut mult2_states: Vec<MultState<C>> = Vec::with_capacity(n);
        let mut mult2_r1_msgs: Vec<MultRound1Msg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = MultState::<C>::new(
                parties[i],
                parties.to_vec(),
                &input_rho_outputs[i],
                &alpha_as_input[i],
                beta_mta_shares[i],
                elgamal_pk,
                d_shares[i],
                pk_shares.to_vec(),
                rng,
            );
            mult2_states.push(state);
            mult2_r1_msgs.push(msg);
        }

        // Round 4: Mult1.R2 || Mult2.R1
        let mut mult1_r2_msgs: Vec<MultRound2Msg<C>> = Vec::with_capacity(n);
        let mut mult1_r1_results: Vec<MultRound1Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult1_r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r2, r1_res) = mult1_states[i]
                .handle_round1(&others, &mult1_r1_msgs[i], rng)
                .expect("mult1 Round-1 should succeed");
            mult1_r2_msgs.push(r2);
            mult1_r1_results.push(r1_res);
        }

        // Round 5: Mult1.R3 || Mult2.R2
        let mut mult1_r3_msgs: Vec<MultRound3Msg<C>> = Vec::with_capacity(n);
        let mut mult1_r2_results: Vec<MultRound2Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult1_r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r3, r2_res) = mult1_states[i]
                .handle_round2(&others, &mult1_r1_results[i], rng)
                .expect("mult1 Round-2 should succeed");
            mult1_r3_msgs.push(r3);
            mult1_r2_results.push(r2_res);
        }
        let mut mult2_r2_msgs: Vec<MultRound2Msg<C>> = Vec::with_capacity(n);
        let mut mult2_r1_results: Vec<MultRound1Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult2_r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r2, r1_res) = mult2_states[i]
                .handle_round1(&others, &mult2_r1_msgs[i], rng)
                .expect("mult2 Round-1 should succeed");
            mult2_r2_msgs.push(r2);
            mult2_r1_results.push(r1_res);
        }

        // Round 6: Mult1.R4 || Mult2.R3
        let mut mult1_r4_msgs: Vec<MultRound4Msg<C>> = Vec::with_capacity(n);
        let mut mult1_r3_results: Vec<MultRound3Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult1_r3_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r4, r3_res) = mult1_states[i]
                .handle_round3(&others, &mult1_r3_msgs[i], &mult1_r2_results[i], rng)
                .expect("mult1 Round-3 should succeed");
            mult1_r4_msgs.push(r4);
            mult1_r3_results.push(r3_res);
        }
        let mut mult2_r3_msgs: Vec<MultRound3Msg<C>> = Vec::with_capacity(n);
        let mut mult2_r2_results: Vec<MultRound2Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult2_r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r3, r2_res) = mult2_states[i]
                .handle_round2(&others, &mult2_r1_results[i], rng)
                .expect("mult2 Round-2 should succeed");
            mult2_r3_msgs.push(r3);
            mult2_r2_results.push(r2_res);
        }

        // Round 7: Mult1.R5 || Mult2.R4
        let mut mult1_r5_msgs: Vec<MultRound5Msg<C>> = Vec::with_capacity(n);
        let mut mult1_r4_results: Vec<MultRound4Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult1_r4_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r5, r4_res) = mult1_states[i]
                .handle_round4(&others, &mult1_r2_results[i], &mult1_r3_results[i], rng)
                .expect("mult1 Round-4 should succeed");
            mult1_r5_msgs.push(r5);
            mult1_r4_results.push(r4_res);
        }
        let mut mult2_r4_msgs: Vec<MultRound4Msg<C>> = Vec::with_capacity(n);
        let mut mult2_r3_results: Vec<MultRound3Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult2_r3_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r4, r3_res) = mult2_states[i]
                .handle_round3(&others, &mult2_r3_msgs[i], &mult2_r2_results[i], rng)
                .expect("mult2 Round-3 should succeed");
            mult2_r4_msgs.push(r4);
            mult2_r3_results.push(r3_res);
        }

        // Round 8: Mult1.R6 || Mult2.R5
        let mut tau_outputs: Vec<MultOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult1_r5_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = mult1_states[i]
                .finish_round5(&others, &mult1_r4_results[i])
                .expect("mult1 Round-5 should succeed");
            tau_outputs.push(output);
        }
        let mut mult2_r5_msgs: Vec<MultRound5Msg<C>> = Vec::with_capacity(n);
        let mut mult2_r4_results: Vec<MultRound4Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult2_r4_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r5, r4_res) = mult2_states[i]
                .handle_round4(&others, &mult2_r2_results[i], &mult2_r3_results[i], rng)
                .expect("mult2 Round-4 should succeed");
            mult2_r5_msgs.push(r5);
            mult2_r4_results.push(r4_res);
        }

        // After Round 8: Mult2.R6 (local verify)
        let mut beta_outputs: Vec<MultOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = mult2_r5_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = mult2_states[i]
                .finish_round5(&others, &mult2_r4_results[i])
                .expect("mult2 Round-5 should succeed");
            beta_outputs.push(output);
        }

        // Compute s = tau^{-1} * beta
        let tau: C::Scalar = tau_outputs
            .iter()
            .map(|o| o.c_i)
            .reduce(|acc, x| acc + x)
            .expect("at least one party");
        let beta: C::Scalar = beta_outputs
            .iter()
            .map(|o| o.c_i)
            .reduce(|acc, x| acc + x)
            .expect("at least one party");

        let tau_inv = tau
            .invert()
            .into_option()
            .expect("tau (k*rho) must be invertible");
        let s_raw = tau_inv * beta;
        let s = low_s_normalize::<C>(s_raw);

        (0..n).map(|_| Signature { r, s }).collect()
    }

    /// Run OT MtA for `n` parties and return $c_i$ shares.
    fn run_ot_mta_helper<C: TecdsaCurve>(
        parties: &[PartyId],
        a_shares: &[C::Scalar],
        b_shares: &[C::Scalar],
        rng: &mut impl CryptoRngCore,
    ) -> Vec<C::Scalar>
    where
        FieldBytesSize<C>: ModulusSize,
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        let n = parties.len();

        // Init
        let mut states: Vec<OtMtaState<C>> = Vec::with_capacity(n);
        let mut all_init_msgs: Vec<Vec<(PartyId, OtMtaInitMsg)>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, init_msgs) =
                OtMtaState::<C>::new(parties[i], parties.to_vec(), a_shares[i], b_shares[i], rng);
            states.push(state);
            all_init_msgs.push(init_msgs);
        }

        // Deliver init messages
        for i in 0..n {
            let mut msgs_for_i: Vec<OtMtaInitMsg> = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                for (dest, msg) in &all_init_msgs[j] {
                    if *dest == parties[i] {
                        msgs_for_i.push(msg.clone());
                    }
                }
            }
            states[i]
                .handle_init(&msgs_for_i)
                .expect("OT MtA init should succeed");
        }

        // Round 1: receiver phase 1
        let mut all_r1_msgs: Vec<Vec<(PartyId, OtMtaRound1Msg)>> = Vec::with_capacity(n);
        for i in 0..n {
            let r1_msgs = states[i]
                .run_receiver_phase1(rng)
                .expect("OT MtA receiver phase1 should succeed");
            all_r1_msgs.push(r1_msgs);
        }

        // Round 2: sender processes, responds
        let mut all_r2_msgs: Vec<Vec<(PartyId, OtMtaRound2Msg)>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut msgs_for_i: Vec<OtMtaRound1Msg> = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                for (dest, msg) in &all_r1_msgs[j] {
                    if *dest == parties[i] {
                        msgs_for_i.push(msg.clone());
                    }
                }
            }
            let r2_msgs = states[i]
                .handle_round1(&msgs_for_i, rng)
                .expect("OT MtA Round-1 should succeed");
            all_r2_msgs.push(r2_msgs);
        }

        // Finish
        let mut c_shares = Vec::with_capacity(n);
        for i in 0..n {
            let mut msgs_for_i: Vec<OtMtaRound2Msg> = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                for (dest, msg) in &all_r2_msgs[j] {
                    if *dest == parties[i] {
                        msgs_for_i.push(msg.clone());
                    }
                }
            }
            let c_i = states[i]
                .finish(&msgs_for_i)
                .expect("OT MtA finish should succeed");
            c_shares.push(c_i);
        }

        c_shares
    }
}

#[cfg(feature = "mta-ot")]
pub use ot_sign::{
    ln18_full_sign_parallel_ot, ln18_online_sign_parallel_ot, ln18_presign_parallel_ot,
    ln18_sign_parallel_ot, Ln18OtOnlineSignParams, Ln18OtPresignParams, Ln18OtSignParams,
};
