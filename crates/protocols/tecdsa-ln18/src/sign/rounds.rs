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

#[derive(Clone)]
pub struct Ln18PresignParams<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub key_share: Ln18KeyShare<C>,
    pub paillier_dk: DecryptionKey,
    pub paillier_eks: BTreeMap<PartyId, EncryptionKey>,
    pub ntilde_params: BTreeMap<PartyId, NTildeParams>,
    pub init_output: InitOutput<C>,
    pub stored_x_input: InputOutput<C>,
}

pub type Ln18SignParams<C> = Ln18PresignParams<C>;

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

    let k_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();
    let rho_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();

    let (input_k_outputs, input_rho_outputs) =
        run_parallel_input_phases::<C>(parties, elgamal_pk, &k_shares, &rho_shares, rng);

    let tau_mta_shares = run_paillier_mta::<C>(parties, &k_shares, &rho_shares, params, rng);

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
        panic!("r is zero -- probability < 2^{{-256}}");
    }

    let tau_mult_outputs = continue_mult_phase::<C>(&mut mult_states, &mult_r1_msgs, rng);

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

pub struct Ln18OnlineSignParams<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub paillier_dk: DecryptionKey,
    pub paillier_eks: BTreeMap<PartyId, EncryptionKey>,
    pub ntilde_params: BTreeMap<PartyId, NTildeParams>,
    pub presignature: Ln18Presignature<C>,
}

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

    let rho_shares: Vec<C::Scalar> = online_params
        .iter()
        .map(|p| p.presignature.stored_rho_input.a_i)
        .collect();
    let alpha_shares: Vec<C::Scalar> = alpha_as_input.iter().map(|io| io.a_i).collect();

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

    let k_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();
    let rho_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();

    let (input_k_outputs, input_rho_outputs) =
        run_parallel_input_phases::<C>(parties, elgamal_pk, &k_shares, &rho_shares, rng);

    let tau_mta_shares = run_paillier_mta::<C>(parties, &k_shares, &rho_shares, params, rng);

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
        panic!("r is zero -- probability < 2^{{-256}}");
    }

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

    let alpha_shares: Vec<C::Scalar> = alpha_as_input.iter().map(|io| io.a_i).collect();
    let beta_mta_shares = run_paillier_mta::<C>(parties, &rho_shares, &alpha_shares, params, rng);

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

    let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
    let mut input_r1_msgs: Vec<InputRound1Msg> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) =
            InputState::<C>::new(parties[i], parties.to_vec(), elgamal_pk, shares[i], rng);
        input_states.push(state);
        input_r1_msgs.push(msg);
    }

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

#[cfg(feature = "mta-ot")]
mod ot_sign {
    use elliptic_curve::ops::Reduce;

    use super::*;
    use crate::mta::ot::{OtMtaInitMsg, OtMtaRound1Msg, OtMtaRound2Msg, OtMtaState};

    pub struct Ln18OtPresignParams<C: TecdsaCurve>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        pub key_share: Ln18KeyShare<C>,
        pub init_output: InitOutput<C>,
        pub stored_x_input: InputOutput<C>,
    }

    pub type Ln18OtSignParams<C> = Ln18OtPresignParams<C>;

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

        let k_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();
        let rho_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();

        let (input_k_outputs, input_rho_outputs) =
            run_parallel_input_phases::<C>(parties, elgamal_pk, &k_shares, &rho_shares, rng);

        let tau_mta_shares = run_ot_mta_helper::<C>(parties, &k_shares, &rho_shares, rng);

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
            panic!("r is zero -- probability < 2^{{-256}}");
        }

        let tau_mult_outputs = continue_mult_phase::<C>(&mut mult_states, &mult_r1_msgs, rng);

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

    pub struct Ln18OtOnlineSignParams<C: TecdsaCurve>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        pub presignature: Ln18Presignature<C>,
    }

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

        let k_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();
        let rho_shares: Vec<C::Scalar> = (0..n).map(|_| C::random_scalar(rng)).collect();

        let (input_k_outputs, input_rho_outputs) =
            run_parallel_input_phases::<C>(parties, elgamal_pk, &k_shares, &rho_shares, rng);

        let tau_mta_shares = run_ot_mta_helper::<C>(parties, &k_shares, &rho_shares, rng);

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
            panic!("r is zero -- probability < 2^{{-256}}");
        }

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

        let alpha_shares: Vec<C::Scalar> = alpha_as_input.iter().map(|io| io.a_i).collect();
        let beta_mta_shares = run_ot_mta_helper::<C>(parties, &rho_shares, &alpha_shares, rng);

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

        let mut states: Vec<OtMtaState<C>> = Vec::with_capacity(n);
        let mut all_init_msgs: Vec<Vec<(PartyId, OtMtaInitMsg)>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, init_msgs) =
                OtMtaState::<C>::new(parties[i], parties.to_vec(), a_shares[i], b_shares[i], rng);
            states.push(state);
            all_init_msgs.push(init_msgs);
        }

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

        let mut all_r1_msgs: Vec<Vec<(PartyId, OtMtaRound1Msg)>> = Vec::with_capacity(n);
        for i in 0..n {
            let r1_msgs = states[i]
                .run_receiver_phase1(rng)
                .expect("OT MtA receiver phase1 should succeed");
            all_r1_msgs.push(r1_msgs);
        }

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
