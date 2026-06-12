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
    non_snake_case
)]

use elliptic_curve::CurveArithmetic;
use rand_core::CryptoRngCore;
use rug::{integer::Order, Integer};
use sha2::{Digest, Sha256};
use tecdsa_class_group::{
    cl::{ClCiphertext, ClPublicKey, ClSecretKey, ClSetup, Qfi},
    zk::{r_enc::REncProof, r_m_aff_dl_ec::RMAffDlEcProof},
};
use tecdsa_curve::TecdsaCurve;

use crate::error::Tx25Error;

pub struct MpmtaRound1Output {
    pub ciphertext: ClCiphertext,
    pub proof: REncProof,
    #[allow(dead_code)]
    enc_randomness: Vec<u8>,
}

impl std::fmt::Debug for MpmtaRound1Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpmtaRound1Output").finish_non_exhaustive()
    }
}

pub struct MpmtaRound2Output {
    pub c_alphas: Vec<ClCiphertext>,
    pub betas: Vec<k256::Scalar>,
    pub beta_points: Vec<k256::ProjectivePoint>,
    pub k_star: Vec<u8>,
    pub proof: RMAffDlEcProof,
    pub r_point: k256::ProjectivePoint,
}

impl std::fmt::Debug for MpmtaRound2Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpmtaRound2Output")
            .field("num_parties", &self.c_alphas.len())
            .field("k_star", &"***")
            .finish_non_exhaustive()
    }
}

pub struct MpmtaDecryptOutput {
    pub alpha: k256::Scalar,
    pub delta: k256::Scalar,
}

impl std::fmt::Debug for MpmtaDecryptOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpmtaDecryptOutput")
            .field("alpha", &"***")
            .field("delta", &"***")
            .finish()
    }
}

fn fiat_shamir_challenge(
    qfi_elements: &[&Qfi],
    ec_points: &[&k256::ProjectivePoint],
    extra: &[&str],
) -> Result<Vec<u8>, Tx25Error> {
    use elliptic_curve::group::GroupEncoding;

    let mut hasher = Sha256::new();

    for qfi in qfi_elements {
        hasher.update(qfi.to_bytes());
        hasher.update(b"||");
    }

    for pt in ec_points {
        let bytes = pt.to_bytes();
        hasher.update(<[u8]>::as_ref(&bytes));
        hasher.update(b"||");
    }

    for s in extra {
        hasher.update(s.as_bytes());
        hasher.update(b"||");
    }

    let hash = hasher.finalize();
    let hash_uint = Integer::from_digits(&hash, Order::Msf);
    let q = Integer::from_str_radix(tecdsa_class_group::cl::SECP256K1_ORDER, 10)
        .map_err(|e| Tx25Error::InvalidInput(format!("parse q: {e}")))?;
    let e = hash_uint % &q;
    Ok(e.to_digits::<u8>(Order::Msf))
}

pub fn mpmta_round1(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    gamma_bytes: &[u8],
) -> Result<MpmtaRound1Output, Tx25Error> {
    let (r_sk, _) = setup.keygen()?;
    let r_bytes = setup.sk_to_bytes(&r_sk)?;

    let ct = setup.encrypt_with_r_bytes(pk, gamma_bytes, &r_bytes)?;
    let proof = REncProof::prove(setup, pk, &ct, gamma_bytes, &r_bytes)?;

    Ok(MpmtaRound1Output {
        ciphertext: ct,
        proof,
        enc_randomness: r_bytes,
    })
}

pub fn mpmta_round2(
    setup: &mut ClSetup,
    party_ids: &[u16],
    my_index: usize,
    pks: &[ClPublicKey],
    c_gammas: &[ClCiphertext],
    k_bytes: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<MpmtaRound2Output, Tx25Error> {
    let n = party_ids.len();
    if n != pks.len() || n != c_gammas.len() {
        return Err(Tx25Error::InvalidInput(format!(
            "length mismatch: party_ids={n}, pks={}, c_gammas={}",
            pks.len(),
            c_gammas.len()
        )));
    }
    if my_index >= n {
        return Err(Tx25Error::InvalidInput(format!(
            "my_index ({my_index}) >= n ({n})"
        )));
    }

    let q_bytes = setup
        .q_bytes()
        .map_err(|e| Tx25Error::InvalidInput(format!("q_bytes: {e}")))?;
    let q = Integer::from_digits(&q_bytes, Order::Msf);

    let (e_sk, _) = setup.keygen()?;
    let e_bytes_raw = setup.sk_to_bytes(&e_sk)?;

    let k_bu = Integer::from_digits(k_bytes, Order::Msf);
    let e_bu = Integer::from_digits(&e_bytes_raw, Order::Msf);
    let k_star_bu = &k_bu + Integer::from(&e_bu * &q);
    let k_star_bytes = k_star_bu.to_digits::<u8>(Order::Msf);

    let k_scalar = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(k_bytes);
    let r_point = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * k_scalar;

    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;

    let mut c_alphas: Vec<ClCiphertext> = Vec::with_capacity(n);
    let mut betas: Vec<k256::Scalar> = Vec::with_capacity(n);
    let mut beta_points: Vec<k256::ProjectivePoint> = Vec::with_capacity(n);

    let mut all_d1s: Vec<Qfi> = Vec::with_capacity(n);
    let mut all_d2s: Vec<Qfi> = Vec::with_capacity(n);

    for j in 0..n {
        if j == my_index {
            let id1 = setup.identity()?;
            let id2 = setup.identity()?;
            let identity_ct = setup.ct_from_components(&id1, &id2)?;
            c_alphas.push(identity_ct);
            betas.push(k256::Scalar::ZERO);
            beta_points.push(<k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY);
            all_d1s.push(setup.identity()?);
            all_d2s.push(setup.identity()?);
            continue;
        }

        let beta_ij = k256::Secp256k1::random_scalar(rng);
        let neg_beta = -beta_ij;
        let neg_beta_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&neg_beta);

        let (cj1, cj2) = setup.ct_components(&c_gammas[j])?;

        let d1 = setup.exp_bytes(&cj1, &k_star_bytes)?;

        let cj2_k = setup.exp_bytes(&cj2, &k_star_bytes)?;
        let f_neg_beta = setup.power_of_f_bytes(&neg_beta_bytes)?;
        let d2 = setup.compose(&cj2_k, &f_neg_beta)?;

        let c_alpha = setup.ct_from_components(&d1, &d2)?;

        let b_ij = g * beta_ij;

        c_alphas.push(c_alpha);
        betas.push(beta_ij);
        beta_points.push(b_ij);
        all_d1s.push(d1);
        all_d2s.push(d2);
    }

    let mut c1s = Vec::new();
    let mut c2s = Vec::new();
    let mut d1s = Vec::new();
    let mut d2s = Vec::new();
    let mut e_js: Vec<Vec<u8>> = Vec::new();
    let mut agg_beta = k256::Scalar::ZERO;
    let mut agg_b_point = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;

    for j in 0..n {
        if j == my_index {
            continue;
        }

        let (cj1, cj2) = setup.ct_components(&c_gammas[j])?;
        let e_j_bytes = fiat_shamir_challenge(
            &[&cj1, &cj2, &all_d1s[j], &all_d2s[j]],
            &[&beta_points[j], &r_point],
            &[&j.to_string(), &my_index.to_string()],
        )?;

        let e_j_scalar = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&e_j_bytes);
        agg_beta += betas[j] * e_j_scalar;
        agg_b_point += beta_points[j] * e_j_scalar;

        c1s.push(cj1);
        c2s.push(cj2);
        d1s.push(all_d1s[j].clone());
        d2s.push(all_d2s[j].clone());
        e_js.push(e_j_bytes);
    }

    let agg_c1 = setup.multiexp_bytes(&c1s.iter().collect::<Vec<_>>(), &e_js)?;
    let agg_c2 = setup.multiexp_bytes(&c2s.iter().collect::<Vec<_>>(), &e_js)?;
    let agg_d1 = setup.multiexp_bytes(&d1s.iter().collect::<Vec<_>>(), &e_js)?;
    let agg_d2 = setup.multiexp_bytes(&d2s.iter().collect::<Vec<_>>(), &e_js)?;

    let agg_beta_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&agg_beta);

    let proof = RMAffDlEcProof::prove(
        setup,
        &agg_c1,
        &agg_c2,
        &agg_d1,
        &agg_d2,
        &r_point,
        &agg_b_point,
        &k_star_bytes,
        &agg_beta_bytes,
    )?;

    Ok(MpmtaRound2Output {
        c_alphas,
        betas,
        beta_points,
        k_star: k_star_bytes,
        proof,
        r_point,
    })
}

pub fn mpmta_decrypt(
    setup: &ClSetup,
    sk: &ClSecretKey,
    c_alpha: &ClCiphertext,
    beta: &k256::Scalar,
) -> Result<MpmtaDecryptOutput, Tx25Error> {
    let alpha_bytes = setup.decrypt_bytes(sk, c_alpha)?;
    let alpha = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_bytes);

    let delta = alpha + beta;

    Ok(MpmtaDecryptOutput { alpha, delta })
}

pub fn mpmta_verify_round2(
    setup: &ClSetup,
    party_ids: &[u16],
    prover_index: usize,
    c_gammas: &[ClCiphertext],
    round2: &MpmtaRound2Output,
) -> Result<bool, Tx25Error> {
    let n = party_ids.len();
    if n != c_gammas.len() || n != round2.c_alphas.len() {
        return Ok(false);
    }

    let mut c1s = Vec::new();
    let mut c2s = Vec::new();
    let mut d1s = Vec::new();
    let mut d2s = Vec::new();
    let mut e_js: Vec<Vec<u8>> = Vec::new();
    let mut agg_b_point = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;

    for j in 0..n {
        if j == prover_index {
            continue;
        }

        let (cj1, cj2) = setup.ct_components(&c_gammas[j])?;
        let (dj1, dj2) = setup.ct_components(&round2.c_alphas[j])?;

        let e_j_bytes = fiat_shamir_challenge(
            &[&cj1, &cj2, &dj1, &dj2],
            &[&round2.beta_points[j], &round2.r_point],
            &[&j.to_string(), &prover_index.to_string()],
        )?;

        let e_j_scalar = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&e_j_bytes);
        agg_b_point += round2.beta_points[j] * e_j_scalar;

        c1s.push(cj1);
        c2s.push(cj2);
        d1s.push(dj1);
        d2s.push(dj2);
        e_js.push(e_j_bytes);
    }

    let agg_c1 = setup.multiexp_bytes(&c1s.iter().collect::<Vec<_>>(), &e_js)?;
    let agg_c2 = setup.multiexp_bytes(&c2s.iter().collect::<Vec<_>>(), &e_js)?;
    let agg_d1 = setup.multiexp_bytes(&d1s.iter().collect::<Vec<_>>(), &e_js)?;
    let agg_d2 = setup.multiexp_bytes(&d2s.iter().collect::<Vec<_>>(), &e_js)?;

    let ok = round2.proof.verify(
        setup,
        &agg_c1,
        &agg_c2,
        &agg_d1,
        &agg_d2,
        &round2.r_point,
        &agg_b_point,
    )?;

    Ok(ok)
}
