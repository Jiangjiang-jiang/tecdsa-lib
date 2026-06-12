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
    non_snake_case
)]

use elliptic_curve::CurveArithmetic;
use rand_core::CryptoRngCore;
use tecdsa_class_group::{
    cl::{ClPublicKey, ClSecretKey, ClSetup, Qfi},
    pvss_share,
    zk::r_sh::RShProof,
};
use tecdsa_curve::TecdsaCurve;

use crate::error::Tx25Error;

pub struct PvssOutput {
    pub c1: Qfi,
    pub c2s: Vec<Qfi>,
    pub proof: RShProof,
    pub secret_share: k256::Scalar,
    pub polynomial_coeffs: Vec<k256::Scalar>,
}

impl std::fmt::Debug for PvssOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PvssOutput")
            .field("num_shares", &self.c2s.len())
            .field("secret_share", &"***")
            .finish_non_exhaustive()
    }
}

pub struct ShareCombOutput {
    pub share: k256::Scalar,
    pub share_point: k256::ProjectivePoint,
}

impl std::fmt::Debug for ShareCombOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareCombOutput")
            .field("share", &"***")
            .finish_non_exhaustive()
    }
}

pub fn pvss_distribute(
    setup: &mut ClSetup,
    party_ids: &[u16],
    pks: &[ClPublicKey],
    threshold: u16,
    my_index_in_list: usize,
    rng: &mut impl CryptoRngCore,
) -> Result<PvssOutput, Tx25Error> {
    let a_0 = k256::Secp256k1::random_scalar(rng);
    pvss_distribute_with_secret(setup, party_ids, pks, threshold, my_index_in_list, a_0, rng)
}

pub fn pvss_distribute_with_secret(
    setup: &mut ClSetup,
    party_ids: &[u16],
    pks: &[ClPublicKey],
    threshold: u16,
    my_index_in_list: usize,
    secret: k256::Scalar,
    _rng: &mut impl CryptoRngCore,
) -> Result<PvssOutput, Tx25Error> {
    let n = party_ids.len();
    if n != pks.len() {
        return Err(Tx25Error::InvalidInput(format!(
            "party_ids.len() ({n}) != pks.len() ({})",
            pks.len()
        )));
    }
    if threshold == 0 || threshold as usize > n {
        return Err(Tx25Error::InvalidInput(format!(
            "threshold {threshold} out of range for {n} parties"
        )));
    }
    if my_index_in_list >= n {
        return Err(Tx25Error::InvalidInput(format!(
            "my_index_in_list ({my_index_in_list}) >= n ({n})"
        )));
    }

    let secret_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&secret);

    let output = pvss_share::pvss_share_distribute_with_secret(
        setup,
        party_ids,
        pks,
        threshold,
        my_index_in_list,
        &secret_bytes,
    )?;

    let polynomial_coeffs: Vec<k256::Scalar> = output
        .polynomial_coeffs_bytes
        .iter()
        .map(|b| tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(b))
        .collect();

    Ok(PvssOutput {
        c1: output.c1,
        c2s: output.c2s,
        proof: output.proof,
        secret_share: tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(
            &output.secret_share_bytes,
        ),
        polynomial_coeffs,
    })
}

pub fn pvss_verify(
    setup: &ClSetup,
    party_ids: &[u16],
    pks: &[ClPublicKey],
    threshold: u16,
    c1: &Qfi,
    c2s: &[Qfi],
    proof: &RShProof,
) -> Result<bool, Tx25Error> {
    let ok = pvss_share::pvss_share_verify(setup, party_ids, pks, threshold, c1, c2s, proof)?;
    Ok(ok)
}

pub fn pvss_decrypt_share(
    setup: &ClSetup,
    sk: &ClSecretKey,
    c1: &Qfi,
    c2_my: &Qfi,
) -> Result<k256::Scalar, Tx25Error> {
    let sk_bytes = setup.sk_to_bytes(sk)?;
    let share_bytes = pvss_share::pvss_share_decrypt(setup, &sk_bytes, c1, c2_my)?;
    Ok(tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(
        &share_bytes,
    ))
}

pub fn pvss_decrypt_share_full(
    setup: &ClSetup,
    sk: &ClSecretKey,
    c1: &Qfi,
    c2_my: &Qfi,
) -> Result<ShareCombOutput, Tx25Error> {
    let share = pvss_decrypt_share(setup, sk, c1, c2_my)?;
    let share_point = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * share;

    Ok(ShareCombOutput { share, share_point })
}
