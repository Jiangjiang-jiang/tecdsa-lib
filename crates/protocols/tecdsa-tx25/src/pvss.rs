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
    non_snake_case
)]

//! TX25 PVSS adapter over `tecdsa_class_group::pvss_share`.
//!
//! Thin wrappers that convert
//! byte-level results to `k256::Scalar` / protocol-specific types.
//!
//! # Distribution (ShareDist)
//!
//! The dealer:
//! 1. Picks a random `(t-1)`-degree polynomial `f(x)` over `Z_q`.
//! 2. Picks shared randomness `rho` from the encrypt randomness domain.
//! 3. For each party `j`: computes `c2_j = pk_j^rho * f^{f(j)}`.
//! 4. Computes `c1 = h^rho` (shared across all parties).
//! 5. Generates an `R_Sh` proof of correct polynomial sharing.
//!
//! # Verification
//!
//! Any verifier can check the `R_Sh` proof against public data.
//!
//! # Decryption (ShareComb)
//!
//! Each party decrypts their encrypted share using their CL secret key.
//!
//! Reference: Tang & Xue. "Robust Threshold ECDSA." S&P 2025, Section 3.

use elliptic_curve::CurveArithmetic;
use rand_core::CryptoRngCore;
use tecdsa_class_group::{
    cl::{ClPublicKey, ClSecretKey, ClSetup, Qfi},
    pvss_share,
    zk::r_sh::RShProof,
};
use tecdsa_curve::TecdsaCurve;

use crate::error::Tx25Error;

// ---------------------------------------------------------------------------
// PVSS Output types
// ---------------------------------------------------------------------------

/// Output of PVSS distribution (ShareDist).
///
/// Contains the shared ciphertext component, per-party encrypted shares,
/// the `R_Sh` proof, the distributor's own share, and the polynomial
/// coefficients for later use.
pub struct PvssOutput {
    /// `c1 = h^rho` -- shared across all parties.
    pub c1: Qfi,
    /// `c2_j = pk_j^rho * f^{f(j)}` for each party `j`.
    pub c2s: Vec<Qfi>,
    /// `R_Sh` proof (PolyVerify) linking encrypted shares to the polynomial.
    pub proof: RShProof,
    /// `f(my_index)` -- the distributor's own plaintext share.
    pub secret_share: k256::Scalar,
    /// Polynomial coefficients `a_0, a_1, ..., a_{t-1}`.
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

/// Output of PVSS decryption (ShareComb).
pub struct ShareCombOutput {
    /// The decrypted share value.
    pub share: k256::Scalar,
    /// The share committed on the elliptic curve: `share * G`.
    pub share_point: k256::ProjectivePoint,
}

impl std::fmt::Debug for ShareCombOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareCombOutput")
            .field("share", &"***")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// PVSS Distribution
// ---------------------------------------------------------------------------

/// Distributes a PVSS sharing with a random secret.
///
/// Picks a random `(t-1)`-degree polynomial `f(x)` over `Z_q`, samples
/// shared randomness `rho`, encrypts each share under the corresponding
/// party's CL public key, and generates an `R_Sh` proof.
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

/// Distributes a PVSS sharing with a pre-determined secret `a_0`.
///
/// The polynomial `f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}` uses the
/// given `secret` as `a_0` and random higher-order coefficients.
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

    let secret_bytes = tecdsa_curve::conv::scalar_to_bytes(&secret);

    let output = pvss_share::pvss_share_distribute_with_secret(
        setup,
        party_ids,
        pks,
        threshold,
        my_index_in_list,
        &secret_bytes,
    )?;

    // Convert polynomial coefficients from bytes to Scalars.
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

// ---------------------------------------------------------------------------
// PVSS Verification
// ---------------------------------------------------------------------------

/// Verifies a PVSS distribution using the `R_Sh` proof.
///
/// Any party can call this to verify that the encrypted shares are
/// consistent with a polynomial of degree `<= t-1` and were produced
/// with shared randomness.
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

// ---------------------------------------------------------------------------
// PVSS Decryption (ShareComb)
// ---------------------------------------------------------------------------

/// Decrypts a party's encrypted PVSS share.
///
/// Given `c1 = h^rho` and `c2_my = pk^rho * f^{share}`, the party
/// computes:
///   1. `M = c1^sk` (where `pk = h^sk`)
///   2. `f_share = c2_my * M^{-1}` (class-group composition with inverse)
///   3. `share = dlog_in_F(f_share)` (discrete log in the F subgroup)
///
/// Returns the decrypted share as a scalar.
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

/// Decrypts a party's encrypted PVSS share and returns full output
/// including the share point `share * G`.
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
