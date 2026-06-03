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
    clippy::cast_lossless
)]

//! Shared-randomness PVSS (PolyVerify-based) for threshold ECDSA protocols.
//!
//! This is the PVSS pattern used by JTX25, WMC24, and TX25, where all
//! encrypted shares use a single shared randomness `rho`:
//!
//!   c1 = h^rho  (common to all parties)
//!   c2_j = pk_j^rho * f^{v_j}  for each party j
//!
//! The sharing is proven correct via the `R_Sh` (PolyVerify) ZK proof.
//!
//! This module is distinct from the Cascudo-David PVSS in `pvss.rs`, which
//! uses per-share independent randomness and individual `R_Enc` proofs.

use num_bigint::BigUint;

use crate::{
    cl::{ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi},
    zk::{r_sh::RShProof, sample_random_mod_q},
};

/// Output of shared-randomness PVSS distribution.
pub struct PvssShareOutput {
    /// `c1 = h^rho` -- common to all parties.
    pub c1: Qfi,
    /// `c2_j = pk_j^rho * f^{v_j}` for each party `j`.
    pub c2s: Vec<Qfi>,
    /// `R_Sh` proof (PolyVerify) of correct polynomial sharing.
    pub proof: RShProof,
    /// The distributor's own plaintext share as big-endian bytes.
    pub secret_share_bytes: Vec<u8>,
}

/// Output of shared-randomness PVSS distribution with polynomial coefficients.
///
/// Used by TX25 which needs the polynomial coefficients for later use.
pub struct PvssShareWithCoeffsOutput {
    /// `c1 = h^rho` -- common to all parties.
    pub c1: Qfi,
    /// `c2_j = pk_j^rho * f^{v_j}` for each party `j`.
    pub c2s: Vec<Qfi>,
    /// `R_Sh` proof (PolyVerify) of correct polynomial sharing.
    pub proof: RShProof,
    /// The distributor's own plaintext share as big-endian bytes.
    pub secret_share_bytes: Vec<u8>,
    /// Polynomial coefficients as big-endian bytes (a_0, a_1, ..., a_{t-1}).
    pub polynomial_coeffs_bytes: Vec<Vec<u8>>,
}

/// Evaluates a polynomial at a point modulo `q` using Horner's method.
///
/// `coeffs[i]` is the coefficient of `x^i`.
fn eval_poly_mod_q(coeffs: &[BigUint], x: &BigUint, q: &BigUint) -> BigUint {
    let mut result = BigUint::ZERO;
    for coeff in coeffs.iter().rev() {
        result = (&result * x + coeff) % q;
    }
    result
}

/// Distributes a shared-randomness PVSS with random polynomial coefficients.
///
/// Picks a random `(t-1)`-degree polynomial `f(x)` over `Z_q`, samples
/// shared randomness `rho`, encrypts each share under the corresponding
/// party's CL public key, and generates an `R_Sh` proof.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context (mutable for random sampling).
/// * `party_ids` - 1-based party indices for all parties.
/// * `pks` - CL public keys for each party (same order as `party_ids`).
/// * `reconstruct_threshold` - Reconstruction threshold (t+1 in corruption convention) (degree of polynomial is `t-1`).
/// * `my_index_in_list` - The distributor's position in `party_ids` (0-based).
pub fn pvss_share_distribute(
    setup: &mut ClSetup,
    party_ids: &[u16],
    pks: &[ClHsmqkPublicKey],
    reconstruct_threshold: u16,
    my_index_in_list: usize,
) -> ClResult<PvssShareOutput> {
    let n = party_ids.len();
    let q = BigUint::from_bytes_be(&setup.q_bytes()?);
    let t = reconstruct_threshold as usize;

    // Generate random polynomial coefficients in [0, q).
    let mut coeffs = Vec::with_capacity(t);
    for _ in 0..t {
        let r = sample_random_mod_q(setup)?;
        coeffs.push(BigUint::from_bytes_be(&r));
    }

    // Evaluate polynomial at each party's id.
    let shares: Vec<Vec<u8>> = party_ids
        .iter()
        .map(|&id| {
            let x = BigUint::from(id);
            eval_poly_mod_q(&coeffs, &x, &q).to_bytes_be()
        })
        .collect();

    // Sample shared randomness rho.
    let (rho_sk, _) = setup.keygen()?;
    let rho_bytes = setup.sk_to_bytes(&rho_sk)?;

    // c1 = h^rho.
    let c1 = setup.power_of_h_bytes(&rho_bytes)?;

    // c2_j = pk_j^rho * f^{v_j} for each party j.
    let mut c2s: Vec<Qfi> = Vec::with_capacity(n);
    for (idx, share) in shares.iter().enumerate() {
        let pk_elt = &pks[idx].elt();
        let pk_rho = setup.exp_bytes(pk_elt, &rho_bytes)?;
        let f_v = setup.power_of_f_bytes(share)?;
        let c2 = setup.compose(&pk_rho, &f_v)?;
        c2s.push(c2);
    }

    // Generate R_Sh proof.
    let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();
    let c2_refs: Vec<&Qfi> = c2s.iter().collect();
    let proof = RShProof::prove(
        setup,
        party_ids,
        reconstruct_threshold,
        &pk_refs,
        &c1,
        &c2_refs,
        &rho_bytes,
    )?;

    Ok(PvssShareOutput {
        c1,
        c2s,
        proof,
        secret_share_bytes: shares[my_index_in_list].clone(),
    })
}

/// Distributes a shared-randomness PVSS with a pre-determined secret.
///
/// The polynomial `f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}` uses the
/// given `secret_bytes` as `a_0` and random higher-order coefficients.
///
/// Returns the full output including polynomial coefficients.
pub fn pvss_share_distribute_with_secret(
    setup: &mut ClSetup,
    party_ids: &[u16],
    pks: &[ClHsmqkPublicKey],
    reconstruct_threshold: u16,
    my_index_in_list: usize,
    secret_bytes: &[u8],
) -> ClResult<PvssShareWithCoeffsOutput> {
    let n = party_ids.len();
    let q = BigUint::from_bytes_be(&setup.q_bytes()?);
    let t = reconstruct_threshold as usize;

    // Build polynomial: a_0 = secret, a_1..a_{t-1} random.
    let mut coeffs = Vec::with_capacity(t);
    coeffs.push(BigUint::from_bytes_be(secret_bytes) % &q);
    for _ in 1..t {
        let r = sample_random_mod_q(setup)?;
        coeffs.push(BigUint::from_bytes_be(&r));
    }

    // Evaluate polynomial at each party's id.
    let shares: Vec<Vec<u8>> = party_ids
        .iter()
        .map(|&id| {
            let x = BigUint::from(id);
            eval_poly_mod_q(&coeffs, &x, &q).to_bytes_be()
        })
        .collect();

    // Sample shared randomness rho.
    let (rho_sk, _) = setup.keygen()?;
    let rho_bytes = setup.sk_to_bytes(&rho_sk)?;

    // c1 = h^rho.
    let c1 = setup.power_of_h_bytes(&rho_bytes)?;

    // c2_j = pk_j^rho * f^{v_j} for each party j.
    let mut c2s: Vec<Qfi> = Vec::with_capacity(n);
    for (idx, share) in shares.iter().enumerate() {
        let pk_elt = &pks[idx].elt();
        let pk_rho = setup.exp_bytes(pk_elt, &rho_bytes)?;
        let f_v = setup.power_of_f_bytes(share)?;
        let c2 = setup.compose(&pk_rho, &f_v)?;
        c2s.push(c2);
    }

    // Generate R_Sh proof.
    let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();
    let c2_refs: Vec<&Qfi> = c2s.iter().collect();
    let proof = RShProof::prove(
        setup,
        party_ids,
        reconstruct_threshold,
        &pk_refs,
        &c1,
        &c2_refs,
        &rho_bytes,
    )?;

    let polynomial_coeffs_bytes: Vec<Vec<u8>> = coeffs.iter().map(|c| c.to_bytes_be()).collect();

    Ok(PvssShareWithCoeffsOutput {
        c1,
        c2s,
        proof,
        secret_share_bytes: shares[my_index_in_list].clone(),
        polynomial_coeffs_bytes,
    })
}

/// Verifies a shared-randomness PVSS distribution using the `R_Sh` proof.
///
/// Any party can call this to verify that the encrypted shares are
/// consistent with a polynomial of degree `<= t-1` and were produced
/// with shared randomness.
pub fn pvss_share_verify(
    setup: &ClSetup,
    party_ids: &[u16],
    pks: &[ClHsmqkPublicKey],
    reconstruct_threshold: u16,
    c1: &Qfi,
    c2s: &[Qfi],
    proof: &RShProof,
) -> ClResult<bool> {
    if party_ids.len() != pks.len() || party_ids.len() != c2s.len() {
        return Ok(false);
    }
    let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();
    let c2_refs: Vec<&Qfi> = c2s.iter().collect();
    proof.verify(
        setup,
        party_ids,
        reconstruct_threshold,
        &pk_refs,
        c1,
        &c2_refs,
    )
}

/// Decrypts a party's encrypted PVSS share and returns the share as bytes.
///
/// Given `c1 = h^rho` and `c2_my = pk^rho * f^{share}`, the party
/// computes:
///   1. `M = c1^sk` (where `pk = h^sk`)
///   2. `f_share = c2_my * M^{-1}` (class-group composition with inverse)
///   3. `share = dlog_in_F(f_share)` (discrete log in the F subgroup)
///
/// Returns the decrypted share as big-endian bytes.
pub fn pvss_share_decrypt(
    setup: &ClSetup,
    sk_bytes: &[u8],
    c1: &Qfi,
    c2_my: &Qfi,
) -> ClResult<Vec<u8>> {
    let mut m = setup.exp_bytes(c1, sk_bytes)?;
    m.neg();
    let f_share = setup.compose(c2_my, &m)?;
    setup.dlog_in_F_bytes(&f_share)
}
