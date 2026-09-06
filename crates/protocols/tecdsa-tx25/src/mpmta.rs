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
    clippy::too_many_arguments,
    non_snake_case
)]

//! Multi-Party MtA with Public Checking (MPMtA) for TX25.
//!
//! Implements the MPMtA protocol from TX25 Section 3.3, using CL-based
//! affine operations with EC-point-based public checking.
//!
//! # Protocol overview
//!
//! **Round 1 (Alice broadcasts):**
//! Each party `i` encrypts its secret `gamma_i` (or `k_i`) under its
//! own CL public key and broadcasts the ciphertext with an `R_Enc` proof
//! of well-formedness.
//!
//! **Round 2 (Bob processes):**
//! For each received `C_{gamma_j}`, Bob computes the CL affine operation
//! using his secret `k_i`:
//!   - Picks `beta_{i,j}` uniformly from `Z_q`
//!   - `C_{alpha_{j,i}} = (c_{j,1}^{k*}, c_{j,2}^{k*} * f^{-beta_{i,j}})`
//!     where `k* = k + e*q` lifts `k` to the CL domain
//!   - Computes `B_{i,j} = beta_{i,j} * G` for public checking
//!   - Generates an aggregated `R_m-AffDL-Ec` proof
//!
//! **Decryption (Alice):**
//! Alice decrypts the `C_alpha` ciphertext and combines with `beta`
//! to obtain `delta = alpha + beta`.
//!
//! # Relationship to the `MtA` / `MtAWithCheck` traits
//!
//! This module does NOT use the `tecdsa_protocol::MtA` trait or
//! `tecdsa_class_group::mta::ClMtA` because the TX25 MPMtA protocol
//! differs from pairwise MtA in several fundamental ways:
//!
//! - **CL-domain lifting:** The secret `k` is lifted to `k* = k + e*q`
//!   before the affine operation, ensuring the result decrypts correctly
//!   in the larger CL plaintext space.  The `ClMtA` trait does not expose
//!   this domain-lifting step.
//! - **QFI-level operations:** The affine computation operates directly on
//!   the QFI components `(c1, c2)` of the ciphertext via `exp`, `compose`,
//!   and `power_of_f`, rather than through the high-level `scal_ciphertext`
//!   and `add_ciphertexts` APIs used by `ClMtA`.
//! - **Multi-party aggregation:** Per-party ciphertexts are aggregated with
//!   Fiat-Shamir challenges into a single aggregated relation, over which
//!   the `R_m-AffDL-Ec` proof is generated.  This is structurally different
//!   from running N-1 independent pairwise MtA instances.
//! - **Public checking via EC points:** The `B_{i,j} = beta_{i,j} * G`
//!   commitments are integral to the aggregated proof structure and the
//!   TX25 online-phase cheater identification mechanism.
//!
//! Each pairwise sub-computation within MPMtA is algebraically equivalent
//! to a single CL MtA execution, but the proof system and aggregation
//! make the overall protocol non-decomposable into independent `MtA` calls.
//!
//! Reference: Tang & Xue. "Robust Threshold ECDSA." S&P 2025, Section 3.3.

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

// ---------------------------------------------------------------------------
// Round 1 output
// ---------------------------------------------------------------------------

/// Output of MPMtA Round 1 (Alice broadcasts).
///
/// Contains the CL ciphertext of the sender's secret and an `R_Enc` proof
/// of well-formedness.
pub struct MpmtaRound1Output {
    /// `Enc(ek_i, gamma_i; rho)` -- encryption of the sender's secret.
    pub ciphertext: ClCiphertext,
    /// `R_Enc` proof that the ciphertext is well-formed.
    pub proof: REncProof,
    /// Encryption randomness (kept by the prover, not broadcast).
    #[allow(dead_code)]
    enc_randomness: Vec<u8>,
}

impl std::fmt::Debug for MpmtaRound1Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpmtaRound1Output").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Round 2 output
// ---------------------------------------------------------------------------

/// Output of MPMtA Round 2 (Bob processes all received ciphertexts).
///
/// For each sender `j != me`, Bob produces an affine ciphertext `C_alpha_{j,i}`,
/// a beta value, and a beta point for public checking.
pub struct MpmtaRound2Output {
    /// `C_{alpha_{j,i}}` for each sender `j` (indexed same as `party_ids`).
    /// For `j == me`, this is a dummy identity ciphertext.
    pub c_alphas: Vec<ClCiphertext>,
    /// `beta_{i,j}` values (secret, one per party).
    /// For `j == me`, this is `Scalar::ZERO`.
    pub betas: Vec<k256::Scalar>,
    /// `B_{i,j} = beta_{i,j} * G` (public, one per party).
    pub beta_points: Vec<k256::ProjectivePoint>,
    /// `k* = k + e*q` (big-endian bytes, the lifted secret used in the affine operation).
    pub k_star: Vec<u8>,
    /// Aggregated `R_m-AffDL-Ec` proof.
    pub proof: RMAffDlEcProof,
    /// `R_i = (k mod q) * G` -- the EC point corresponding to the secret.
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

// ---------------------------------------------------------------------------
// Decrypt output
// ---------------------------------------------------------------------------

/// Output of MPMtA decryption (Alice decrypts Bob's response).
pub struct MpmtaDecryptOutput {
    /// Decrypted `alpha` value: `alpha = Dec(sk, C_alpha)`.
    pub alpha: k256::Scalar,
    /// `delta = alpha + beta` (the combined MtA output share).
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

/// Computes a Fiat-Shamir challenge hash from QFI elements, EC points,
/// and extra strings, reduced modulo `q`.
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

// ---------------------------------------------------------------------------
// Round 1: Alice broadcasts
// ---------------------------------------------------------------------------

/// MPMtA Round 1: Encrypt the sender's secret and produce a proof.
///
/// Each party `i` encrypts its secret `gamma_i` under its own CL public
/// key and generates an `R_Enc` proof of well-formedness.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context (mutable for encryption + proof).
/// * `pk` - This party's CL public key.
/// * `gamma_bytes` - The secret value to encrypt (big-endian bytes).
pub fn mpmta_round1(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    gamma_bytes: &[u8],
) -> Result<MpmtaRound1Output, Tx25Error> {
    // Encrypt with known randomness so we can produce the R_Enc proof.
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

// ---------------------------------------------------------------------------
// Round 2: Bob processes all received ciphertexts
// ---------------------------------------------------------------------------

/// MPMtA Round 2: Process all received ciphertexts with the local secret.
///
/// For each received `C_{gamma_j}` from party `j`, Bob (party `i`) computes
/// the CL affine operation using his secret `k_i`:
///
/// 1. Lift `k` to CL domain: `k* = k + e*q` where `e` is sampled from
///    the encrypt randomness domain.
/// 2. For each `j != me`:
///    - Sample `beta_{i,j}` uniformly from `Z_q`.
///    - Parse `C_{gamma_j} = (c_{j,1}, c_{j,2})`.
///    - `C_{alpha_{j,i}} = (c_{j,1}^{k*}, c_{j,2}^{k*} * f^{-beta_{i,j}})`.
///    - `B_{i,j} = beta_{i,j} * G`.
/// 3. Aggregate ciphertexts with Fiat-Shamir challenges and produce
///    an `R_m-AffDL-Ec` proof.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `party_ids` - All party indices (1-based).
/// * `my_index` - This party's position in `party_ids` (0-based).
/// * `pks` - CL public keys for all parties (same order as `party_ids`).
/// * `c_gammas` - Received `C_{gamma_j}` ciphertexts from all parties.
///   The entry at `my_index` is this party's own ciphertext (will be skipped).
/// * `k_decimal` - This party's secret (decimal string).
/// * `rng` - Cryptographic RNG.
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

    // Step 1: Lift k to CL domain: k* = k + e*q.
    // Sample e from the encrypt randomness domain (secret-key range).
    let (e_sk, _) = setup.keygen()?;
    let e_bytes_raw = setup.sk_to_bytes(&e_sk)?;

    let k_bu = Integer::from_digits(k_bytes, Order::Msf);
    let e_bu = Integer::from_digits(&e_bytes_raw, Order::Msf);
    let k_star_bu = k_bu + e_bu * q;
    let k_star_bytes = k_star_bu.to_digits::<u8>(Order::Msf);

    // Compute R_i = (k mod q) * G.
    let k_scalar = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(k_bytes);
    let r_point = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * k_scalar;

    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;

    // Step 2: For each j, compute affine operation.
    let mut c_alphas: Vec<ClCiphertext> = Vec::with_capacity(n);
    let mut betas: Vec<k256::Scalar> = Vec::with_capacity(n);
    let mut beta_points: Vec<k256::ProjectivePoint> = Vec::with_capacity(n);

    // Collect per-party (d1, d2) for the aggregated proof.
    let mut all_d1s: Vec<Qfi> = Vec::with_capacity(n);
    let mut all_d2s: Vec<Qfi> = Vec::with_capacity(n);

    for j in 0..n {
        if j == my_index {
            // For self: trivial values.
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

        // Sample beta_{i,j} uniformly from Z_q.
        let beta_ij = k256::Secp256k1::random_scalar(rng);
        let neg_beta = -beta_ij;
        let neg_beta_bytes = tecdsa_curve::conv::scalar_to_bytes(&neg_beta);

        // Parse C_{gamma_j} = (c_{j,1}, c_{j,2}).
        let (cj1, cj2) = setup.ct_components(&c_gammas[j])?;

        // d1 = c_{j,1}^{k*}
        let d1 = setup.exp_bytes(&cj1, &k_star_bytes)?;

        // d2 = c_{j,2}^{k*} * f^{-beta_{i,j}}
        let cj2_k = setup.exp_bytes(&cj2, &k_star_bytes)?;
        let f_neg_beta = setup.power_of_f_bytes(&neg_beta_bytes)?;
        let d2 = setup.compose(&cj2_k, &f_neg_beta)?;

        // Reconstruct as ciphertext.
        let c_alpha = setup.ct_from_components(&d1, &d2)?;

        // B_{i,j} = beta_{i,j} * G
        let b_ij = g * beta_ij;

        c_alphas.push(c_alpha);
        betas.push(beta_ij);
        beta_points.push(b_ij);
        all_d1s.push(d1);
        all_d2s.push(d2);
    }

    // Step 3: Aggregate ciphertexts with Fiat-Shamir challenges for the proof.
    //
    // We aggregate the per-party (c1_j, c2_j) -> (d1_j, d2_j) into a single
    // aggregated relation for the R_m-AffDL-Ec proof.
    // Collect each party's bases and the shared per-party challenge exponents,
    // then fold each aggregate with a single shared-squaring multi-exponentiation.
    // The bases differ per party (not reused), so this is a genuine variable-base
    // multi-exp: `multiexp` shares one squaring chain across all n terms instead
    // of doing n independent exp+compose pairs.
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

        // Compute per-party Fiat-Shamir challenge e_j.
        let (cj1, cj2) = setup.ct_components(&c_gammas[j])?;
        let e_j_bytes = fiat_shamir_challenge(
            &[&cj1, &cj2, &all_d1s[j], &all_d2s[j]],
            &[&beta_points[j], &r_point],
            &[&j.to_string(), &my_index.to_string()],
        )?;

        // Aggregate beta and B on the EC side.
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

    // Compute aggregated beta decimal for the proof.
    let agg_beta_bytes = tecdsa_curve::conv::scalar_to_bytes(&agg_beta);

    // Generate the R_m-AffDL-Ec proof on the aggregated values.
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

// ---------------------------------------------------------------------------
// Decryption: Alice decrypts Bob's response
// ---------------------------------------------------------------------------

/// MPMtA decryption: Alice decrypts the response ciphertext.
///
/// Given `C_alpha` from Bob and Alice's own `beta` share, decrypts
/// `alpha = Dec(sk, C_alpha)` and computes `delta = alpha + beta`.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `sk` - Alice's (the sender's) CL secret key.
/// * `c_alpha` - The affine ciphertext from Bob.
/// * `beta` - Alice's beta share (from Bob's round 2 output, or
///   the beta she received from Bob).
pub fn mpmta_decrypt(
    setup: &ClSetup,
    sk: &ClSecretKey,
    c_alpha: &ClCiphertext,
    beta: &k256::Scalar,
) -> Result<MpmtaDecryptOutput, Tx25Error> {
    // Decrypt: alpha = Dec(sk, C_alpha).
    let alpha_bytes = setup.decrypt_bytes(sk, c_alpha)?;
    let alpha = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_bytes);

    // delta = alpha + beta.
    let delta = alpha + beta;

    Ok(MpmtaDecryptOutput { alpha, delta })
}

// ---------------------------------------------------------------------------
// Round 2 verification helper
// ---------------------------------------------------------------------------

/// Verifies an MPMtA Round 2 output's aggregated proof.
///
/// A verifier recomputes the aggregated ciphertext components from the
/// public data and checks the `R_m-AffDL-Ec` proof.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `party_ids` - All party indices.
/// * `prover_index` - The prover's position in `party_ids` (0-based).
/// * `c_gammas` - The original Round 1 ciphertexts from all parties.
/// * `round2` - The prover's Round 2 output to verify.
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

    // Recompute the aggregated values from public data.
    // Same shared-squaring multi-exponentiation as the prover side (see above).
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

        // Recompute per-party Fiat-Shamir challenge.
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

    // Verify the aggregated proof.
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
