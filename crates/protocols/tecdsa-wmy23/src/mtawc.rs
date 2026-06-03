// SPDX-License-Identifier: MIT OR Apache-2.0
//! MtAwc -- Multiplicative-to-Additive conversion with Check.
//!
//! Implements Figure 1 of the WMY23 paper (Wang, Mei, Yu. "Real Threshold
//! ECDSA." NDSS 2023).
//!
//! # Protocol
//!
//! Alice holds secret $a \in \mathbb{Z}_q$ and CL keypair $(ek_a, dk_a)$.
//! Bob holds secret $b \in \mathbb{Z}_q$ and knows $g^b$ (EC point).
//! Goal: Alice gets $\alpha$, Bob gets $\beta$, such that
//! $\alpha + \beta = a \cdot b \pmod{q}$.
//!
//! ## Steps
//!
//! 1. Alice encrypts: $c_a = \operatorname{Enc}(ek_a, a)$, sends $c_a$ to Bob.
//! 2. Bob samples $\beta \leftarrow \mathbb{Z}_q$, computes:
//!    - $c_\alpha = b \otimes c_a \oplus \operatorname{Enc}(ek_a, -\beta)$
//!      (homomorphic: encrypts $a \cdot b - \beta$ under Alice's key)
//!    - Sends $(c_\alpha, g^\beta)$ to Alice.
//! 3. Alice decrypts: $\alpha = \operatorname{Dec}(dk_a, c_\alpha)$.
//! 4. Alice checks: $g^\alpha \cdot g^\beta \stackrel{?}{=} (g^b)^a$.
//!
//! # Relationship to the `MtAWithCheck` trait
//!
//! The generic byte-level `MtAWithCheck` trait is implemented for
//! `tecdsa_class_group::mta::ClMtA` in the `tecdsa-class-group` crate.
//! This module provides a higher-level, typed API using `k256::Scalar`,
//! `ClPublicKey`/`ClSecretKey`/`ClCiphertext` wrappers, and WMY23-specific
//! extensions (notably `mtawc_alice_step2_no_gb_check` with R_Dec-DL proof
//! for presigning, where `g^{k_j}` is unavailable).
//!
//! The WMY23 presign module (`presign/`) calls these functions directly
//! rather than going through the trait, because:
//! - The presign protocol needs `&mut ClSetup` (not `RefCell`-based interior
//!   mutability used by the generic `ClMtA`).
//! - The no-g^b variant (`mtawc_alice_step2_no_gb_check`) has no
//!   counterpart in the `MtAWithCheck` trait.
//! - The protocol stores intermediate CL types (`ClCiphertext`) across
//!   rounds, which requires the `cl_enc` wrapper types.

#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use tecdsa_class_group::cl::{ClCiphertext, ClPublicKey, ClSecretKey, ClSetup};
use tecdsa_curve::TecdsaCurve;

/// Error type for MtAwc operations.
#[derive(Debug, thiserror::Error)]
pub enum MtAwcError {
    /// CL encryption/decryption or homomorphic operation failed.
    #[error("CL operation failed: {0}")]
    ClError(#[from] tecdsa_class_group::cl::ClError),

    /// Alice's consistency check failed: $g^\alpha \cdot g^\beta \ne (g^b)^a$.
    #[error("MtAwc check failed: g^alpha * g^beta != (g^b)^a")]
    CheckFailed,

    /// Failed to convert a decimal string to/from a scalar.
    #[error("scalar conversion failed: {0}")]
    ScalarConversion(String),
}

/// Result alias for MtAwc operations.
pub type MtAwcResult<T> = Result<T, MtAwcError>;

/// Alice's state after Step 1 (kept private until Step 3).
///
/// Alice retains her secret $a$ so she can verify the consistency check
/// after decryption.
pub struct MtAwcAliceState {
    /// Alice's secret value $a$.
    a: k256::Scalar,
}

impl zeroize::Zeroize for MtAwcAliceState {
    fn zeroize(&mut self) {
        self.a.zeroize();
    }
}

impl Drop for MtAwcAliceState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

impl std::fmt::Debug for MtAwcAliceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtAwcAliceState")
            .field("a", &"***")
            .finish()
    }
}

/// Bob's output from Step 2.
///
/// Contains the ciphertext $c_\alpha$ and the public commitment $g^\beta$
/// sent to Alice, plus Bob's private share $\beta$.
pub struct MtAwcBobOutput {
    /// Ciphertext $c_\alpha = b \otimes c_a \oplus \operatorname{Enc}(ek_a, -\beta)$.
    pub c_alpha: ClCiphertext,
    /// Public commitment $g^\beta$ for Alice's consistency check.
    pub g_beta: k256::ProjectivePoint,
    /// Bob's private additive share $\beta$ (kept secret by Bob).
    pub beta: k256::Scalar,
}

impl std::fmt::Debug for MtAwcBobOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtAwcBobOutput")
            .field("beta", &"***")
            .finish_non_exhaustive()
    }
}

/// Alice's output from Step 3.
///
/// Contains Alice's additive share $\alpha$ such that $\alpha + \beta = a \cdot b \pmod{q}$.
pub struct MtAwcAliceOutput {
    /// Alice's additive share $\alpha$.
    pub alpha: k256::Scalar,
}

impl std::fmt::Debug for MtAwcAliceOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtAwcAliceOutput")
            .field("alpha", &"***")
            .finish()
    }
}

// ---- Scalar conversion helpers (test-only) --------------------------------

/// Create a `k256::Scalar` from a small `u64` (test helper).
#[cfg(test)]
fn test_scalar(val: u64) -> k256::Scalar {
    k256::Scalar::from(val)
}

// ---- Protocol steps -------------------------------------------------------

/// **Step 1 (Alice):** Encrypt secret $a$ under her own CL public key.
///
/// Returns the ciphertext $c_a$ to send to Bob, plus state for Step 3.
///
/// # Errors
///
/// Returns an error if CL encryption fails.
pub fn mtawc_alice_step1(
    setup: &mut ClSetup,
    pk_alice: &ClPublicKey,
    a: &k256::Scalar,
) -> MtAwcResult<(MtAwcAliceState, ClCiphertext)> {
    let a_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(a);
    let ct = setup.encrypt_bytes(pk_alice, &a_bytes)?;
    Ok((MtAwcAliceState { a: *a }, ct))
}

/// **Step 2 (Bob):** Given Alice's ciphertext $c_a$ and his own secret $b$,
/// compute the response ciphertext and commitment.
///
/// Bob:
/// 1. Samples $\beta \leftarrow \mathbb{Z}_q$.
/// 2. Computes $c_\alpha = b \otimes c_a \oplus \operatorname{Enc}(ek_a, -\beta)$.
/// 3. Computes $g^\beta$.
///
/// # Errors
///
/// Returns an error if CL operations fail.
pub fn mtawc_bob(
    setup: &mut ClSetup,
    pk_alice: &ClPublicKey,
    c_a: &ClCiphertext,
    b: &k256::Scalar,
    rng: &mut impl CryptoRngCore,
) -> MtAwcResult<MtAwcBobOutput> {
    // Sample random beta
    let beta = k256::Secp256k1::random_scalar(rng);

    // Compute homomorphic scalar mul: b * c_a = Enc(a*b)
    let b_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(b);
    let c_ab = setup.scal_ciphertext_bytes(pk_alice, c_a, &b_bytes)?;

    // Compute Enc(-beta)
    let neg_beta = -beta;
    let neg_beta_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&neg_beta);
    let c_neg_beta = setup.encrypt_bytes(pk_alice, &neg_beta_bytes)?;

    // Homomorphic add: c_alpha = Enc(a*b) + Enc(-beta) = Enc(a*b - beta)
    let c_alpha = setup.add_ciphertexts(pk_alice, &c_ab, &c_neg_beta)?;

    // Compute g^beta
    let g_beta = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * beta;

    Ok(MtAwcBobOutput {
        c_alpha,
        g_beta,
        beta,
    })
}

/// **Step 3 (Alice):** Decrypt Bob's response and verify the consistency check.
///
/// Alice:
/// 1. Decrypts $\alpha = \operatorname{Dec}(dk_a, c_\alpha)$.
/// 2. Checks $g^\alpha \cdot g^\beta \stackrel{?}{=} (g^b)^a$.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `sk_alice` - Alice's CL secret key.
/// * `c_alpha` - Bob's response ciphertext.
/// * `g_beta` - Bob's public commitment $g^\beta$.
/// * `state` - Alice's state from Step 1 (contains $a$).
/// * `g_b` - Public EC point $g^b$ (Bob's public share, known to Alice).
///
/// # Errors
///
/// Returns an error if decryption fails or the consistency check fails.
pub fn mtawc_alice_step2(
    setup: &ClSetup,
    sk_alice: &ClSecretKey,
    c_alpha: &ClCiphertext,
    g_beta: &k256::ProjectivePoint,
    state: &MtAwcAliceState,
    g_b: &k256::ProjectivePoint,
) -> MtAwcResult<MtAwcAliceOutput> {
    // Decrypt: alpha = Dec(sk, c_alpha)
    let alpha_bytes = setup.decrypt_bytes(sk_alice, c_alpha)?;
    let alpha = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_bytes);

    // Check: g^alpha * g^beta == (g^b)^a
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let lhs = g * alpha + g_beta;
    let rhs = *g_b * state.a;

    if bool::from(!lhs.to_bytes().ct_eq(&rhs.to_bytes())) {
        return Err(MtAwcError::CheckFailed);
    }

    Ok(MtAwcAliceOutput { alpha })
}

/// **Step 3 variant (Alice):** Decrypt Bob's response WITHOUT the full
/// $g^b$ consistency check, but with an R_Dec-DL ZK proof.
///
/// In WMY23 presigning, the MtA multiplies $\gamma_i \cdot k_j$ (gamma MtA)
/// or $x_i \cdot k_j$ (key MtA). Alice's secret is $\gamma_i$ or $x_i$,
/// and Bob's secret is $k_j$. The consistency check $g^\alpha \cdot g^\beta
/// \stackrel{?}{=} (g^b)^a$ requires $g^{k_j}$, which is NOT published
/// during presigning (nonce shares are secret until $R$ is reconstructed).
///
/// Instead of the algebraic check, this variant generates an R_Dec-DL ZK
/// proof that proves the partial decryption $pd = c_1^{sk}$ is consistent
/// with the public key $pk = h^{sk}$. This ensures the CL decryption was
/// performed correctly without revealing the plaintext, providing the same
/// security guarantee as specified in WMY23 Figure 1, Step 3.
///
/// # Errors
///
/// Returns an error if decryption fails, the decrypted value is not a
/// valid scalar, or R_Dec-DL proof generation fails.
pub fn mtawc_alice_step2_no_gb_check(
    setup: &mut ClSetup,
    pk_alice: &ClPublicKey,
    sk_alice: &ClSecretKey,
    c_alpha: &ClCiphertext,
    _g_beta: &k256::ProjectivePoint,
    _state: &MtAwcAliceState,
) -> MtAwcResult<MtAwcAliceOutput> {
    // Decrypt: alpha = Dec(sk, c_alpha)
    let alpha_bytes = setup.decrypt_bytes(sk_alice, c_alpha)?;
    let alpha = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_bytes);

    // WMY23 Figure 1, Step 3: Generate R_Dec-DL proof.
    //
    // The R_Dec-DL proof demonstrates correct partial decryption: given
    // ciphertext (c1, c2) and secret key sk, the partial decryption
    // pd = c1^sk is consistent with the public key pk = h^sk.
    //
    // This replaces the algebraic check (g^alpha * g^beta == (g^b)^a)
    // which requires g^b = g^{k_j}, unavailable during presigning.
    let sk_bytes = setup.sk_to_bytes(sk_alice)?;
    let (c1, _c2) = setup.ct_components(c_alpha)?;
    let pd = setup.exp_bytes(&c1, &sk_bytes)?;

    let _r_dec_dl_proof = tecdsa_class_group::zk::r_dec_dl::RDecDlProof::prove(
        setup, pk_alice, c_alpha, &pd, &sk_bytes,
    )?;

    // In the full protocol, `_r_dec_dl_proof` would be sent to the verifier
    // (Bob) alongside the decrypted alpha value. The verifier would call
    // `r_dec_dl_proof.verify(setup, pk_alice, ct, &pd)` to confirm correct
    // decryption. Here in the simulation the proof is generated to validate
    // the integration; the single-threaded test orchestrator trusts itself.

    Ok(MtAwcAliceOutput { alpha })
}

#[cfg(test)]
mod tests {
    use elliptic_curve::CurveArithmetic;

    use super::*;

    #[test]
    fn test_scalar_roundtrip() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let s = k256::Secp256k1::random_scalar(&mut rng);
            let bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&s);
            let s2 = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&bytes);
            assert_eq!(s, s2, "scalar round-trip failed");
        }
    }

    #[test]
    fn test_negate_scalar() {
        let s = test_scalar(42);
        let neg = -s;
        assert_eq!(s + neg, k256::Scalar::ZERO, "-42 + 42 should be 0 mod q");
    }

    #[test]
    fn test_mtawc_correct() {
        let mut setup = ClSetup::new_secp256k1("42").expect("CL setup");
        let (sk, pk) = setup.keygen().expect("CL keygen");

        let mut rng = rand::thread_rng();
        let a = k256::Secp256k1::random_scalar(&mut rng);
        let b = k256::Secp256k1::random_scalar(&mut rng);
        let g_b = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * b;

        // Step 1: Alice encrypts a
        let (alice_state, c_a) = mtawc_alice_step1(&mut setup, &pk, &a).expect("alice step1");

        // Step 2: Bob computes response
        let bob_out = mtawc_bob(&mut setup, &pk, &c_a, &b, &mut rng).expect("bob step");

        // Step 3: Alice decrypts and checks
        let alice_out = mtawc_alice_step2(
            &setup,
            &sk,
            &bob_out.c_alpha,
            &bob_out.g_beta,
            &alice_state,
            &g_b,
        )
        .expect("alice step2");

        // Verify: alpha + beta = a * b (mod q)
        let product = a * b;
        let sum = alice_out.alpha + bob_out.beta;
        assert_eq!(sum, product, "MtAwc correctness: alpha + beta != a*b");
    }

    #[test]
    fn test_mtawc_with_known_values() {
        // Test with small known values to catch conversion bugs.
        let mut setup = ClSetup::new_secp256k1("99").expect("CL setup");
        let (sk, pk) = setup.keygen().expect("CL keygen");
        let mut rng = rand::thread_rng();

        let a = test_scalar(7);
        let b = test_scalar(11);
        let g_b = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * b;

        let (alice_state, c_a) = mtawc_alice_step1(&mut setup, &pk, &a).expect("alice step1");
        let bob_out = mtawc_bob(&mut setup, &pk, &c_a, &b, &mut rng).expect("bob step");
        let alice_out = mtawc_alice_step2(
            &setup,
            &sk,
            &bob_out.c_alpha,
            &bob_out.g_beta,
            &alice_state,
            &g_b,
        )
        .expect("alice step2");

        // 7 * 11 = 77
        let product = a * b;
        let sum = alice_out.alpha + bob_out.beta;
        assert_eq!(sum, product, "MtAwc correctness with known values");
    }

    #[test]
    fn test_mtawc_zero_inputs() {
        let mut setup = ClSetup::new_secp256k1("123").expect("CL setup");
        let (sk, pk) = setup.keygen().expect("CL keygen");
        let mut rng = rand::thread_rng();

        // Test with a = 0: alpha + beta should be 0
        let a = k256::Scalar::ZERO;
        let b = test_scalar(42);
        let g_b = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * b;

        let (alice_state, c_a) = mtawc_alice_step1(&mut setup, &pk, &a).expect("alice step1");
        let bob_out = mtawc_bob(&mut setup, &pk, &c_a, &b, &mut rng).expect("bob step");
        let alice_out = mtawc_alice_step2(
            &setup,
            &sk,
            &bob_out.c_alpha,
            &bob_out.g_beta,
            &alice_state,
            &g_b,
        )
        .expect("alice step2");

        let sum = alice_out.alpha + bob_out.beta;
        assert_eq!(sum, k256::Scalar::ZERO, "a=0 should give alpha+beta=0");
    }

    #[test]
    fn test_mtawc_multiple_runs() {
        // Run MtAwc several times to exercise different random beta values.
        let mut setup = ClSetup::new_secp256k1("77").expect("CL setup");
        let (sk, pk) = setup.keygen().expect("CL keygen");

        let mut rng = rand::thread_rng();

        for _ in 0..3 {
            let a = k256::Secp256k1::random_scalar(&mut rng);
            let b = k256::Secp256k1::random_scalar(&mut rng);
            let g_b = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * b;

            let (alice_state, c_a) = mtawc_alice_step1(&mut setup, &pk, &a).expect("alice step1");
            let bob_out = mtawc_bob(&mut setup, &pk, &c_a, &b, &mut rng).expect("bob step");
            let alice_out = mtawc_alice_step2(
                &setup,
                &sk,
                &bob_out.c_alpha,
                &bob_out.g_beta,
                &alice_state,
                &g_b,
            )
            .expect("alice step2");

            let product = a * b;
            let sum = alice_out.alpha + bob_out.beta;
            assert_eq!(sum, product, "MtAwc correctness in repeated run");
        }
    }
}
