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
//! `ClPublicKey`/`ClSecretKey`/`ClCiphertext` wrappers.
//!
//! The WMY23 presign module (`presign/`) calls these functions directly
//! rather than going through the trait, because:
//! - The presign protocol needs `&mut ClSetup` (not `RefCell`-based interior
//!   mutability used by the generic `ClMtA`).
//! - The protocol stores intermediate CL types (`ClCiphertext`) across
//!   rounds, which requires the `cl_enc` wrapper types.
//!
//! ## Faithfulness to WMY23 Figure 5 (Phase 2)
//!
//! In the paper, the receiver (Alice) of every MtAwc instance is the holder
//! of the nonce share `k_j`, and the ciphertext consumed by the sender is
//! `c_{k_j}` -- the *same* ciphertext that `DRG.Comb` output and bound to
//! `PC_{k_j}` via the broadcast `R_Enc-PC` proof (Phase 1b). The receiver's
//! Step-3 check is the algebraic check `g^alpha * g^beta = (g^b)^a`, which is
//! computable as `Gamma_i^{k_j}` / `X_i^{k_j}` because the k-holder knows the
//! scalar `k_j` and `Gamma_i = g^{gamma_i}` (resp. `X_i = g^{x_i}`) are
//! published. The presign module therefore feeds the (Lagrange-scaled)
//! `DRG.Comb` ciphertext into [`mtawc_bob`] and verifies decryptions with
//! [`mtawc_alice_decrypt_and_check`].

#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use tecdsa_class_group::cl::{ClCiphertext, ClPublicKey, ClSecretKey, ClSetup};
use tecdsa_curve::{ScalarExt, TecdsaCurve};

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
    let a_int = a.to_integer();
    let ct = setup.encrypt(pk_alice, &a_int)?;
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
    let b_int = b.to_integer();
    let c_ab = setup.scal_ciphertext(pk_alice, c_a, &b_int)?;

    // Compute Enc(-beta)
    let neg_beta = -beta;
    let neg_beta_int = neg_beta.to_integer();
    let c_neg_beta = setup.encrypt(pk_alice, &neg_beta_int)?;

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
    let alpha_int = setup.decrypt(sk_alice, c_alpha)?;
    let alpha = k256::Secp256k1::scalar_from_integer(&alpha_int);

    // Check: g^alpha * g^beta == (g^b)^a
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let lhs = g * alpha + g_beta;
    let rhs = *g_b * state.a;

    if bool::from(!lhs.to_bytes().ct_eq(&rhs.to_bytes())) {
        return Err(MtAwcError::CheckFailed);
    }

    Ok(MtAwcAliceOutput { alpha })
}

/// **Step 3 (Alice), explicit-scalar variant:** Decrypt Bob's response and
/// run the faithful WMY23 Figure 1 / Figure 5 (Phase 2) algebraic check.
///
/// This is identical to [`mtawc_alice_step2`] but takes Alice's secret `a`
/// directly (rather than via [`MtAwcAliceState`]), which is convenient in
/// presigning where `a = hat_k_i` is already held in the round state and the
/// same value is reused across both the `k*gamma` and `k*x` conversions.
///
/// The check `g^alpha * g^beta == (g^b)^a` is exactly the paper's Phase-2
/// verification: with Alice = nonce-share holder, `a = k_j` (a scalar Alice
/// knows) and `g^b` is the published `Gamma_i = g^{gamma_i}` (resp.
/// `X_i = g^{x_i}`), so the right-hand side is `Gamma_i^{k_j}` (resp.
/// `X_i^{k_j}`). No `g^{k_j}` is ever needed, so the nonce share stays secret.
/// A failed check identifies the sender (Bob) as a cheater (WMY23 Sec. V-D).
///
/// # Errors
///
/// Returns [`MtAwcError::CheckFailed`] if the algebraic check fails, or a CL
/// error if decryption fails.
pub fn mtawc_alice_decrypt_and_check(
    setup: &ClSetup,
    sk_alice: &ClSecretKey,
    c_alpha: &ClCiphertext,
    g_beta: &k256::ProjectivePoint,
    a: &k256::Scalar,
    g_b: &k256::ProjectivePoint,
) -> MtAwcResult<MtAwcAliceOutput> {
    // Decrypt: alpha = Dec(sk, c_alpha)
    let alpha_int = setup.decrypt(sk_alice, c_alpha)?;
    let alpha = k256::Secp256k1::scalar_from_integer(&alpha_int);

    // WMY23 Figure 1 / Figure 5 (Phase 2), Step 3:
    //   check  g^alpha * g^beta == (g^b)^a
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let lhs = g * alpha + g_beta;
    let rhs = *g_b * a;

    if bool::from(!lhs.to_bytes().ct_eq(&rhs.to_bytes())) {
        return Err(MtAwcError::CheckFailed);
    }

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
            let bytes = s.to_bytes_vec();
            let s2 = k256::Secp256k1::scalar_from_bytes(&bytes);
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
        let mut setup = ClSetup::new_secp256k1(42u64).expect("CL setup");
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
        let mut setup = ClSetup::new_secp256k1(99u64).expect("CL setup");
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
        let mut setup = ClSetup::new_secp256k1(123u64).expect("CL setup");
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
        let mut setup = ClSetup::new_secp256k1(77u64).expect("CL setup");
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
