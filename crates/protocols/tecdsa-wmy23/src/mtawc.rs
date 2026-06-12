#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use tecdsa_class_group::cl::{ClCiphertext, ClPublicKey, ClSecretKey, ClSetup};
use tecdsa_curve::TecdsaCurve;

#[derive(Debug, thiserror::Error)]
pub enum MtAwcError {
    #[error("CL operation failed: {0}")]
    ClError(#[from] tecdsa_class_group::cl::ClError),

    #[error("MtAwc check failed: g^alpha * g^beta != (g^b)^a")]
    CheckFailed,

    #[error("scalar conversion failed: {0}")]
    ScalarConversion(String),
}

pub type MtAwcResult<T> = Result<T, MtAwcError>;

pub struct MtAwcAliceState {
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

pub struct MtAwcBobOutput {
    pub c_alpha: ClCiphertext,
    pub g_beta: k256::ProjectivePoint,
    pub beta: k256::Scalar,
}

impl std::fmt::Debug for MtAwcBobOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtAwcBobOutput")
            .field("beta", &"***")
            .finish_non_exhaustive()
    }
}

pub struct MtAwcAliceOutput {
    pub alpha: k256::Scalar,
}

impl std::fmt::Debug for MtAwcAliceOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtAwcAliceOutput")
            .field("alpha", &"***")
            .finish()
    }
}

#[cfg(test)]
fn test_scalar(val: u64) -> k256::Scalar {
    k256::Scalar::from(val)
}

pub fn mtawc_alice_step1(
    setup: &mut ClSetup,
    pk_alice: &ClPublicKey,
    a: &k256::Scalar,
) -> MtAwcResult<(MtAwcAliceState, ClCiphertext)> {
    let a_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(a);
    let ct = setup.encrypt_bytes(pk_alice, &a_bytes)?;
    Ok((MtAwcAliceState { a: *a }, ct))
}

pub fn mtawc_bob(
    setup: &mut ClSetup,
    pk_alice: &ClPublicKey,
    c_a: &ClCiphertext,
    b: &k256::Scalar,
    rng: &mut impl CryptoRngCore,
) -> MtAwcResult<MtAwcBobOutput> {
    let beta = k256::Secp256k1::random_scalar(rng);

    let b_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(b);
    let c_ab = setup.scal_ciphertext_bytes(pk_alice, c_a, &b_bytes)?;

    let neg_beta = -beta;
    let neg_beta_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&neg_beta);
    let c_neg_beta = setup.encrypt_bytes(pk_alice, &neg_beta_bytes)?;

    let c_alpha = setup.add_ciphertexts(pk_alice, &c_ab, &c_neg_beta)?;

    let g_beta = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * beta;

    Ok(MtAwcBobOutput {
        c_alpha,
        g_beta,
        beta,
    })
}

pub fn mtawc_alice_step2(
    setup: &ClSetup,
    sk_alice: &ClSecretKey,
    c_alpha: &ClCiphertext,
    g_beta: &k256::ProjectivePoint,
    state: &MtAwcAliceState,
    g_b: &k256::ProjectivePoint,
) -> MtAwcResult<MtAwcAliceOutput> {
    let alpha_bytes = setup.decrypt_bytes(sk_alice, c_alpha)?;
    let alpha = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_bytes);

    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let lhs = g * alpha + g_beta;
    let rhs = *g_b * state.a;

    if bool::from(!lhs.to_bytes().ct_eq(&rhs.to_bytes())) {
        return Err(MtAwcError::CheckFailed);
    }

    Ok(MtAwcAliceOutput { alpha })
}

pub fn mtawc_alice_decrypt_and_check(
    setup: &ClSetup,
    sk_alice: &ClSecretKey,
    c_alpha: &ClCiphertext,
    g_beta: &k256::ProjectivePoint,
    a: &k256::Scalar,
    g_b: &k256::ProjectivePoint,
) -> MtAwcResult<MtAwcAliceOutput> {
    let alpha_bytes = setup.decrypt_bytes(sk_alice, c_alpha)?;
    let alpha = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_bytes);

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
        assert_eq!(sum, product, "MtAwc correctness: alpha + beta != a*b");
    }

    #[test]
    fn test_mtawc_with_known_values() {
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

        let product = a * b;
        let sum = alice_out.alpha + bob_out.beta;
        assert_eq!(sum, product, "MtAwc correctness with known values");
    }

    #[test]
    fn test_mtawc_zero_inputs() {
        let mut setup = ClSetup::new_secp256k1("123").expect("CL setup");
        let (sk, pk) = setup.keygen().expect("CL keygen");
        let mut rng = rand::thread_rng();

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
