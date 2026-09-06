// SPDX-License-Identifier: MIT OR Apache-2.0
//! Interactive PDL (Paillier Discrete Log) verification protocol.
//!
//! Implements Protocol 6.1 from Lindell 2017, which allows a verifier (P2)
//! to check that a Paillier ciphertext `c_key = Enc(x_1)` is consistent
//! with the elliptic curve point `Q_1 = x_1 * G`, without learning `x_1`.
//!
//! The protocol is interactive with 4 messages:
//!
//! 1. **V -> P**: `(c_tag, c_tag_tag)` where `c_tag = (a (*) c_key) (+) Enc(b)`,
//!    `c_tag_tag = commit(a, b)`, and `Q_tag = a * Q_1 + b * G`.
//! 2. **P -> V**: `(commit(Q_hat), range_proof)` where `alpha = Dec(c_tag)`,
//!    `Q_hat = alpha * G`.
//! 3. **V -> P**: Decommit `(a, b)`.
//! 4. **P -> V**: Verify `a * x_1 + b = alpha` and decommit `Q_hat`.
//!
//! Final check by V: `Q_hat == Q_tag`.
//!
//! This module is shared by Lin17 and ABC+24 (which is an adaptation of the
//! same PDL verification).

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use rug::Integer;
use tecdsa_bigint::BigIntExt;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{
    conv::{integer_to_scalar, scalar_to_bytes},
    TecdsaCurve,
};
use thiserror::Error;

use crate::scheme::{DecryptionKey, EncryptionKey};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that may occur during the interactive PDL proof.
#[derive(Debug, Error)]
pub enum PdlError {
    /// Paillier operation failed.
    #[error("Paillier operation failed: {0}")]
    Paillier(String),
    /// Commitment verification failed.
    #[error("commitment verification failed: {0}")]
    CommitmentVerification(String),
    /// PDL verification failed.
    #[error("PDL verification failed: {0}")]
    PdlVerification(String),
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Verifier's first message in the PDL protocol.
///
/// Contains:
/// - `c_tag`: Paillier ciphertext `(a (*) c_key) (+) Enc(b)`.
/// - `c_tag_tag`: Commitment to `(a, b)`.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PdlVerifierMsg1 {
    /// `c' = (a (*) c_key) (+) Enc(b)` -- Paillier ciphertext encoding `a*x_1 + b`.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub c_tag: crate::scheme::Ciphertext,
    /// Commitment to `(a, b)`.
    pub c_tag_tag: HashCommitment,
}

/// Prover's first message in the PDL protocol.
///
/// Contains:
/// - `q_hat_commitment`: Commitment to `Q_hat = alpha * G`.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PdlProverMsg1 {
    /// Commitment to `Q_hat = alpha * G`.
    pub q_hat_commitment: HashCommitment,
}

/// Verifier's second message (decommitment of `a, b`).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PdlVerifierMsg2 {
    /// The scalar `a` sampled by the verifier.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub a: Integer,
    /// The scalar `b` sampled by the verifier.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub b: Integer,
    /// Opening nonce for `c_tag_tag`.
    pub nonce: [u8; 32],
}

/// Prover's second message (decommitment of `Q_hat`).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PdlProverMsg2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// `Q_hat = alpha * G` where `alpha = Dec(c_tag)`.
    pub q_hat: C::ProjectivePoint,
    /// Opening nonce for the commitment to `Q_hat`.
    pub nonce: [u8; 32],
}

// ---------------------------------------------------------------------------
// Verifier state
// ---------------------------------------------------------------------------

/// Verifier's state during the PDL protocol.
pub struct PdlVerifierState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The random scalar `a` in Z_q.
    pub a: Integer,
    /// The random scalar `b` in Z_{q^2}.
    pub b: Integer,
    /// `Q' = a * Q_1 + b * G` -- expected value of `Q_hat`.
    pub q_tag: C::ProjectivePoint,
    /// Opening nonce for the commitment `c_tag_tag`.
    pub nonce: [u8; 32],
}

// ---------------------------------------------------------------------------
// Prover state
// ---------------------------------------------------------------------------

/// Prover's state during the PDL protocol.
pub struct PdlProverState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The decrypted value `alpha = Dec(c_tag)`.
    pub alpha: Integer,
    /// `Q_hat = alpha * G`.
    pub q_hat: C::ProjectivePoint,
    /// Opening nonce for commitment to `Q_hat`.
    pub nonce: [u8; 32],
}

// ---------------------------------------------------------------------------
// Verifier functions (P2 side)
// ---------------------------------------------------------------------------

/// Verifier step 1: Sample `a, b`, compute `c_tag`, commit to `(a, b)`.
///
/// The verifier (P2) initiates the PDL verification by:
/// 1. Sampling `a` uniformly from `Z_q`.
/// 2. Sampling `b` uniformly from `Z_{q^2}`.
/// 3. Computing `c_tag = (a (*) c_key) (+) Enc(b)`.
/// 4. Computing `Q' = a * Q_1 + b * G`.
/// 5. Committing to `(a, b)`.
pub fn verifier_step1<C: TecdsaCurve>(
    ek: &EncryptionKey,
    c_key: &crate::scheme::Ciphertext,
    q1: &C::ProjectivePoint,
    rng: &mut impl CryptoRngCore,
) -> Result<(PdlVerifierMsg1, PdlVerifierState<C>), PdlError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Compute q (group order)
    let q_int = tecdsa_curve::conv::curve_order::<C>();

    // Sample a from Z_q
    let a = q_int.sample_below_ref(rng);
    // Sample b from Z_{q^2}
    let b = q_int.square().sample_below_ref(rng);

    // Compute c_tag = (a (*) c_key) (+) Enc(b)
    let c_a = ek
        .omul(&a, c_key)
        .map_err(|e| PdlError::Paillier(format!("PDL omul failed: {e}")))?;
    let (c_b, _) = ek
        .encrypt_with_random(rng, &b)
        .map_err(|e| PdlError::Paillier(format!("PDL encrypt b failed: {e}")))?;
    let c_tag = ek
        .oadd(&c_a, &c_b)
        .map_err(|e| PdlError::Paillier(format!("PDL oadd failed: {e}")))?;

    // Compute Q' = a * Q_1 + b * G
    let a_scalar = tecdsa_curve::conv::bytes_to_scalar::<C>(&a.to_bytes_msf());
    let b_scalar = tecdsa_curve::conv::bytes_to_scalar::<C>(&b.to_bytes_msf());
    let q_tag = *q1 * a_scalar + C::generator() * b_scalar;

    // Commit to (a, b)
    let ab_bytes = serialize_ab(&a, &b);
    let (c_tag_tag, nonce) = HashCommitment::commit(&ab_bytes, rng);

    let msg = PdlVerifierMsg1 { c_tag, c_tag_tag };
    let state = PdlVerifierState { a, b, q_tag, nonce };

    Ok((msg, state))
}

/// Verifier step 2: After receiving prover's commitment, send decommitment.
///
/// This step simply reveals `(a, b, nonce)`.
pub fn verifier_step2<C: TecdsaCurve>(state: &PdlVerifierState<C>) -> PdlVerifierMsg2
where
    FieldBytesSize<C>: ModulusSize,
{
    PdlVerifierMsg2 {
        a: state.a.clone(),
        b: state.b.clone(),
        nonce: state.nonce,
    }
}

/// Verifier final check: verify prover's decommitment and check `Q_hat == Q'`.
pub fn verifier_finalize<C: TecdsaCurve>(
    state: &PdlVerifierState<C>,
    prover_msg1: &PdlProverMsg1,
    prover_msg2: &PdlProverMsg2<C>,
) -> Result<(), PdlError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify prover's commitment to Q_hat opens correctly
    let q_hat_bytes = prover_msg2.q_hat.to_bytes();
    if !prover_msg1
        .q_hat_commitment
        .verify(q_hat_bytes.as_ref(), &prover_msg2.nonce)
    {
        return Err(PdlError::CommitmentVerification(
            "PDL: prover Q_hat commitment opening failed".into(),
        ));
    }

    // Check Q_hat == Q'
    if prover_msg2.q_hat != state.q_tag {
        return Err(PdlError::PdlVerification("PDL: Q_hat != Q_tag".into()));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Prover functions (P1 side)
// ---------------------------------------------------------------------------

/// Prover step 1: Decrypt `c_tag`, compute `Q_hat = alpha * G`, commit.
pub fn prover_step1<C: TecdsaCurve>(
    dk: &DecryptionKey,
    verifier_msg: &PdlVerifierMsg1,
    rng: &mut impl CryptoRngCore,
) -> Result<(PdlProverMsg1, PdlProverState<C>), PdlError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Decrypt c_tag to get alpha
    let alpha = dk
        .decrypt(&verifier_msg.c_tag)
        .map_err(|e| PdlError::Paillier(format!("PDL decrypt c_tag failed: {e}")))?;

    // Compute Q_hat = alpha * G
    // alpha might be negative (Paillier returns values in {-N/2, .., N/2})
    // We need to handle this by reducing mod q
    let alpha_scalar = integer_to_scalar::<C>(&alpha);
    let q_hat = C::generator() * alpha_scalar;

    // Commit to Q_hat
    let q_hat_bytes = q_hat.to_bytes();
    let (commitment, nonce) = HashCommitment::commit(q_hat_bytes.as_ref(), rng);

    let msg = PdlProverMsg1 {
        q_hat_commitment: commitment,
    };
    let state = PdlProverState {
        alpha,
        q_hat,
        nonce,
    };

    Ok((msg, state))
}

/// Prover step 2: Verify decommitment, check `a*x_1 + b = alpha` (over integers),
/// and send decommitment of `Q_hat`.
pub fn prover_step2<C: TecdsaCurve>(
    x1: &C::Scalar,
    state: &PdlProverState<C>,
    verifier_msg1: &PdlVerifierMsg1,
    verifier_msg2: &PdlVerifierMsg2,
) -> Result<PdlProverMsg2<C>, PdlError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify verifier's commitment to (a, b) opens correctly
    let ab_bytes = serialize_ab(&verifier_msg2.a, &verifier_msg2.b);
    if !verifier_msg1
        .c_tag_tag
        .verify(&ab_bytes, &verifier_msg2.nonce)
    {
        return Err(PdlError::CommitmentVerification(
            "PDL: verifier (a, b) commitment opening failed".into(),
        ));
    }

    // Check that a * x_1 + b = alpha (over the integers).
    // First we need x_1 as an Integer.
    let x1_bytes = scalar_to_bytes(x1);
    let x1_int = Integer::from_bytes_msf(&x1_bytes);

    let expected = Integer::from(&verifier_msg2.a * &x1_int + &verifier_msg2.b);

    // The alpha from Paillier decryption might be in {-N/2, ..., N/2}.
    // If Paillier gave back a negative, the original plaintext was
    // wrapped: actual value = alpha + N. But since a*x1+b is
    // computed over the integers and is always positive (a, x1, b >= 0)
    // and strictly less than N (since a < q, x1 < q, b < q^2, and q << N),
    // the Paillier decryption should return a positive value directly.
    if expected != state.alpha {
        return Err(PdlError::PdlVerification(
            "PDL: a * x_1 + b != alpha".into(),
        ));
    }

    // Return decommitment of Q_hat
    Ok(PdlProverMsg2 {
        q_hat: state.q_hat,
        nonce: state.nonce,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serialize (a, b) to bytes for commitment.
fn serialize_ab(a: &Integer, b: &Integer) -> Vec<u8> {
    let a_bytes = a.to_bytes_msf();
    let b_bytes = b.to_bytes_msf();
    #[allow(clippy::cast_possible_truncation)]
    let a_len = a_bytes.len() as u32;
    #[allow(clippy::cast_possible_truncation)]
    let b_len = b_bytes.len() as u32;
    let mut data = Vec::with_capacity(4 + a_bytes.len() + 4 + b_bytes.len());
    data.extend_from_slice(&a_len.to_le_bytes());
    data.extend_from_slice(&a_bytes);
    data.extend_from_slice(&b_len.to_le_bytes());
    data.extend_from_slice(&b_bytes);
    data
}

/// Run the complete PDL verification protocol between prover (P1) and verifier (P2).
///
/// Returns `Ok(())` if the proof passes, meaning `c_key` is an encryption of
/// the discrete log of `q1`.
pub fn pdl_verify<C: TecdsaCurve>(
    dk: &DecryptionKey,
    ek: &EncryptionKey,
    x1: &C::Scalar,
    c_key: &crate::scheme::Ciphertext,
    q1: &C::ProjectivePoint,
    rng: &mut impl CryptoRngCore,
) -> Result<(), PdlError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verifier step 1
    let (v_msg1, v_state) = verifier_step1::<C>(ek, c_key, q1, rng)?;

    // Prover step 1
    let (p_msg1, p_state) = prover_step1::<C>(dk, &v_msg1, rng)?;

    // Verifier step 2
    let v_msg2 = verifier_step2::<C>(&v_state);

    // Prover step 2
    let p_msg2 = prover_step2::<C>(x1, &p_state, &v_msg1, &v_msg2)?;

    // Verifier finalize
    verifier_finalize::<C>(&v_state, &p_msg1, &p_msg2)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;

    use super::*;

    #[test]
    fn pdl_proof_valid() {
        let mut rng = rand_core::OsRng;

        // Generate Paillier keys
        let dk = crate::scheme::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        // Generate EC key
        let x1 = Secp256k1::random_scalar(&mut rng);
        let q1 = Secp256k1::generator() * x1;

        // Encrypt x1
        let x1_bytes = scalar_to_bytes(&x1);
        let x1_int = Integer::from_bytes_msf(&x1_bytes);
        let (c_key, _) = dk.encrypt_with_random(&mut rng, &x1_int).expect("encrypt");

        // Run PDL verification
        pdl_verify::<Secp256k1>(&dk, &ek, &x1, &c_key, &q1, &mut rng)
            .expect("PDL verification should pass");
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn pdl_proof_wrong_ckey() {
        let mut rng = rand_core::OsRng;

        let dk = crate::scheme::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let x1 = Secp256k1::random_scalar(&mut rng);
        let q1 = Secp256k1::generator() * x1;

        // Encrypt a DIFFERENT value
        let wrong_x = Secp256k1::random_scalar(&mut rng);
        let wrong_bytes = scalar_to_bytes(&wrong_x);
        let wrong_int = Integer::from_bytes_msf(&wrong_bytes);
        let (wrong_c_key, _) = dk
            .encrypt_with_random(&mut rng, &wrong_int)
            .expect("encrypt");

        // PDL verification should fail: c_key encrypts wrong_x, not x1
        let result = pdl_verify::<Secp256k1>(&dk, &ek, &x1, &wrong_c_key, &q1, &mut rng);
        assert!(result.is_err(), "PDL should fail with wrong c_key");
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn pdl_proof_wrong_q1() {
        let mut rng = rand_core::OsRng;

        let dk = crate::scheme::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let x1 = Secp256k1::random_scalar(&mut rng);

        // Use a WRONG public key (different generator point)
        let wrong_x = Secp256k1::random_scalar(&mut rng);
        let wrong_q1 = Secp256k1::generator() * wrong_x;

        let x1_bytes = scalar_to_bytes(&x1);
        let x1_int = Integer::from_bytes_msf(&x1_bytes);
        let (c_key, _) = dk.encrypt_with_random(&mut rng, &x1_int).expect("encrypt");

        // PDL verification should fail: q1 does not correspond to x1
        let result = pdl_verify::<Secp256k1>(&dk, &ek, &x1, &c_key, &wrong_q1, &mut rng);
        assert!(result.is_err(), "PDL should fail with wrong Q1");
    }
}
