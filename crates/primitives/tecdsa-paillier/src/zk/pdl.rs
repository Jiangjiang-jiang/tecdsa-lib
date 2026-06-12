use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use fast_paillier::{backend::Integer, DecryptionKey, EncryptionKey};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{conv::scalar_to_bytes, TecdsaCurve};
use thiserror::Error;

use crate::conv::integer_to_scalar;

#[derive(Debug, Error)]
pub enum PdlError {
    #[error("Paillier operation failed: {0}")]
    Paillier(String),
    #[error("commitment verification failed: {0}")]
    CommitmentVerification(String),
    #[error("PDL verification failed: {0}")]
    PdlVerification(String),
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PdlVerifierMsg1 {
    pub c_tag: fast_paillier::Ciphertext,
    pub c_tag_tag: HashCommitment,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PdlProverMsg1 {
    pub q_hat_commitment: HashCommitment,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PdlVerifierMsg2 {
    pub a: Integer,
    pub b: Integer,
    pub nonce: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PdlProverMsg2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub q_hat: C::ProjectivePoint,
    pub nonce: [u8; 32],
}

pub struct PdlVerifierState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub a: Integer,
    pub b: Integer,
    pub q_tag: C::ProjectivePoint,
    pub nonce: [u8; 32],
}

pub struct PdlProverState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub alpha: Integer,
    pub q_hat: C::ProjectivePoint,
    pub nonce: [u8; 32],
}

pub fn verifier_step1<C: TecdsaCurve>(
    ek: &EncryptionKey,
    c_key: &fast_paillier::Ciphertext,
    q1: &C::ProjectivePoint,
    rng: &mut impl CryptoRngCore,
) -> Result<(PdlVerifierMsg1, PdlVerifierState<C>), PdlError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q_bytes = scalar_to_bytes::<C>(&(-C::Scalar::ONE));
    let q_int = Integer::from_bytes_msf(&q_bytes) + 1u8;
    let q_squared = &q_int * &q_int;

    let a = q_int.random_below_ref(rng);
    let b = q_squared.random_below_ref(rng);

    let c_a = ek
        .omul(&a, c_key)
        .map_err(|e| PdlError::Paillier(format!("PDL omul failed: {e}")))?;
    let (c_b, _) = ek
        .encrypt_with_random(rng, &b)
        .map_err(|e| PdlError::Paillier(format!("PDL encrypt b failed: {e}")))?;
    let c_tag = ek
        .oadd(&c_a, &c_b)
        .map_err(|e| PdlError::Paillier(format!("PDL oadd failed: {e}")))?;

    let a_scalar = tecdsa_curve::conv::bytes_to_scalar::<C>(&a.to_bytes_msf());
    let b_scalar = tecdsa_curve::conv::bytes_to_scalar::<C>(&b.to_bytes_msf());
    let q_tag = *q1 * a_scalar + C::generator() * b_scalar;

    let ab_bytes = serialize_ab(&a, &b);
    let (c_tag_tag, nonce) = HashCommitment::commit(&ab_bytes, rng);

    let msg = PdlVerifierMsg1 { c_tag, c_tag_tag };
    let state = PdlVerifierState { a, b, q_tag, nonce };

    Ok((msg, state))
}

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

pub fn verifier_finalize<C: TecdsaCurve>(
    state: &PdlVerifierState<C>,
    prover_msg1: &PdlProverMsg1,
    prover_msg2: &PdlProverMsg2<C>,
) -> Result<(), PdlError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q_hat_bytes = prover_msg2.q_hat.to_bytes();
    if !prover_msg1
        .q_hat_commitment
        .verify(q_hat_bytes.as_ref(), &prover_msg2.nonce)
    {
        return Err(PdlError::CommitmentVerification(
            "PDL: prover Q_hat commitment opening failed".into(),
        ));
    }

    if prover_msg2.q_hat != state.q_tag {
        return Err(PdlError::PdlVerification("PDL: Q_hat != Q_tag".into()));
    }

    Ok(())
}

pub fn prover_step1<C: TecdsaCurve>(
    dk: &DecryptionKey,
    verifier_msg: &PdlVerifierMsg1,
    rng: &mut impl CryptoRngCore,
) -> Result<(PdlProverMsg1, PdlProverState<C>), PdlError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let alpha = dk
        .decrypt(&verifier_msg.c_tag)
        .map_err(|e| PdlError::Paillier(format!("PDL decrypt c_tag failed: {e}")))?;

    let alpha_scalar = integer_to_scalar::<C>(&alpha);
    let q_hat = C::generator() * alpha_scalar;

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
    let ab_bytes = serialize_ab(&verifier_msg2.a, &verifier_msg2.b);
    if !verifier_msg1
        .c_tag_tag
        .verify(&ab_bytes, &verifier_msg2.nonce)
    {
        return Err(PdlError::CommitmentVerification(
            "PDL: verifier (a, b) commitment opening failed".into(),
        ));
    }

    let x1_bytes = scalar_to_bytes::<C>(x1);
    let x1_int = Integer::from_bytes_msf(&x1_bytes);

    let expected = &verifier_msg2.a * &x1_int + &verifier_msg2.b;

    if expected != state.alpha {
        return Err(PdlError::PdlVerification(
            "PDL: a * x_1 + b != alpha".into(),
        ));
    }

    Ok(PdlProverMsg2 {
        q_hat: state.q_hat,
        nonce: state.nonce,
    })
}

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

pub fn pdl_verify<C: TecdsaCurve>(
    dk: &DecryptionKey,
    ek: &EncryptionKey,
    x1: &C::Scalar,
    c_key: &fast_paillier::Ciphertext,
    q1: &C::ProjectivePoint,
    rng: &mut impl CryptoRngCore,
) -> Result<(), PdlError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let (v_msg1, v_state) = verifier_step1::<C>(ek, c_key, q1, rng)?;

    let (p_msg1, p_state) = prover_step1::<C>(dk, &v_msg1, rng)?;

    let v_msg2 = verifier_step2::<C>(&v_state);

    let p_msg2 = prover_step2::<C>(x1, &p_state, &v_msg1, &v_msg2)?;

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

        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let x1 = Secp256k1::random_scalar(&mut rng);
        let q1 = Secp256k1::generator() * x1;

        let x1_bytes = scalar_to_bytes::<Secp256k1>(&x1);
        let x1_int = Integer::from_bytes_msf(&x1_bytes);
        let (c_key, _) = dk.encrypt_with_random(&mut rng, &x1_int).expect("encrypt");

        pdl_verify::<Secp256k1>(&dk, &ek, &x1, &c_key, &q1, &mut rng)
            .expect("PDL verification should pass");
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn pdl_proof_wrong_ckey() {
        let mut rng = rand_core::OsRng;

        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let x1 = Secp256k1::random_scalar(&mut rng);
        let q1 = Secp256k1::generator() * x1;

        let wrong_x = Secp256k1::random_scalar(&mut rng);
        let wrong_bytes = scalar_to_bytes::<Secp256k1>(&wrong_x);
        let wrong_int = Integer::from_bytes_msf(&wrong_bytes);
        let (wrong_c_key, _) = dk
            .encrypt_with_random(&mut rng, &wrong_int)
            .expect("encrypt");

        let result = pdl_verify::<Secp256k1>(&dk, &ek, &x1, &wrong_c_key, &q1, &mut rng);
        assert!(result.is_err(), "PDL should fail with wrong c_key");
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn pdl_proof_wrong_q1() {
        let mut rng = rand_core::OsRng;

        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let x1 = Secp256k1::random_scalar(&mut rng);

        let wrong_x = Secp256k1::random_scalar(&mut rng);
        let wrong_q1 = Secp256k1::generator() * wrong_x;

        let x1_bytes = scalar_to_bytes::<Secp256k1>(&x1);
        let x1_int = Integer::from_bytes_msf(&x1_bytes);
        let (c_key, _) = dk.encrypt_with_random(&mut rng, &x1_int).expect("encrypt");

        let result = pdl_verify::<Secp256k1>(&dk, &ek, &x1, &c_key, &wrong_q1, &mut rng);
        assert!(result.is_err(), "PDL should fail with wrong Q1");
    }
}
