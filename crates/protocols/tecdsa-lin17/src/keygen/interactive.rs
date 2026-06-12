use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{conv::scalar_to_bytes, zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::{
    backend::Integer,
    zk::{correct_key_ni::NICorrectKeyProof, pdl, range_ni::RangeProofNi},
};

use crate::{
    error::Lin17Error,
    key_share::{Lin17Party1KeyShare, Lin17Party2KeyShare},
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP1Round1Msg {
    pub commitment: HashCommitment,
}

pub struct KeyGenP1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub x1: C::Scalar,
    pub q1: C::ProjectivePoint,
    pub dlog_proof: DlogProof<C>,
    pub nonce: [u8; 32],
}

pub fn party1_keygen_round1<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (KeyGenP1Round1Msg, KeyGenP1State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1 = C::random_scalar(rng);
    let q1 = C::generator() * x1;

    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x1, &ephemeral, &q1, b"lin17-keygen-q1");

    let commit_data = serialize_point_and_proof::<C>(&q1, &dlog_proof);
    let (commitment, nonce) = HashCommitment::commit(&commit_data, rng);

    let msg = KeyGenP1Round1Msg { commitment };
    let state = KeyGenP1State {
        x1,
        q1,
        dlog_proof,
        nonce,
    };

    (msg, state)
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP2Round2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub q2: C::ProjectivePoint,
    pub dlog_proof: DlogProof<C>,
}

pub struct KeyGenP2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub x2: C::Scalar,
    pub q2: C::ProjectivePoint,
}

pub fn party2_keygen_round2<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (KeyGenP2Round2Msg<C>, KeyGenP2State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x2 = C::random_scalar(rng);
    let q2 = C::generator() * x2;

    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x2, &ephemeral, &q2, b"lin17-keygen-q2");

    let msg = KeyGenP2Round2Msg { q2, dlog_proof };
    let state = KeyGenP2State { x2, q2 };

    (msg, state)
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP1Round3Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub q1: C::ProjectivePoint,
    pub dlog_proof: DlogProof<C>,
    pub nonce: [u8; 32],
    pub ek: tecdsa_paillier::EncryptionKey,
    pub c_key: tecdsa_paillier::Ciphertext,
    pub c_key_nonce: Integer,
    pub correct_key_proof: NICorrectKeyProof,
    pub range_proof: RangeProofNi,
}

pub fn party1_keygen_round3<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<KeyGenP1Round3Msg<C>, Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if !p2_msg.dlog_proof.verify(&p2_msg.q2, b"lin17-keygen-q2") {
        return Err(Lin17Error::DlogVerification(
            "Keygen: P2's DLog proof for Q_2 failed".into(),
        ));
    }

    let dk = tecdsa_paillier::keygen(rng)
        .map_err(|e| Lin17Error::Paillier(format!("Paillier keygen failed: {e}")))?;
    let ek = dk.encryption_key().clone();

    let x1_bytes = state.x1.to_repr();
    let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
    let (c_key, c_key_nonce) = dk
        .encrypt_with_random(rng, &x1_int)
        .map_err(|e| Lin17Error::Paillier(format!("encrypt x_1 failed: {e}")))?;

    let correct_key_proof = NICorrectKeyProof::prove(&dk, b"lin17-correct-key-challenge");

    let q_bytes = scalar_to_bytes::<C>(&(-C::Scalar::ONE));
    let q_int = Integer::from_bytes_msf(&q_bytes) + 1u8;
    let range_proof = RangeProofNi::prove(&dk, &ek, &c_key, &x1_int, &c_key_nonce, &q_int, rng)?;

    Ok(KeyGenP1Round3Msg {
        q1: state.q1,
        dlog_proof: state.dlog_proof.clone(),
        nonce: state.nonce,
        ek,
        c_key,
        c_key_nonce,
        correct_key_proof,
        range_proof,
    })
}

pub fn party1_keygen_round3_with_dk<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP1Round3Msg<C>, tecdsa_paillier::DecryptionKey), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if !p2_msg.dlog_proof.verify(&p2_msg.q2, b"lin17-keygen-q2") {
        return Err(Lin17Error::DlogVerification(
            "Keygen: P2's DLog proof for Q_2 failed".into(),
        ));
    }

    let dk = tecdsa_paillier::keygen(rng)
        .map_err(|e| Lin17Error::Paillier(format!("Paillier keygen failed: {e}")))?;

    party1_keygen_round3_core::<C>(state, dk, rng)
}

pub fn party1_keygen_round3_with_precomputed_dk<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
    dk: tecdsa_paillier::DecryptionKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP1Round3Msg<C>, tecdsa_paillier::DecryptionKey), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if !p2_msg.dlog_proof.verify(&p2_msg.q2, b"lin17-keygen-q2") {
        return Err(Lin17Error::DlogVerification(
            "Keygen: P2's DLog proof for Q_2 failed".into(),
        ));
    }

    party1_keygen_round3_core::<C>(state, dk, rng)
}

fn party1_keygen_round3_core<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    dk: tecdsa_paillier::DecryptionKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP1Round3Msg<C>, tecdsa_paillier::DecryptionKey), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let ek = dk.encryption_key().clone();

    let x1_bytes = state.x1.to_repr();
    let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
    let (c_key, c_key_nonce) = dk
        .encrypt_with_random(rng, &x1_int)
        .map_err(|e| Lin17Error::Paillier(format!("encrypt x_1 failed: {e}")))?;

    let correct_key_proof = NICorrectKeyProof::prove(&dk, b"lin17-correct-key-challenge");

    let q_bytes = scalar_to_bytes::<C>(&(-C::Scalar::ONE));
    let q_int = Integer::from_bytes_msf(&q_bytes) + 1u8;
    let range_proof = RangeProofNi::prove(&dk, &ek, &c_key, &x1_int, &c_key_nonce, &q_int, rng)?;

    let msg = KeyGenP1Round3Msg {
        q1: state.q1,
        dlog_proof: state.dlog_proof.clone(),
        nonce: state.nonce,
        ek,
        c_key,
        c_key_nonce,
        correct_key_proof,
        range_proof,
    };

    Ok((msg, dk))
}

pub fn party2_verify_round3<C: TecdsaCurve>(
    _p2_state: &KeyGenP2State<C>,
    p1_round1: &KeyGenP1Round1Msg,
    p1_round3: &KeyGenP1Round3Msg<C>,
) -> Result<(), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let commit_data = serialize_point_and_proof::<C>(&p1_round3.q1, &p1_round3.dlog_proof);
    if !p1_round1.commitment.verify(&commit_data, &p1_round3.nonce) {
        return Err(Lin17Error::CommitmentVerification(
            "Keygen: P1's commitment to Q_1 failed to open".into(),
        ));
    }

    if !p1_round3
        .dlog_proof
        .verify(&p1_round3.q1, b"lin17-keygen-q1")
    {
        return Err(Lin17Error::DlogVerification(
            "Keygen: P1's DLog proof for Q_1 failed".into(),
        ));
    }

    let nn = p1_round3.ek.nn();
    if !p1_round3.c_key.in_mult_group_of(nn) {
        return Err(Lin17Error::CiphertextValidation(
            "Keygen: c_key not in Z*_{N^2}".into(),
        ));
    }

    if !p1_round3
        .correct_key_proof
        .verify(&p1_round3.ek, b"lin17-correct-key-challenge")
    {
        return Err(Lin17Error::CorrectKeyVerification(
            "Keygen: NICorrectKeyProof verification failed".into(),
        ));
    }

    let q_bytes = scalar_to_bytes::<C>(&(-C::Scalar::ONE));
    let q_int = Integer::from_bytes_msf(&q_bytes) + 1u8;
    if !p1_round3
        .range_proof
        .verify(&p1_round3.ek, &p1_round3.c_key, &q_int)
    {
        return Err(Lin17Error::RangeProofVerification(
            "Keygen: range proof verification failed".into(),
        ));
    }

    Ok(())
}

pub fn party1_finalize_keygen<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    p2_q2: &C::ProjectivePoint,
    dk: tecdsa_paillier::DecryptionKey,
) -> Lin17Party1KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let public_key = *p2_q2 * state.x1;

    Lin17Party1KeyShare {
        secret_share: state.x1,
        public_key,
        dk,
    }
}

pub fn party2_finalize_keygen<C: TecdsaCurve>(
    state: &KeyGenP2State<C>,
    p1_q1: &C::ProjectivePoint,
    c_key: tecdsa_paillier::Ciphertext,
    ek: tecdsa_paillier::EncryptionKey,
) -> Lin17Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let public_key = *p1_q1 * state.x2;

    Lin17Party2KeyShare {
        secret_share: state.x2,
        public_key,
        c_key,
        ek,
    }
}

pub fn interactive_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(Lin17Party1KeyShare<C>, Lin17Party2KeyShare<C>), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let (p1_r1_msg, p1_state) = party1_keygen_round1::<C>(rng);

    let (p2_r2_msg, p2_state) = party2_keygen_round2::<C>(rng);

    let (p1_r3_msg, dk) = party1_keygen_round3_with_dk::<C>(&p1_state, &p2_r2_msg, rng)?;

    party2_verify_round3::<C>(&p2_state, &p1_r1_msg, &p1_r3_msg)?;

    pdl::pdl_verify::<C>(
        &dk,
        &p1_r3_msg.ek,
        &p1_state.x1,
        &p1_r3_msg.c_key,
        &p1_r3_msg.q1,
        rng,
    )?;

    let p1_share = party1_finalize_keygen::<C>(&p1_state, &p2_r2_msg.q2, dk);
    let p2_share =
        party2_finalize_keygen::<C>(&p2_state, &p1_r3_msg.q1, p1_r3_msg.c_key, p1_r3_msg.ek);

    debug_assert_eq!(p1_share.public_key, p2_share.public_key);

    Ok((p1_share, p2_share))
}

fn serialize_point_and_proof<C: TecdsaCurve>(
    point: &C::ProjectivePoint,
    proof: &DlogProof<C>,
) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut data = Vec::new();
    data.extend_from_slice(point.to_bytes().as_ref());
    data.extend_from_slice(proof.commitment.to_bytes().as_ref());
    data.extend_from_slice(proof.response.to_repr().as_ref());
    data
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;
    use tecdsa_protocol::{verify_ecdsa, DataToSign};

    use super::*;

    #[test]
    fn interactive_keygen_produces_consistent_shares() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        assert_eq!(p1.public_key, p2.public_key);

        let x = p1.secret_share * p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    fn interactive_keygen_paillier_encrypts_x1() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        let decrypted = p1.dk.decrypt(&p2.c_key).expect("decryption failed");
        let x1_bytes = p1.secret_share.to_repr();
        let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
        assert_eq!(decrypted, x1_int);
    }

    #[test]
    fn interactive_keygen_signing_compatibility() {
        use sha2::{Digest, Sha256};

        use crate::sign;

        let mut rng = rand_core::OsRng;

        let (p1_key, p2_key) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        let hash = Sha256::digest(b"test interactive keygen -> sign");
        let mut fb = elliptic_curve::FieldBytes::<Secp256k1>::default();
        let len = fb.len();
        fb.copy_from_slice(&hash[..len]);
        let scalar = Option::from(<k256::Scalar as elliptic_curve::PrimeField>::from_repr(fb))
            .expect("hash must be valid scalar");
        let message = DataToSign::from_digest(scalar);

        let signature = sign::sign(&p1_key, &p2_key, &message, &mut rng)
            .expect("signing should succeed with interactive keygen shares");

        verify_ecdsa::<Secp256k1>(&signature, &p1_key.public_key, &message)
            .expect("signature should verify");
    }

    #[test]
    fn round_by_round_keygen() {
        let mut rng = rand_core::OsRng;

        let (p1_r1_msg, p1_state) = party1_keygen_round1::<Secp256k1>(&mut rng);

        let (p2_r2_msg, p2_state) = party2_keygen_round2::<Secp256k1>(&mut rng);

        let (p1_r3_msg, dk) =
            party1_keygen_round3_with_dk::<Secp256k1>(&p1_state, &p2_r2_msg, &mut rng)
                .expect("P1 round 3 should succeed");

        party2_verify_round3::<Secp256k1>(&p2_state, &p1_r1_msg, &p1_r3_msg)
            .expect("P2 verification of P1's round 3 should succeed");

        pdl::pdl_verify::<Secp256k1>(
            &dk,
            &p1_r3_msg.ek,
            &p1_state.x1,
            &p1_r3_msg.c_key,
            &p1_r3_msg.q1,
            &mut rng,
        )
        .expect("PDL verification should pass");

        let p1_share = party1_finalize_keygen::<Secp256k1>(&p1_state, &p2_r2_msg.q2, dk);
        let p2_share = party2_finalize_keygen::<Secp256k1>(
            &p2_state,
            &p1_r3_msg.q1,
            p1_r3_msg.c_key,
            p1_r3_msg.ek,
        );

        assert_eq!(p1_share.public_key, p2_share.public_key);
    }

    #[test]
    fn multiple_interactive_keygens_produce_different_keys() {
        let mut rng = rand_core::OsRng;

        let (p1a, _p2a) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 1 should succeed");
        let (p1b, _p2b) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 2 should succeed");

        assert_ne!(p1a.public_key, p1b.public_key);
    }
}
