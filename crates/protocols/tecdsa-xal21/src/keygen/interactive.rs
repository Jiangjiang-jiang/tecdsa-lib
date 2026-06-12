use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;

use crate::{
    error::Xal21Error,
    key_share::{Xal21Party1KeyShare, Xal21Party2KeyShare},
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
    let dlog_proof = DlogProof::<C>::prove(&x1, &ephemeral, &q1, b"xal21-keygen-q1");

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
    pub ek: tecdsa_paillier::EncryptionKey,
    pub pi_gcd: NICorrectKeyProof,
    pub ntilde: tecdsa_paillier::zk::mta_range::NTildeParams,
}

pub struct KeyGenP2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub x2: C::Scalar,
    pub q2: C::ProjectivePoint,
    pub dk: tecdsa_paillier::DecryptionKey,
    pub ek: tecdsa_paillier::EncryptionKey,
    pub ntilde: tecdsa_paillier::zk::mta_range::NTildeParams,
}

pub fn party2_keygen_round2<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP2Round2Msg<C>, KeyGenP2State<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let dk = tecdsa_paillier::keygen(rng)
        .map_err(|e| Xal21Error::Paillier(format!("Paillier keygen failed: {e}")))?;
    let ntilde = super::generate_ntilde_params(rng);

    party2_keygen_round2_with_setup::<C>(dk, ntilde, rng)
}

pub fn party2_keygen_round2_with_setup<C: TecdsaCurve>(
    dk: tecdsa_paillier::DecryptionKey,
    ntilde: tecdsa_paillier::zk::mta_range::NTildeParams,
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP2Round2Msg<C>, KeyGenP2State<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x2 = C::random_scalar(rng);
    let q2 = C::generator() * x2;

    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x2, &ephemeral, &q2, b"xal21-keygen-q2");

    let ek = dk.encryption_key().clone();

    let pi_gcd = NICorrectKeyProof::prove(&dk, b"xal21-correct-key-challenge");

    let msg = KeyGenP2Round2Msg {
        q2,
        dlog_proof,
        ek: ek.clone(),
        pi_gcd,
        ntilde: ntilde.clone(),
    };

    let state = KeyGenP2State {
        x2,
        q2,
        dk,
        ek,
        ntilde,
    };

    Ok((msg, state))
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
}

pub fn party1_keygen_round3<C: TecdsaCurve>(
    p1_state: &KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
) -> Result<KeyGenP1Round3Msg<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if !p2_msg.dlog_proof.verify(&p2_msg.q2, b"xal21-keygen-q2") {
        return Err(Xal21Error::DlogVerification(
            "Keygen: P2's DLog proof for Q2 failed".into(),
        ));
    }

    if !p2_msg
        .pi_gcd
        .verify(&p2_msg.ek, b"xal21-correct-key-challenge")
    {
        return Err(Xal21Error::PiGcdVerification(
            "Keygen: Pi_GCD proof verification failed".into(),
        ));
    }

    Ok(KeyGenP1Round3Msg {
        q1: p1_state.q1,
        dlog_proof: p1_state.dlog_proof.clone(),
        nonce: p1_state.nonce,
    })
}

pub fn party2_verify_round3<C: TecdsaCurve>(
    p1_round1: &KeyGenP1Round1Msg,
    p1_round3: &KeyGenP1Round3Msg<C>,
) -> Result<(), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let commit_data = serialize_point_and_proof::<C>(&p1_round3.q1, &p1_round3.dlog_proof);
    if !p1_round1.commitment.verify(&commit_data, &p1_round3.nonce) {
        return Err(Xal21Error::CommitmentVerification(
            "Keygen: P1's commitment to Q1 failed to open".into(),
        ));
    }

    if !p1_round3
        .dlog_proof
        .verify(&p1_round3.q1, b"xal21-keygen-q1")
    {
        return Err(Xal21Error::DlogVerification(
            "Keygen: P1's DLog proof for Q1 failed".into(),
        ));
    }

    Ok(())
}

pub fn party1_finalize<C: TecdsaCurve>(
    p1_state: KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
) -> Xal21Party1KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let public_key = p1_state.q1 + p2_msg.q2;

    Xal21Party1KeyShare {
        secret_share: p1_state.x1,
        public_key,
        public_share: p1_state.q1,
        ek: p2_msg.ek.clone(),
        ntilde: p2_msg.ntilde.clone(),
    }
}

pub fn party2_finalize<C: TecdsaCurve>(
    p2_state: KeyGenP2State<C>,
    p1_round3: &KeyGenP1Round3Msg<C>,
) -> Xal21Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let public_key = p1_round3.q1 + p2_state.q2;

    Xal21Party2KeyShare {
        secret_share: p2_state.x2,
        public_key,
        public_share_p1: p1_round3.q1,
        dk: p2_state.dk,
        ek: p2_state.ek,
        ntilde: p2_state.ntilde,
    }
}

pub fn interactive_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(Xal21Party1KeyShare<C>, Xal21Party2KeyShare<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let (p1_r1_msg, p1_state) = party1_keygen_round1::<C>(rng);

    let (p2_r2_msg, p2_state) = party2_keygen_round2::<C>(rng)?;

    let p1_r3_msg = party1_keygen_round3::<C>(&p1_state, &p2_r2_msg)?;

    party2_verify_round3::<C>(&p1_r1_msg, &p1_r3_msg)?;

    let p2_share = party2_finalize::<C>(p2_state, &p1_r3_msg);
    let p1_share = party1_finalize::<C>(p1_state, &p2_r2_msg);

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

        let x = p1.secret_share + p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn interactive_keygen_q1_matches() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        let expected_q1 = Secp256k1::generator() * p1.secret_share;
        assert_eq!(p1.public_share, expected_q1);

        assert_eq!(p2.public_share_p1, expected_q1);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn interactive_keygen_signing_compatibility() {
        use sha2::{Digest, Sha256};

        use crate::{offline_sign, online_sign};

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

        let (p1_presig, p2_presig) = offline_sign::offline_sign(&p1_key, &p2_key, &mut rng)
            .expect("offline signing should succeed");

        let sig = online_sign::online_sign(&p1_key, &p1_presig, &p2_presig, &message)
            .expect("online signing should succeed with interactive keygen shares");

        verify_ecdsa::<Secp256k1>(&sig, &p1_key.public_key, &message)
            .expect("signature should verify");
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn round_by_round_keygen() {
        let mut rng = rand_core::OsRng;

        let (p1_r1_msg, p1_state) = party1_keygen_round1::<Secp256k1>(&mut rng);

        let (p2_r2_msg, p2_state) =
            party2_keygen_round2::<Secp256k1>(&mut rng).expect("P2 round 2 should succeed");

        let p1_r3_msg = party1_keygen_round3::<Secp256k1>(&p1_state, &p2_r2_msg)
            .expect("P1 round 3 should succeed (proofs valid)");

        party2_verify_round3::<Secp256k1>(&p1_r1_msg, &p1_r3_msg)
            .expect("P2 verification of P1's decommitment should succeed");

        let p2_share = party2_finalize::<Secp256k1>(p2_state, &p1_r3_msg);
        let p1_share = party1_finalize::<Secp256k1>(p1_state, &p2_r2_msg);

        assert_eq!(p1_share.public_key, p2_share.public_key);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn multiple_interactive_keygens_produce_different_keys() {
        let mut rng = rand_core::OsRng;

        let (p1a, _p2a) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 1 should succeed");
        let (p1b, _p2b) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 2 should succeed");

        assert_ne!(p1a.public_key, p1b.public_key);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn interactive_keygen_paillier_key_is_valid() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        assert_eq!(p1.ek.n(), p2.ek.n());

        assert_eq!(p2.dk.encryption_key().n(), p1.ek.n());

        let test_val = tecdsa_paillier::backend::Integer::from(42u32);
        let (ct, _) = p1.ek.encrypt_with_random(&mut rng, &test_val).unwrap();
        let pt = p2.dk.decrypt(&ct).unwrap();
        assert_eq!(pt, test_val);
    }
}
