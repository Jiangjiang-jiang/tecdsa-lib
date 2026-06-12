use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::{
    backend::Integer,
    zk::{correct_key_ni::NICorrectKeyProof, pi_eq::PiEqProof},
};

use super::curve_order;
use crate::{
    error::Kgg24Error,
    key_share::{Kgg24Party1KeyShare, Kgg24Party2KeyShare},
};

const TAU: u32 = 256;

const KAPPA: u32 = 80;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP2Round1Msg {
    pub commitment: HashCommitment,
}

pub struct KeyGenP2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub x2: C::Scalar,
    pub x2_point: C::ProjectivePoint,
    pub dlog_proof: DlogProof<C>,
    pub nonce: [u8; 32],
}

pub fn party2_keygen_round1<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (KeyGenP2Round1Msg, KeyGenP2State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x2 = C::random_scalar(rng);
    let x2_point = C::generator() * x2;

    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x2, &ephemeral, &x2_point, b"kgg24-keygen-x2");

    let commit_data = serialize_point_and_proof::<C>(&x2_point, &dlog_proof);
    let (commitment, nonce) = HashCommitment::commit(&commit_data, rng);

    let msg = KeyGenP2Round1Msg { commitment };
    let state = KeyGenP2State {
        x2,
        x2_point,
        dlog_proof,
        nonce,
    };

    (msg, state)
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP1Round2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub x1_point: C::ProjectivePoint,
    pub dlog_proof: DlogProof<C>,
    pub c_key: tecdsa_paillier::Ciphertext,
    pub ek: tecdsa_paillier::EncryptionKey,
    pub pi_gcd: NICorrectKeyProof,
    pub pi_eq: PiEqProof<C>,
}

pub struct KeyGenP1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub x1: C::Scalar,
    pub x1_point: C::ProjectivePoint,
    pub dk: tecdsa_paillier::DecryptionKey,
}

pub fn party1_keygen_round2<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP1Round2Msg<C>, KeyGenP1State<C>), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let dk = tecdsa_paillier::keygen(rng)
        .map_err(|e| Kgg24Error::Paillier(format!("Paillier keygen failed: {e}")))?;

    party1_keygen_round2_with_dk::<C>(dk, rng)
}

pub fn party1_keygen_round2_with_dk<C: TecdsaCurve>(
    dk: tecdsa_paillier::DecryptionKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP1Round2Msg<C>, KeyGenP1State<C>), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1 = C::random_scalar(rng);
    let x1_point = C::generator() * x1;

    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x1, &ephemeral, &x1_point, b"kgg24-keygen-x1");

    let ek = dk.encryption_key().clone();

    let q_int = curve_order::<C>();

    let noise_bound = Integer::u_pow_u(2, TAU + 2 * KAPPA);
    let t = noise_bound.random_below_ref(rng);

    let x1_bytes = x1.to_repr();
    let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
    let x_hat_1 = &x1_int + &t * &q_int;

    let (c_key, enc_nonce) = dk.encrypt_with_random(rng, &x_hat_1).map_err(|e| {
        Kgg24Error::Paillier(format!("Paillier encryption of noised x1 failed: {e}"))
    })?;

    let pi_gcd = NICorrectKeyProof::prove(&dk, b"kgg24-correct-key-challenge");

    let ssid = b"kgg24-keygen";
    let pi_eq = PiEqProof::<C>::prove(ssid, &ek, &dk, &c_key, &x1_point, &x_hat_1, &enc_nonce, rng);

    let msg = KeyGenP1Round2Msg {
        x1_point,
        dlog_proof,
        c_key,
        ek,
        pi_gcd,
        pi_eq,
    };

    let state = KeyGenP1State { x1, x1_point, dk };

    Ok((msg, state))
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP2Round3Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub x2_point: C::ProjectivePoint,
    pub dlog_proof: DlogProof<C>,
    pub nonce: [u8; 32],
}

pub fn party2_keygen_round3<C: TecdsaCurve>(
    p2_state: &KeyGenP2State<C>,
    p1_msg: &KeyGenP1Round2Msg<C>,
) -> Result<KeyGenP2Round3Msg<C>, Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if !p1_msg
        .dlog_proof
        .verify(&p1_msg.x1_point, b"kgg24-keygen-x1")
    {
        return Err(Kgg24Error::DlogVerification(
            "Keygen: P1's DLog proof for X1 failed".into(),
        ));
    }

    if !p1_msg
        .pi_gcd
        .verify(&p1_msg.ek, b"kgg24-correct-key-challenge")
    {
        return Err(Kgg24Error::PiGcdVerification(
            "Keygen: Pi_GCD proof verification failed".into(),
        ));
    }

    let ssid = b"kgg24-keygen";
    if !p1_msg
        .pi_eq
        .verify(ssid, &p1_msg.ek, &p1_msg.c_key, &p1_msg.x1_point)
    {
        return Err(Kgg24Error::PiEqVerification(
            "Keygen: Pi_eq proof verification failed".into(),
        ));
    }

    Ok(KeyGenP2Round3Msg {
        x2_point: p2_state.x2_point,
        dlog_proof: p2_state.dlog_proof.clone(),
        nonce: p2_state.nonce,
    })
}

pub fn party1_verify_round3<C: TecdsaCurve>(
    p2_round1: &KeyGenP2Round1Msg,
    p2_round3: &KeyGenP2Round3Msg<C>,
) -> Result<(), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let commit_data = serialize_point_and_proof::<C>(&p2_round3.x2_point, &p2_round3.dlog_proof);
    if !p2_round1.commitment.verify(&commit_data, &p2_round3.nonce) {
        return Err(Kgg24Error::CommitmentVerification(
            "Keygen: P2's commitment to X2 failed to open".into(),
        ));
    }

    if !p2_round3
        .dlog_proof
        .verify(&p2_round3.x2_point, b"kgg24-keygen-x2")
    {
        return Err(Kgg24Error::DlogVerification(
            "Keygen: P2's DLog proof for X2 failed".into(),
        ));
    }

    Ok(())
}

pub fn party1_finalize_keygen<C: TecdsaCurve>(
    p1_state: KeyGenP1State<C>,
    x2_point: &C::ProjectivePoint,
) -> Kgg24Party1KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let public_key = p1_state.x1_point + x2_point;

    Kgg24Party1KeyShare {
        secret_share: p1_state.x1,
        public_key,
        dk: p1_state.dk,
    }
}

pub fn party2_finalize_keygen<C: TecdsaCurve>(
    p2_state: &KeyGenP2State<C>,
    p1_msg: &KeyGenP1Round2Msg<C>,
) -> Kgg24Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let public_key = p1_msg.x1_point + p2_state.x2_point;

    Kgg24Party2KeyShare {
        secret_share: p2_state.x2,
        public_key,
        c_key: p1_msg.c_key.clone(),
        ek: p1_msg.ek.clone(),
    }
}

pub fn interactive_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(Kgg24Party1KeyShare<C>, Kgg24Party2KeyShare<C>), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let (p2_r1_msg, p2_state) = party2_keygen_round1::<C>(rng);

    let (p1_r2_msg, p1_state) = party1_keygen_round2::<C>(rng)?;

    let p2_r3_msg = party2_keygen_round3::<C>(&p2_state, &p1_r2_msg)?;

    party1_verify_round3::<C>(&p2_r1_msg, &p2_r3_msg)?;

    let p2_share = party2_finalize_keygen::<C>(&p2_state, &p1_r2_msg);
    let p1_share = party1_finalize_keygen::<C>(p1_state, &p2_r3_msg.x2_point);

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
    fn interactive_keygen_paillier_encrypts_noised_x1() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        let decrypted = p1.dk.decrypt(&p2.c_key).expect("decryption failed");
        let x1_bytes = p1.secret_share.to_repr();
        let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());

        let q_int = curve_order::<Secp256k1>();
        let decrypted_mod_q = decrypted.modulo_ref(&q_int);
        assert_eq!(decrypted_mod_q, x1_int);
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

        let result = sign::sign(&p1_key, &p2_key, &message, &mut rng)
            .expect("signing should succeed with interactive keygen shares");

        verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &message)
            .expect("signature should verify");
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn round_by_round_keygen() {
        let mut rng = rand_core::OsRng;

        let (p2_r1_msg, p2_state) = party2_keygen_round1::<Secp256k1>(&mut rng);

        let (p1_r2_msg, p1_state) =
            party1_keygen_round2::<Secp256k1>(&mut rng).expect("P1 round 2 should succeed");

        let p2_r3_msg = party2_keygen_round3::<Secp256k1>(&p2_state, &p1_r2_msg)
            .expect("P2 round 3 should succeed (proofs valid)");

        party1_verify_round3::<Secp256k1>(&p2_r1_msg, &p2_r3_msg)
            .expect("P1 verification of P2's decommitment should succeed");

        let p2_share = party2_finalize_keygen::<Secp256k1>(&p2_state, &p1_r2_msg);
        let p1_share = party1_finalize_keygen::<Secp256k1>(p1_state, &p2_r3_msg.x2_point);

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
    fn interactive_keygen_refresh_then_sign() {
        use sha2::{Digest, Sha256};

        use crate::{refresh::refresh, sign};

        let mut rng = rand_core::OsRng;

        let (mut p1_key, mut p2_key) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        let original_pk = p1_key.public_key;

        refresh(&mut p1_key, &mut p2_key, &mut rng).expect("refresh should succeed");

        assert_eq!(p1_key.public_key, original_pk);
        assert_eq!(p2_key.public_key, original_pk);

        let hash = Sha256::digest(b"test interactive keygen -> refresh -> sign");
        let mut fb = elliptic_curve::FieldBytes::<Secp256k1>::default();
        let len = fb.len();
        fb.copy_from_slice(&hash[..len]);
        let scalar = Option::from(<k256::Scalar as elliptic_curve::PrimeField>::from_repr(fb))
            .expect("hash must be valid scalar");
        let message = DataToSign::from_digest(scalar);

        let result = sign::sign(&p1_key, &p2_key, &message, &mut rng)
            .expect("signing after refresh should succeed");

        verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &message)
            .expect("signature should verify after interactive keygen + refresh");
    }
}
