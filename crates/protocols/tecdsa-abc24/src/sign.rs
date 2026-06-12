use elliptic_curve::{
    group::Curve as CurveGroup, ops::LinearCombination, sec1::ModulusSize, Field, FieldBytes,
    FieldBytesSize, Group, PrimeField,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    error::Abc24Error,
    key_share::{Abc24ClientKeyShare, Abc24ServerKeyShare},
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerRound1Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub r2: C::ProjectivePoint,
    pub y: C::ProjectivePoint,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClientRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub r1: C::ProjectivePoint,
    pub r_point: C::ProjectivePoint,
    pub s_ct: tecdsa_paillier::Ciphertext,
}

fn random_oracle<C: TecdsaCurve>(
    public_key: &C::ProjectivePoint,
    r1: &C::ProjectivePoint,
    r: &C::ProjectivePoint,
    message_digest: &C::Scalar,
) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::group::GroupEncoding;
    let mut hasher = Sha256::new();
    hasher.update(b"ABC24-RO");
    hasher.update(public_key.to_bytes().as_ref());
    hasher.update(r1.to_bytes().as_ref());
    hasher.update(r.to_bytes().as_ref());
    hasher.update(AsRef::<[u8]>::as_ref(&message_digest.to_repr()));
    let hash = hasher.finalize();

    let mut fb = FieldBytes::<C>::default();
    let fb_len = fb.len();
    let hash_len = hash.len().min(fb_len);
    fb[fb_len - hash_len..].copy_from_slice(&hash[..hash_len]);
    Option::from(<C::Scalar as PrimeField>::from_repr(fb)).unwrap_or(C::Scalar::ONE)
}

pub struct ServerSignState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub k2: C::Scalar,
    pub r2: C::ProjectivePoint,
}

impl<C: TecdsaCurve> zeroize::Zeroize for ServerSignState<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k2.zeroize();
    }
}

impl<C: TecdsaCurve> Drop for ServerSignState<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

pub fn server_round1<C: TecdsaCurve>(
    key_share: &Abc24ServerKeyShare<C>,
    rng: &mut impl CryptoRngCore,
) -> (ServerRound1Msg<C>, ServerSignState<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k2 = C::random_scalar(rng);
    let r2 = C::generator() * k2;
    let y = key_share.client_public_share * k2;

    let msg = ServerRound1Msg { r2, y };
    let state = ServerSignState { k2, r2 };

    (msg, state)
}

pub fn server_finalize<C: TecdsaCurve>(
    key_share: &Abc24ServerKeyShare<C>,
    state: &ServerSignState<C>,
    client_msg: &ClientRound2Msg<C>,
    message: &DataToSign<C>,
) -> Result<Signature<C>, Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    let m = *message.digest();

    if bool::from(client_msg.r1.is_identity()) {
        return Err(Abc24Error::InvalidInput("R_1 is identity".into()));
    }

    let expected_r = client_msg.r1 * state.k2;
    if expected_r != client_msg.r_point {
        return Err(Abc24Error::DhTupleCheck(
            "R != R_1^{k_2}: DH consistency failed".into(),
        ));
    }

    let mu = random_oracle::<C>(
        &key_share.public_key,
        &client_msg.r1,
        &client_msg.r_point,
        &m,
    );

    let k2_plus_mu = state.k2 + mu;
    let r_combined = client_msg.r1 * k2_plus_mu;
    let r_affine = r_combined.to_affine();
    let r = C::xcoord_mod_q(&r_affine);

    let decrypted = key_share
        .dk
        .decrypt(&client_msg.s_ct)
        .map_err(|e| Abc24Error::Paillier(format!("decryption failed: {e}")))?;

    let dec_bytes = decrypted.to_bytes_msf();
    let sigma_raw = bytes_to_scalar::<C>(&dec_bytes);

    let k2_mu_inv = k2_plus_mu
        .invert()
        .into_option()
        .ok_or_else(|| Abc24Error::ProtocolState("k_2 + mu is zero".into()))?;
    let sigma = sigma_raw * k2_mu_inv;

    let s = low_s_normalize::<C>(sigma);
    let signature = Signature { r, s };

    verify_ecdsa::<C>(&signature, &key_share.public_key, message).map_err(|e| {
        Abc24Error::EcdsaVerification(format!("final signature verification failed: {e}"))
    })?;

    Ok(signature)
}

pub fn client_round2<C: TecdsaCurve>(
    key_share: &Abc24ClientKeyShare<C>,
    server_msg: &ServerRound1Msg<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<ClientRound2Msg<C>, Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let m = *message.digest();

    if bool::from(server_msg.r2.is_identity()) {
        return Err(Abc24Error::InvalidInput("R_2 is identity".into()));
    }

    let expected_y = server_msg.r2 * key_share.secret_share;
    if expected_y != server_msg.y {
        return Err(Abc24Error::DhTupleCheck(
            "R_2^{x_1} != Y: server DH consistency failed".into(),
        ));
    }

    let k1 = C::random_scalar(rng);
    let r1 = C::generator() * k1;
    let r_point = server_msg.r2 * k1;

    let mu = random_oracle::<C>(&key_share.public_key, &r1, &r_point, &m);

    let r_combined = (server_msg.r2 + C::generator() * mu) * k1;
    let r_affine = r_combined.to_affine();
    let r = C::xcoord_mod_q(&r_affine);

    let k1_inv = k1
        .invert()
        .into_option()
        .ok_or_else(|| Abc24Error::ProtocolState("k_1 is zero".into()))?;

    let q_bytes = scalar_to_bytes::<C>(&(-C::Scalar::ONE));
    let q_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&q_bytes) + 1u8;

    let k1_inv_m_rx1 = k1_inv * (m + r * key_share.secret_share);
    let u_base_bytes = scalar_to_bytes::<C>(&k1_inv_m_rx1);
    let u_base = tecdsa_paillier::backend::Integer::from_bytes_msf(&u_base_bytes);

    let mu_mask = q_int.random_below_ref(rng);
    let u = &u_base + &mu_mask * &q_int;

    let k1_inv_r = k1_inv * r;
    let v_base_bytes = scalar_to_bytes::<C>(&k1_inv_r);
    let v_base = tecdsa_paillier::backend::Integer::from_bytes_msf(&v_base_bytes);

    let mu_prime_mask = q_int.random_below_ref(rng);
    let v = &v_base + &mu_prime_mask * &q_int;

    let (enc_u, _nonce_u) = key_share
        .ek
        .encrypt_with_random(rng, &u)
        .map_err(|e| Abc24Error::Paillier(format!("encrypt u failed: {e}")))?;

    let e_v = key_share
        .ek
        .omul(&v, &key_share.enc_x2)
        .map_err(|e| Abc24Error::Paillier(format!("homomorphic scalar mult E^v failed: {e}")))?;

    let s_ct = key_share
        .ek
        .oadd(&enc_u, &e_v)
        .map_err(|e| Abc24Error::Paillier(format!("homomorphic add failed: {e}")))?;

    Ok(ClientRound2Msg { r1, r_point, s_ct })
}

use tecdsa_curve::conv::{bytes_to_scalar, scalar_to_bytes};

pub fn sign<C: TecdsaCurve>(
    server_key: &Abc24ServerKeyShare<C>,
    client_key: &Abc24ClientKeyShare<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Signature<C>, Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    let (server_msg, server_state) = server_round1::<C>(server_key, rng);

    let client_msg = client_round2::<C>(client_key, &server_msg, message, rng)?;

    server_finalize::<C>(server_key, &server_state, &client_msg, message)
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;
    use sha2::Sha256;
    use tecdsa_protocol::DataToSign;

    use super::*;
    use crate::keygen::trusted_dealer_keygen;

    fn make_message(msg: &[u8]) -> DataToSign<Secp256k1> {
        use elliptic_curve::PrimeField;
        use sha2::Digest;
        let hash = Sha256::digest(msg);
        let mut fb = k256::FieldBytes::default();
        fb.copy_from_slice(&hash);
        let scalar = k256::Scalar::from_repr(fb).unwrap();
        DataToSign::from_digest(scalar)
    }

    #[test]
    fn sign_produces_valid_ecdsa_signature() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
        let message = make_message(b"hello ABC+24");

        let sig = sign::<Secp256k1>(&server, &client, &message, &mut rng)
            .expect("signing should succeed");

        verify_ecdsa::<Secp256k1>(&sig, &server.public_key, &message)
            .expect("signature must verify");
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn sign_different_messages_produce_different_signatures() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let msg1 = make_message(b"message one");
        let msg2 = make_message(b"message two");

        let sig1 = sign::<Secp256k1>(&server, &client, &msg1, &mut rng).unwrap();
        let sig2 = sign::<Secp256k1>(&server, &client, &msg2, &mut rng).unwrap();

        assert_ne!(sig1.r, sig2.r);
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn sign_multiple_times_with_same_key() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        for i in 0..3 {
            let msg = make_message(format!("message {i}").as_bytes());
            let sig = sign::<Secp256k1>(&server, &client, &msg, &mut rng)
                .expect("signing should succeed");
            verify_ecdsa::<Secp256k1>(&sig, &server.public_key, &msg)
                .expect("signature must verify");
        }
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn server_round1_dh_consistency() {
        let mut rng = rand_core::OsRng;
        let (server, _client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let (msg, state) = server_round1::<Secp256k1>(&server, &mut rng);

        let expected_y = server.client_public_share * state.k2;
        assert_eq!(msg.y, expected_y);
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn client_rejects_bad_dh_tuple() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
        let message = make_message(b"test");

        let (mut server_msg, _state) = server_round1::<Secp256k1>(&server, &mut rng);

        server_msg.y = Secp256k1::generator() * k256::Scalar::from(42u64);

        let result = client_round2::<Secp256k1>(&client, &server_msg, &message, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "redundant sign variant"]
    fn server_rejects_bad_dh_tuple() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
        let message = make_message(b"test");

        let (server_msg, server_state) = server_round1::<Secp256k1>(&server, &mut rng);
        let mut client_msg =
            client_round2::<Secp256k1>(&client, &server_msg, &message, &mut rng).unwrap();

        client_msg.r_point = Secp256k1::generator() * k256::Scalar::from(99u64);

        let result = server_finalize::<Secp256k1>(&server, &server_state, &client_msg, &message);
        assert!(result.is_err());
    }

    #[test]
    fn signature_is_low_s() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
        let message = make_message(b"low-s test");

        let sig = sign::<Secp256k1>(&server, &client, &message, &mut rng).unwrap();

        verify_ecdsa::<Secp256k1>(&sig, &server.public_key, &message)
            .expect("low-s signature must verify");
    }
}
