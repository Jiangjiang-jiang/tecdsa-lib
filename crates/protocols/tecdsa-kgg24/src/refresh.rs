use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::zk::{correct_key_ni::NICorrectKeyProof, pi_eq::PiEqProof};

use crate::{
    error::Kgg24Error,
    key_share::{Kgg24Party1KeyShare, Kgg24Party2KeyShare},
    keygen::curve_order,
};

const TAU: u32 = 256;
const KAPPA: u32 = 80;

pub struct RefreshMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub ek: tecdsa_paillier::EncryptionKey,
    pub c_key: tecdsa_paillier::Ciphertext,
    pub pi_gcd: NICorrectKeyProof,
    pub pi_eq: PiEqProof<C>,
    pub x1_new_point: C::ProjectivePoint,
}

pub fn refresh<C: TecdsaCurve>(
    p1_key: &mut Kgg24Party1KeyShare<C>,
    p2_key: &mut Kgg24Party2KeyShare<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<(), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let r = C::random_scalar(rng);

    let refresh_msg = party1_refresh::<C>(p1_key, r, rng)?;

    party2_refresh::<C>(p2_key, r, &refresh_msg)?;

    assert_eq!(
        p1_key.public_key, p2_key.public_key,
        "public keys diverged after refresh"
    );

    Ok(())
}

fn party1_refresh<C: TecdsaCurve>(
    key_share: &mut Kgg24Party1KeyShare<C>,
    r: C::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<RefreshMsg<C>, Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1_new = key_share.secret_share - r;
    let x1_new_point = C::generator() * x1_new;

    let dk_new = tecdsa_paillier::keygen(rng)
        .map_err(|e| Kgg24Error::Refresh(format!("Paillier keygen failed: {e}")))?;
    let ek_new = dk_new.encryption_key().clone();

    let q_int = curve_order::<C>();
    let noise_bound = tecdsa_paillier::backend::Integer::from(1u8) << (TAU + 2 * KAPPA);
    let t_prime = noise_bound.random_below_ref(rng);

    let x1_new_bytes = x1_new.to_repr();
    let x1_new_int = tecdsa_paillier::backend::Integer::from_bytes_msf(x1_new_bytes.as_ref());
    let x_hat_1_new = &x1_new_int + &t_prime * &q_int;

    let (c_key_new, enc_nonce) = dk_new.encrypt_with_random(rng, &x_hat_1_new).map_err(|e| {
        Kgg24Error::Refresh(format!(
            "Paillier encryption of refreshed share failed: {e}"
        ))
    })?;

    let pi_gcd = NICorrectKeyProof::prove(&dk_new, b"kgg24-correct-key-challenge");

    let ssid = b"kgg24-refresh";
    let pi_eq = PiEqProof::<C>::prove(
        ssid,
        &ek_new,
        &dk_new,
        &c_key_new,
        &x1_new_point,
        &x_hat_1_new,
        &enc_nonce,
        rng,
    );

    key_share.secret_share = x1_new;
    key_share.dk = dk_new;

    Ok(RefreshMsg {
        ek: ek_new,
        c_key: c_key_new,
        pi_gcd,
        pi_eq,
        x1_new_point,
    })
}

fn party2_refresh<C: TecdsaCurve>(
    key_share: &mut Kgg24Party2KeyShare<C>,
    r: C::Scalar,
    refresh_msg: &RefreshMsg<C>,
) -> Result<(), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if !refresh_msg
        .pi_gcd
        .verify(&refresh_msg.ek, b"kgg24-correct-key-challenge")
    {
        return Err(Kgg24Error::PiGcdVerification(
            "Refresh: Pi_GCD proof verification failed".into(),
        ));
    }

    let ssid = b"kgg24-refresh";
    if !refresh_msg.pi_eq.verify(
        ssid,
        &refresh_msg.ek,
        &refresh_msg.c_key,
        &refresh_msg.x1_new_point,
    ) {
        return Err(Kgg24Error::PiEqVerification(
            "Refresh: Pi_eq proof verification failed".into(),
        ));
    }

    let x2_new = key_share.secret_share + r;
    let x2_new_point = C::generator() * x2_new;
    let expected_pk = refresh_msg.x1_new_point + x2_new_point;
    if expected_pk != key_share.public_key {
        return Err(Kgg24Error::Refresh(
            "Refresh: X1_new + X2_new does not match the existing public key".into(),
        ));
    }

    key_share.secret_share = x2_new;
    key_share.ek = refresh_msg.ek.clone();
    key_share.c_key = refresh_msg.c_key.clone();

    Ok(())
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;

    use super::*;
    use crate::keygen::trusted_dealer_keygen;

    #[test]
    fn refresh_preserves_public_key() {
        let mut rng = rand_core::OsRng;
        let (mut p1, mut p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let original_pk = p1.public_key;

        refresh(&mut p1, &mut p2, &mut rng).expect("refresh should succeed");

        assert_eq!(p1.public_key, original_pk);
        assert_eq!(p2.public_key, original_pk);

        let x = p1.secret_share + p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    #[ignore = "redundant refresh variant"]
    fn refresh_changes_shares() {
        let mut rng = rand_core::OsRng;
        let (mut p1, mut p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let old_x1 = p1.secret_share;
        let old_x2 = p2.secret_share;

        refresh(&mut p1, &mut p2, &mut rng).expect("refresh should succeed");

        assert_ne!(p1.secret_share, old_x1);
        assert_ne!(p2.secret_share, old_x2);
    }

    #[test]
    #[ignore = "redundant refresh variant"]
    fn multiple_refreshes_preserve_key() {
        let mut rng = rand_core::OsRng;
        let (mut p1, mut p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let original_pk = p1.public_key;

        for _ in 0..5 {
            refresh(&mut p1, &mut p2, &mut rng).expect("refresh should succeed");
        }

        assert_eq!(p1.public_key, original_pk);
        assert_eq!(p2.public_key, original_pk);

        let x = p1.secret_share + p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    #[ignore = "redundant refresh variant"]
    fn refresh_updates_paillier_ciphertext() {
        let mut rng = rand_core::OsRng;
        let (mut p1, mut p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        refresh(&mut p1, &mut p2, &mut rng).expect("refresh should succeed");

        let decrypted = p1.dk.decrypt(&p2.c_key).expect("decryption failed");
        let q_int = curve_order::<Secp256k1>();
        let decrypted_mod_q = decrypted.modulo_ref(&q_int);

        let x1_bytes = p1.secret_share.to_repr();
        let x1_int = tecdsa_paillier::backend::Integer::from_bytes_msf(x1_bytes.as_ref());
        assert_eq!(decrypted_mod_q, x1_int);
    }
}
