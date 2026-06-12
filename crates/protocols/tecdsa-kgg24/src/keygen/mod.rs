pub mod interactive;
pub(crate) mod machine;
pub(crate) mod wire;

use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
pub use interactive::{
    interactive_keygen, party1_finalize_keygen, party1_keygen_round2, party1_keygen_round2_with_dk,
    party1_verify_round3, party2_finalize_keygen, party2_keygen_round1, party2_keygen_round3,
    KeyGenP1Round2Msg, KeyGenP1State, KeyGenP2Round1Msg, KeyGenP2Round3Msg, KeyGenP2State,
};
pub use machine::{Kgg24KeyShare, Kgg24KeygenMachine, Kgg24KeygenMsg, TwoPartyRole};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;

use crate::key_share::{Kgg24Party1KeyShare, Kgg24Party2KeyShare};

const TAU: u32 = 256;

const KAPPA: u32 = 80;

pub fn trusted_dealer_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Kgg24Party1KeyShare<C>, Kgg24Party2KeyShare<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1 = C::random_scalar(rng);
    let x2 = C::random_scalar(rng);

    let x = x1 + x2;
    let public_key = C::generator() * x;

    let dk = tecdsa_paillier::keygen(rng).expect("Paillier keygen failed");
    let ek = dk.encryption_key().clone();

    let q_int = curve_order::<C>();

    let noise_bound = tecdsa_paillier::backend::Integer::from(1u8) << (TAU + 2 * KAPPA);
    let t = noise_bound.random_below_ref(rng);

    let x1_bytes = x1.to_repr();
    let x1_int = tecdsa_paillier::backend::Integer::from_bytes_msf(x1_bytes.as_ref());
    let x_hat_1 = &x1_int + &t * &q_int;

    let (c_key, _nonce) = dk
        .encrypt_with_random(rng, &x_hat_1)
        .expect("Paillier encryption of noised x_1 failed");

    let p1_share = Kgg24Party1KeyShare {
        secret_share: x1,
        public_key,
        dk,
    };

    let p2_share = Kgg24Party2KeyShare {
        secret_share: x2,
        public_key,
        c_key,
        ek,
    };

    (p1_share, p2_share)
}

pub(crate) fn curve_order<C: TecdsaCurve>() -> tecdsa_paillier::backend::Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let neg_one = -C::Scalar::ONE;
    let neg_one_bytes = neg_one.to_repr();
    let q_minus_1 = tecdsa_paillier::backend::Integer::from_bytes_msf(neg_one_bytes.as_ref());
    &q_minus_1 + 1u8
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;

    use super::*;

    #[test]
    fn trusted_dealer_produces_consistent_shares() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        assert_eq!(p1.public_key, p2.public_key);

        let x = p1.secret_share + p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    fn paillier_encrypts_noised_x1_correctly() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let decrypted = p1.dk.decrypt(&p2.c_key).expect("decryption failed");
        let x1_bytes = p1.secret_share.to_repr();
        let x1_int = tecdsa_paillier::backend::Integer::from_bytes_msf(x1_bytes.as_ref());

        let q_int = curve_order::<Secp256k1>();
        let decrypted_mod_q = decrypted.modulo_ref(&q_int);
        assert_eq!(decrypted_mod_q, x1_int);
    }
}
