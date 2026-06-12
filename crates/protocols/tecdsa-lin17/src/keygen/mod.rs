pub mod interactive;
pub(crate) mod machine;
pub(crate) mod wire;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
pub use interactive::{
    interactive_keygen, party1_finalize_keygen, party1_keygen_round1, party1_keygen_round3,
    party1_keygen_round3_with_dk, party1_keygen_round3_with_precomputed_dk, party2_finalize_keygen,
    party2_keygen_round2, party2_verify_round3, KeyGenP1Round1Msg, KeyGenP1Round3Msg, KeyGenP1State,
    KeyGenP2Round2Msg, KeyGenP2State,
};
pub use machine::{Lin17KeyShare, Lin17KeygenMachine, Lin17KeygenMsg, TwoPartyRole};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;

use crate::key_share::{Lin17Party1KeyShare, Lin17Party2KeyShare};

pub fn trusted_dealer_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Lin17Party1KeyShare<C>, Lin17Party2KeyShare<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1 = C::random_scalar(rng);
    let x2 = C::random_scalar(rng);

    let x = x1 * x2;
    let public_key = C::generator() * x;

    let dk = tecdsa_paillier::keygen(rng).expect("Paillier keygen failed");
    let ek = dk.encryption_key().clone();

    let x1_bytes = x1.to_repr();
    let x1_plaintext = tecdsa_paillier::backend::Integer::from_bytes_msf(x1_bytes.as_ref());

    let (c_key, _nonce) = dk
        .encrypt_with_random(rng, &x1_plaintext)
        .expect("Paillier encryption of x_1 failed");

    let p1_share = Lin17Party1KeyShare {
        secret_share: x1,
        public_key,
        dk,
    };

    let p2_share = Lin17Party2KeyShare {
        secret_share: x2,
        public_key,
        c_key,
        ek,
    };

    (p1_share, p2_share)
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

        let x = p1.secret_share * p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    fn paillier_encrypts_x1_correctly() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let decrypted = p1.dk.decrypt(&p2.c_key).expect("decryption failed");
        let x1_bytes = p1.secret_share.to_repr();
        let x1_int = tecdsa_paillier::backend::Integer::from_bytes_msf(x1_bytes.as_ref());
        assert_eq!(decrypted, x1_int);
    }
}
