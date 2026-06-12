pub mod interactive;
pub(crate) mod machine;
pub(crate) mod wire;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
pub use interactive::{
    interactive_keygen, party1_finalize, party1_keygen_round1, party1_keygen_round3,
    party2_finalize, party2_keygen_round2, party2_keygen_round2_with_setup, party2_verify_round3,
    KeyGenP1Round1Msg, KeyGenP1Round3Msg, KeyGenP1State, KeyGenP2Round2Msg, KeyGenP2State,
};
pub use machine::{TwoPartyRole, Xal21KeyShare, Xal21KeygenMachine, Xal21KeygenMsg};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{backend::Integer, zk::mta_range::NTildeParams};

use crate::key_share::{Xal21Party1KeyShare, Xal21Party2KeyShare};

fn generate_ntilde_params(rng: &mut impl CryptoRngCore) -> NTildeParams {
    let p = Integer::generate_safe_prime(rng, 1536);
    let q = Integer::generate_safe_prime(rng, 1536);
    let n_tilde = &p * &q;
    let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);
    let lambda = (&p - Integer::one()) * (&q - Integer::one());
    let h2 = h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod for h2");
    NTildeParams {
        N_tilde: n_tilde,
        h1,
        h2,
    }
}

pub fn generate_setup(
    rng: &mut impl CryptoRngCore,
) -> (tecdsa_paillier::DecryptionKey, NTildeParams) {
    let dk = tecdsa_paillier::keygen(rng).expect("Paillier keygen failed");
    let ntilde = generate_ntilde_params(rng);
    (dk, ntilde)
}

pub fn trusted_dealer_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Xal21Party1KeyShare<C>, Xal21Party2KeyShare<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1 = C::random_scalar(rng);
    let x2 = C::random_scalar(rng);

    let x = x1 + x2;
    let public_key = C::generator() * x;

    let q1 = C::generator() * x1;

    let dk = tecdsa_paillier::keygen(rng).expect("Paillier keygen failed");
    let ek = dk.encryption_key().clone();

    let ntilde = generate_ntilde_params(rng);

    let p1_share = Xal21Party1KeyShare {
        secret_share: x1,
        public_key,
        public_share: q1,
        ek: ek.clone(),
        ntilde: ntilde.clone(),
    };

    let p2_share = Xal21Party2KeyShare {
        secret_share: x2,
        public_key,
        public_share_p1: q1,
        dk,
        ek,
        ntilde,
    };

    (p1_share, p2_share)
}

pub(crate) fn curve_order<C: TecdsaCurve>() -> tecdsa_paillier::backend::Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::Field;
    let neg_one = -C::Scalar::ONE;
    let neg_one_bytes = neg_one.to_repr();
    let q_minus_1 = tecdsa_paillier::backend::Integer::from_bytes_msf(neg_one_bytes.as_ref());
    &q_minus_1 + 1u8
}

pub(crate) use tecdsa_curve::conv::scalar_to_bytes;

#[allow(dead_code)]
pub(crate) fn scalar_to_int<C: TecdsaCurve>(s: &C::Scalar) -> tecdsa_paillier::backend::Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    tecdsa_paillier::backend::Integer::from_bytes_msf(&scalar_to_bytes::<C>(s))
}

pub(crate) fn int_to_scalar<C: TecdsaCurve>(value: &tecdsa_paillier::backend::Integer) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    tecdsa_curve::conv::bytes_to_scalar::<C>(&value.to_bytes_msf())
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
    fn public_share_is_correct() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let expected_q1 = Secp256k1::generator() * p1.secret_share;
        assert_eq!(p1.public_share, expected_q1);

        assert_eq!(p2.public_share_p1, expected_q1);
    }
}
