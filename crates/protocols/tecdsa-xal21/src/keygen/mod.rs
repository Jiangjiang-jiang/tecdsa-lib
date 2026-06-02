// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key generation for the XAL+21 two-party ECDSA protocol.
//!
//! This module provides both trusted-dealer key generation and interactive
//! (3-round) distributed key generation.
//!
//! - [`trusted_dealer_keygen`]: simplified keygen via a trusted dealer.
//! - [`interactive`]: pure round functions for the interactive DKG protocol.
//! - `machine`: [`StateMachine`](tecdsa_protocol::StateMachine) wrapper
//!   for the interactive DKG, with wire serialization.

pub mod interactive;
pub(crate) mod machine;
pub(crate) mod wire;

pub use interactive::{
    interactive_keygen, party1_finalize, party1_keygen_round1, party1_keygen_round3,
    party2_finalize, party2_keygen_round2, party2_verify_round3, KeyGenP1Round1Msg,
    KeyGenP1Round3Msg, KeyGenP1State, KeyGenP2Round2Msg, KeyGenP2State,
};
pub use machine::{TwoPartyRole, Xal21KeyShare, Xal21KeygenMachine, Xal21KeygenMsg};

// ---------------------------------------------------------------------------
// Trusted dealer key generation (formerly keygen.rs content)
// ---------------------------------------------------------------------------

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;

use crate::key_share::{Xal21Party1KeyShare, Xal21Party2KeyShare};

/// Generate key shares for the XAL+21 two-party ECDSA protocol via a trusted dealer.
///
/// Produces additive key shares: `x = x_1 + x_2` where `Q = x * G`.
///
/// P_1 receives `(x_1, Q, Q_1, ek)` and P_2 receives `(x_2, Q, Q_1, dk, ek)`.
///
/// # Panics
///
/// Panics if Paillier key generation fails (should not happen with valid RNG).
pub fn trusted_dealer_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Xal21Party1KeyShare<C>, Xal21Party2KeyShare<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Sample random non-zero secret shares x_1, x_2
    let x1 = C::random_scalar(rng);
    let x2 = C::random_scalar(rng);

    // Compute joint secret key x = x_1 + x_2 and public key Q = x * G
    let x = x1 + x2;
    let public_key = C::generator() * x;

    // Compute P_1's public share Q_1 = x_1 * G
    let q1 = C::generator() * x1;

    // Generate Paillier key pair for P_2 (P_2 owns the decryption key)
    let dk = tecdsa_paillier::keygen(rng).expect("Paillier keygen failed");
    let ek = dk.encryption_key().clone();

    let p1_share = Xal21Party1KeyShare {
        secret_share: x1,
        public_key,
        public_share: q1,
        ek: ek.clone(),
    };

    let p2_share = Xal21Party2KeyShare {
        secret_share: x2,
        public_key,
        public_share_p1: q1,
        dk,
        ek,
    };

    (p1_share, p2_share)
}

/// Compute the curve order q as a big integer.
pub(crate) fn curve_order<C: TecdsaCurve>() -> tecdsa_paillier::backend::Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::Field;
    // q - 1 is the repr of -1 in the scalar field
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
    use super::*;
    use k256::Secp256k1;

    #[test]
    fn trusted_dealer_produces_consistent_shares() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        // Both parties should have the same public key
        assert_eq!(p1.public_key, p2.public_key);

        // Q = (x_1 + x_2) * G (additive sharing)
        let x = p1.secret_share + p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    fn public_share_is_correct() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        // Q_1 = x_1 * G
        let expected_q1 = Secp256k1::generator() * p1.secret_share;
        assert_eq!(p1.public_share, expected_q1);

        // P_2 also has Q_1
        assert_eq!(p2.public_share_p1, expected_q1);
    }
}
