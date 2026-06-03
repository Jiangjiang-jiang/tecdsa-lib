// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key generation for the KGG24 two-party ECDSA protocol.
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

// ---------------------------------------------------------------------------
// Trusted dealer key generation (formerly keygen.rs content)
// ---------------------------------------------------------------------------
use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
pub use interactive::{
    interactive_keygen, party1_finalize_keygen, party1_keygen_round2, party1_verify_round3,
    party2_finalize_keygen, party2_keygen_round1, party2_keygen_round3, KeyGenP1Round2Msg,
    KeyGenP1State, KeyGenP2Round1Msg, KeyGenP2Round3Msg, KeyGenP2State,
};
pub use machine::{Kgg24KeyShare, Kgg24KeygenMachine, Kgg24KeygenMsg, TwoPartyRole};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;

use crate::key_share::{Kgg24Party1KeyShare, Kgg24Party2KeyShare};

/// Security parameter tau (bit-length of the noise exponent base).
/// For secp256k1: tau = 256 (curve order is ~256 bits).
const TAU: u32 = 256;

/// Statistical security parameter kappa.
const KAPPA: u32 = 80;

/// Generate key shares for the KGG24 two-party ECDSA protocol via a trusted dealer.
///
/// Produces additive key shares: `x = x_1 + x_2` where `Q = x * G`.
///
/// P_1 receives `(x_1, Q, dk)` and P_2 receives `(x_2, Q, C, ek)` where
/// `C = Enc(x_1 + t*q)` and `t` is a random noise term.
///
/// # Panics
///
/// Panics if Paillier key generation fails (should not happen with valid RNG).
pub fn trusted_dealer_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Kgg24Party1KeyShare<C>, Kgg24Party2KeyShare<C>)
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

    // Generate Paillier key pair for P_1
    let dk = tecdsa_paillier::keygen(rng).expect("Paillier keygen failed");
    let ek = dk.encryption_key().clone();

    // Get the curve order q
    let q_int = curve_order::<C>();

    // Sample noise t from [0, 2^{tau + 2*kappa})
    let noise_bound = tecdsa_paillier::backend::Integer::from(1u8) << (TAU + 2 * KAPPA);
    let t = noise_bound.random_below_ref(rng);

    // Compute x_hat_1 = x_1 + t * q (the noised share)
    let x1_bytes = x1.to_repr();
    let x1_int = tecdsa_paillier::backend::Integer::from_bytes_msf(x1_bytes.as_ref());
    let x_hat_1 = &x1_int + &t * &q_int;

    // Encrypt x_hat_1: C = Enc_pk(x_1 + t*q)
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

/// Compute the curve order q as a big integer.
pub(crate) fn curve_order<C: TecdsaCurve>() -> tecdsa_paillier::backend::Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // q - 1 is the repr of -1 in the scalar field
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

        // Both parties should have the same public key
        assert_eq!(p1.public_key, p2.public_key);

        // Q = (x_1 + x_2) * G (additive sharing)
        let x = p1.secret_share + p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    fn paillier_encrypts_noised_x1_correctly() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        // Decrypt c_key and verify it equals x_1 mod q
        let decrypted = p1.dk.decrypt(&p2.c_key).expect("decryption failed");
        let x1_bytes = p1.secret_share.to_repr();
        let x1_int = tecdsa_paillier::backend::Integer::from_bytes_msf(x1_bytes.as_ref());

        // The decrypted value is x_1 + t*q, so (decrypted mod q) should equal x_1
        let q_int = curve_order::<Secp256k1>();
        let decrypted_mod_q = decrypted.modulo_ref(&q_int);
        assert_eq!(decrypted_mod_q, x1_int);
    }
}
