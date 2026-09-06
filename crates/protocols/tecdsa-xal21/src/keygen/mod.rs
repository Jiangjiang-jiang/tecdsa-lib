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

// ---------------------------------------------------------------------------
// Trusted dealer key generation (formerly keygen.rs content)
// ---------------------------------------------------------------------------
use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
pub use interactive::{
    interactive_keygen, party1_finalize, party1_keygen_round1, party1_keygen_round3,
    party2_finalize, party2_keygen_round2, party2_keygen_round2_with_setup, party2_verify_round3,
    KeyGenP1Round1Msg, KeyGenP1Round3Msg, KeyGenP1State, KeyGenP2Round2Msg, KeyGenP2State,
};
pub use machine::{TwoPartyRole, Xal21KeyShare, Xal21KeygenMachine, Xal21KeygenMsg};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{zk::mta_range::NTildeParams, BigIntExt};

use crate::key_share::{Xal21Party1KeyShare, Xal21Party2KeyShare};

fn generate_ntilde_params(rng: &mut impl CryptoRngCore) -> NTildeParams {
    // `t` is the quadratic-residue base and `s = t^lambda` for a secret lambda,
    // so the discrete log relating them is unknown -- which is what makes the
    // range proofs' Ring-Pedersen commitments hiding.
    let (params, _secret) = tecdsa_pedersen_mod::PedersenModParams::generate(1536, rng);
    NTildeParams {
        N_tilde: params.n,
        h1: params.t,
        h2: params.s,
    }
}

/// Generate XAL+21's one-time MtA setup material: P2's Paillier keypair and the
/// Ring-Pedersen (`N~`) auxiliary parameters used by the MtA range proofs.
///
/// Both are message-independent, one-time setup (Paillier `keygen` and a
/// Ring-Pedersen modulus each need a pair of safe primes). Exposing them lets
/// callers (e.g. benchmarks) generate the material up front and inject it via
/// [`Xal21KeygenMachine::new_with_setup`], keeping safe-prime generation out of
/// the measured DKG rounds.
///
/// # Panics
///
/// Panics if Paillier key generation fails (should not happen with a valid RNG).
pub fn generate_setup(
    rng: &mut impl CryptoRngCore,
) -> (tecdsa_paillier::DecryptionKey, NTildeParams) {
    let dk = tecdsa_paillier::keygen(rng).expect("Paillier keygen failed");
    let ntilde = generate_ntilde_params(rng);
    (dk, ntilde)
}

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

    // Generate Ring-Pedersen auxiliary parameters for MtA range proofs
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

pub(crate) use tecdsa_curve::conv::{curve_order, scalar_to_bytes};

#[allow(dead_code)]
pub(crate) fn scalar_to_int<C: TecdsaCurve>(s: &C::Scalar) -> tecdsa_paillier::backend::Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    tecdsa_paillier::backend::Integer::from_bytes_msf(&scalar_to_bytes(s))
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

    /// The Ring-Pedersen parameters must be non-degenerate.
    ///
    /// `generate_ntilde_params` previously used `lambda = (p-1)(q-1) = phi(N~)`,
    /// and by Euler that makes `h2 = h1^phi = 1`. The MtA range proofs commit as
    /// `h1^x * h2^r`, so a unit `h2` silently drops the blinding factor `r` and
    /// the commitment becomes a deterministic function of the secret witness.
    #[test]
    fn ntilde_params_are_hiding() {
        use tecdsa_paillier::BigIntExt;

        let rng = &mut rand::thread_rng();
        let ntilde = super::generate_ntilde_params(rng);

        assert_ne!(
            ntilde.h2, 1,
            "h2 must not be the identity: h1^x * h2^r would ignore r"
        );
        assert_ne!(ntilde.h1, 1, "h1 must not be the identity");
        assert_ne!(ntilde.h1, ntilde.h2, "h1 and h2 must differ");
        assert!(ntilde.h1.in_mult_group_of(&ntilde.N_tilde));
        assert!(ntilde.h2.in_mult_group_of(&ntilde.N_tilde));
    }
}
