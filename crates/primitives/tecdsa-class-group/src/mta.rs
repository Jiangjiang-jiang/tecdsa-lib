// SPDX-License-Identifier: GPL-3.0-or-later
//! CL-based MtA (Multiplicative-to-Additive) sub-protocol.
//!
//! Implements `tecdsa_protocol::MtA` using CL-HSM class-group encryption
//! following XAL+21 Figure 5 / Castagnos et al.
//!
//! The protocol has three steps:
//!
//! 1. **Sender encrypt**: P2 encrypts input `b` with CL encryption.
//! 2. **Receiver compute**: P1 homomorphically computes
//!    `c_A = hscmul(a, c_B) + encrypt(pk, -alpha')`, sets `alpha = alpha' mod q`.
//! 3. **Sender decrypt**: P2 decrypts `beta_raw = decrypt(sk, c_A)`,
//!    sets `beta = beta_raw mod q`.
//!
//! After completion: `alpha + beta = a * b mod q`.
//!
//! # Interior mutability
//!
//! `ClSetup` requires `&mut self` for encryption and homomorphic operations
//! (because the BICYCL RNG is mutated). Since the `MtA` trait passes
//! `&Self::Setup`, we use `RefCell<ClSetup>` for interior mutability.
//! This is safe because protocol execution is single-threaded.

use std::cell::RefCell;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use k256::Secp256k1;
use num_bigint::BigUint;
use num_traits::Zero;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use tecdsa_curve::conv;
use tecdsa_protocol::{MtA, MtAWithCheck};

use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClError, ClSetup, PublicKey as ClHsmqkPublicKey,
    SecretKey as ClHsmqkSecretKey,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// CL-based MtA backend.
///
/// Uses CL-HSM class-group encryption with homomorphic operations as
/// described in XAL+21 (Figure 5).
pub struct ClMtA;

/// Setup material for CL MtA: the CL scheme parameters, public key,
/// and secret key.
///
/// Wraps `ClSetup` in a `RefCell` because the MtA trait passes `&Setup`
/// but CL operations need `&mut ClSetup`.
pub struct ClMtaSetup {
    /// CL-HSM scheme parameters (wrapped for interior mutability).
    pub setup: RefCell<ClSetup>,
    /// CL public key (owned by the sender, shared with both parties).
    pub pk: ClHsmqkPublicKey,
    /// CL secret key (owned by the sender).
    pub sk: ClHsmqkSecretKey,
}

impl Clone for ClMtaSetup {
    fn clone(&self) -> Self {
        // ClSetup/ClHsmqkPublicKey/ClHsmqkSecretKey do not implement Clone.
        // The MtA trait requires Setup: Clone, so we implement it but
        // it should never actually be called in practice. Each party
        // creates its own setup.
        unimplemented!("ClMtaSetup::clone is not supported; each party should create its own setup")
    }
}

/// Sender's internal state between encrypt and decrypt.
///
/// Stores the original plaintext `b` for potential verification.
pub struct ClSenderState {
    /// The sender's input value `b` as big-endian bytes.
    pub b_bytes: Vec<u8>,
}

/// Message from sender (P2) to receiver (P1): encrypted `b`.
pub struct ClSenderMsg {
    /// CL ciphertext: `c_B = Enc(pk, b)`.
    pub ciphertext: ClHsmqkCiphertext,
}

/// Message from receiver (P1) to sender (P2): affine result ciphertext.
pub struct ClReceiverMsg {
    /// CL ciphertext: `c_A = hscmul(a, c_B) + Enc(pk, alpha')`.
    pub ciphertext: ClHsmqkCiphertext,
}

/// Error type for the CL MtA backend.
#[derive(Debug, thiserror::Error)]
pub enum ClMtaError {
    /// An error from the CL class-group operations.
    #[error("CL error: {0}")]
    Cl(#[from] ClError),

    /// Invalid parameter.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

// ---------------------------------------------------------------------------
// MtA trait implementation
// ---------------------------------------------------------------------------

impl MtA for ClMtA {
    type Setup = ClMtaSetup;
    type SenderState = ClSenderState;
    type SenderMsg = ClSenderMsg;
    type ReceiverMsg = ClReceiverMsg;
    type Error = ClMtaError;

    /// Step 1: Sender (P2) encrypts input `b` using CL encryption.
    fn sender_encrypt(
        setup: &Self::Setup,
        b_bytes: &[u8],
        _q_bytes: &[u8],
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SenderMsg, Self::SenderState), Self::Error> {
        let mut cl_setup = setup.setup.borrow_mut();
        let ciphertext = cl_setup.encrypt_bytes(&setup.pk, b_bytes)?;

        let msg = ClSenderMsg { ciphertext };
        let state = ClSenderState {
            b_bytes: b_bytes.to_vec(),
        };

        Ok((msg, state))
    }

    /// Step 2: Receiver (P1) homomorphically computes the affine operation
    /// and obtains `alpha`.
    ///
    /// Computes:
    ///   `c_scaled = hscmul(a, c_B)` = Enc(a * b)
    ///   `c_alpha = encrypt(pk, alpha')` (random mask)
    ///   `c_A = hadd(c_scaled, c_alpha)` = Enc(a * b + alpha')
    ///   `alpha = q - (alpha' mod q)`
    fn receiver_compute(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>), Self::Error> {
        let q = BigUint::from_bytes_be(q_bytes);

        let mut cl_setup = setup.setup.borrow_mut();

        // 1. Homomorphic scalar multiplication: c_scaled = a * c_B = Enc(a * b)
        let c_scaled =
            cl_setup.scal_ciphertext_bytes(&setup.pk, &sender_msg.ciphertext, a_bytes)?;

        // 2. Sample alpha' from [0, q) for masking
        // Use the CL setup's own keygen to generate randomness, then reduce
        let (sk_tmp, _pk_tmp) = cl_setup.keygen()?;
        let r_bytes = cl_setup.sk_to_bytes(&sk_tmp)?;
        let r_big = BigUint::from_bytes_be(&r_bytes);
        let alpha_prime = &r_big % &q;
        let alpha_prime_bytes = alpha_prime.to_bytes_be();

        // 3. Encrypt alpha': c_alpha = Enc(pk, alpha')
        let c_alpha = cl_setup.encrypt_bytes(&setup.pk, &alpha_prime_bytes)?;

        // 4. Homomorphic addition: c_A = c_scaled + c_alpha = Enc(a*b + alpha')
        let c_a = cl_setup.add_ciphertexts(&setup.pk, &c_scaled, &c_alpha)?;

        // 5. Compute receiver's output: alpha = -alpha' mod q = q - (alpha' mod q)
        let alpha_mod_q = &alpha_prime % &q;
        let alpha = if alpha_mod_q.is_zero() {
            BigUint::zero()
        } else {
            &q - &alpha_mod_q
        };
        let alpha_bytes = alpha.to_bytes_be();

        let msg = ClReceiverMsg { ciphertext: c_a };

        Ok((msg, alpha_bytes))
    }

    /// Step 3: Sender (P2) decrypts to obtain `beta`.
    ///
    /// `beta = decrypt(sk, c_A) mod q`
    fn sender_decrypt(
        setup: &Self::Setup,
        _state: &Self::SenderState,
        q_bytes: &[u8],
        receiver_msg: &Self::ReceiverMsg,
    ) -> Result<Vec<u8>, Self::Error> {
        let q = BigUint::from_bytes_be(q_bytes);

        let cl_setup = setup.setup.borrow();

        // Decrypt the affine ciphertext
        let plaintext_bytes = cl_setup.decrypt_bytes(&setup.sk, &receiver_msg.ciphertext)?;
        let plaintext = BigUint::from_bytes_be(&plaintext_bytes);

        // Reduce mod q
        let beta = &plaintext % &q;
        let beta_bytes = beta.to_bytes_be();

        Ok(beta_bytes)
    }
}

// ---------------------------------------------------------------------------
// MtAWithCheck trait implementation (WMY23-style MtAwc)
// ---------------------------------------------------------------------------

/// Consistency-check proof for CL MtA (WMY23 MtAwc pattern).
///
/// After the receiver computes the affine operation, it also computes
/// `g^beta` (where `beta` is the receiver's MtA share) and sends it
/// alongside the ciphertext.  The sender verifies:
///
///   `g^{sender_share} * g^{receiver_share} == (g^a)^b`
///
/// where `a` is the receiver's input and `b` is the sender's input.
/// Since `sender_share + receiver_share = a * b mod q`, this checks
/// that both shares are consistent.
///
/// The proof contains `g^alpha` (the receiver's share commitment) as
/// compressed secp256k1 point bytes.  The verifier also needs `g^a`
/// (the receiver's public input) as auxiliary data.
pub struct ClCheckProof {
    /// `g^alpha` where `alpha` is the receiver's MtA share,
    /// as compressed secp256k1 point bytes (33 bytes).
    pub g_alpha_bytes: Vec<u8>,
}

impl std::fmt::Debug for ClCheckProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClCheckProof")
            .field("g_alpha_bytes_len", &self.g_alpha_bytes.len())
            .finish()
    }
}

impl MtAWithCheck for ClMtA {
    type CheckProof = ClCheckProof;

    /// Receiver (P1) computes the affine operation and produces a
    /// consistency check proof.
    ///
    /// In addition to the standard `receiver_compute` output, produces
    /// `g^alpha` as proof that the receiver's share is computed honestly.
    ///
    /// The sender can verify: `g^beta * g^alpha == (g^a)^b`
    /// where `g^a` is provided as auxiliary data.
    fn receiver_compute_with_check(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>, Self::CheckProof), Self::Error> {
        // Perform the standard receiver computation.
        let (receiver_msg, alpha_bytes) =
            Self::receiver_compute(setup, a_bytes, q_bytes, sender_msg, rng)?;

        // Compute g^alpha as an EC point for the consistency check.
        let alpha = BigUint::from_bytes_be(&alpha_bytes);
        let q = BigUint::from_bytes_be(q_bytes);
        let alpha_scalar = conv::biguint_to_scalar::<Secp256k1>(&(&alpha % &q));

        let g_alpha = <Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * alpha_scalar;
        let g_alpha_bytes = g_alpha.to_bytes().to_vec();

        let check_proof = ClCheckProof { g_alpha_bytes };

        Ok((receiver_msg, alpha_bytes, check_proof))
    }

    /// Verify the consistency check on the sender side.
    ///
    /// Checks: `g^beta * g^alpha == (g^a)^b`
    ///
    /// # Arguments
    ///
    /// * `state` - Sender state containing the original input `b`.
    /// * `beta_bytes` - The sender's decrypted share (big-endian).
    /// * `check_proof` - Contains `g^alpha` (receiver's share commitment).
    /// * `aux_bytes` - `g^a` as compressed secp256k1 point bytes (33 bytes).
    ///   This is the receiver's public EC point, known to the sender.
    fn verify_check(
        _setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        beta_bytes: &[u8],
        check_proof: &Self::CheckProof,
        aux_bytes: &[u8],
    ) -> Result<bool, Self::Error> {
        let q = BigUint::from_bytes_be(q_bytes);

        // Parse g^alpha from the check proof.
        let g_alpha_repr = k256::CompressedPoint::try_from(check_proof.g_alpha_bytes.as_slice())
            .map_err(|e| ClMtaError::InvalidParam(format!("invalid g_alpha point: {e}")))?;
        let g_alpha =
            Option::<k256::ProjectivePoint>::from(k256::ProjectivePoint::from_bytes(&g_alpha_repr))
                .ok_or_else(|| ClMtaError::InvalidParam("invalid g_alpha EC point".into()))?;

        // Parse g^a (receiver's public point) from aux_bytes.
        let g_a_repr = k256::CompressedPoint::try_from(aux_bytes)
            .map_err(|e| ClMtaError::InvalidParam(format!("invalid g_a point: {e}")))?;
        let g_a =
            Option::<k256::ProjectivePoint>::from(k256::ProjectivePoint::from_bytes(&g_a_repr))
                .ok_or_else(|| ClMtaError::InvalidParam("invalid g_a EC point".into()))?;

        // Compute g^beta from beta_bytes.
        let beta = BigUint::from_bytes_be(beta_bytes);
        let beta_scalar = conv::biguint_to_scalar::<Secp256k1>(&(&beta % &q));
        let g_beta = <Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * beta_scalar;

        // Compute b as scalar.
        let b = BigUint::from_bytes_be(&state.b_bytes);
        let b_scalar = conv::biguint_to_scalar::<Secp256k1>(&(&b % &q));

        // Check: g^alpha * g^beta == (g^a)^b
        let lhs = g_alpha + g_beta;
        let rhs = g_a * b_scalar;

        Ok(bool::from(lhs.to_bytes().ct_eq(&rhs.to_bytes())))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use num_traits::Num;

    use super::*;

    /// Helper: create a ClMtaSetup for testing with secp256k1 parameters.
    fn test_setup(seed: &str) -> ClMtaSetup {
        let mut cl_setup = ClSetup::new_secp256k1(seed).expect("CL setup should succeed");
        let (sk, pk) = cl_setup.keygen().expect("keygen should succeed");

        ClMtaSetup {
            setup: RefCell::new(cl_setup),
            pk,
            sk,
        }
    }

    /// Helper: secp256k1 curve order as BigUint.
    fn curve_order() -> BigUint {
        BigUint::from_str_radix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .expect("valid order")
    }

    #[test]
    fn cl_mta_correctness() {
        let setup = test_setup("2001");

        let q = curve_order();
        let q_bytes = q.to_bytes_be();

        // Sender's input b
        let b = BigUint::from(12345u32);
        let b_bytes = b.to_bytes_be();

        // Receiver's input a
        let a = BigUint::from(67890u32);
        let a_bytes = a.to_bytes_be();

        let mut rng = rand::thread_rng();

        // Step 1: Sender encrypts
        let (sender_msg, sender_state) =
            ClMtA::sender_encrypt(&setup, &b_bytes, &q_bytes, &mut rng)
                .expect("sender_encrypt should succeed");

        // Step 2: Receiver computes
        let (receiver_msg, alpha_bytes) =
            ClMtA::receiver_compute(&setup, &a_bytes, &q_bytes, &sender_msg, &mut rng)
                .expect("receiver_compute should succeed");

        // Step 3: Sender decrypts
        let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
            .expect("sender_decrypt should succeed");

        // Verify: alpha + beta = a * b mod q
        let alpha = BigUint::from_bytes_be(&alpha_bytes);
        let beta = BigUint::from_bytes_be(&beta_bytes);
        let sum = (&alpha + &beta) % &q;
        let expected = (&a * &b) % &q;

        assert_eq!(sum, expected, "alpha + beta must equal a * b mod q");
    }

    #[test]
    #[ignore = "redundant MtA variant"]
    fn cl_mta_multiple_runs() {
        let setup = test_setup("2002");

        let q = curve_order();
        let q_bytes = q.to_bytes_be();

        let mut rng = rand::thread_rng();

        let test_values: &[(u32, u32)] = &[(100, 200), (42, 99), (1, 1)];

        for &(a_val, b_val) in test_values {
            let a = BigUint::from(a_val);
            let b = BigUint::from(b_val);

            let (sender_msg, sender_state) =
                ClMtA::sender_encrypt(&setup, &b.to_bytes_be(), &q_bytes, &mut rng)
                    .expect("sender_encrypt");

            let (receiver_msg, alpha_bytes) =
                ClMtA::receiver_compute(&setup, &a.to_bytes_be(), &q_bytes, &sender_msg, &mut rng)
                    .expect("receiver_compute");

            let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
                .expect("sender_decrypt");

            let alpha = BigUint::from_bytes_be(&alpha_bytes);
            let beta = BigUint::from_bytes_be(&beta_bytes);
            let sum = (&alpha + &beta) % &q;
            let expected = (&a * &b) % &q;

            assert_eq!(
                sum, expected,
                "MtA correctness must hold for a={a_val}, b={b_val}"
            );
        }
    }

    #[test]
    #[ignore = "redundant MtA variant"]
    fn cl_mta_with_larger_values() {
        let setup = test_setup("2003");

        let q = curve_order();
        let q_bytes = q.to_bytes_be();

        // Use values that are close to (but less than) q
        let a = &q - BigUint::from(1u32);
        let b = BigUint::from(2u32);

        let mut rng = rand::thread_rng();

        let (sender_msg, sender_state) =
            ClMtA::sender_encrypt(&setup, &b.to_bytes_be(), &q_bytes, &mut rng)
                .expect("sender_encrypt");

        let (receiver_msg, alpha_bytes) =
            ClMtA::receiver_compute(&setup, &a.to_bytes_be(), &q_bytes, &sender_msg, &mut rng)
                .expect("receiver_compute");

        let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
            .expect("sender_decrypt");

        let alpha = BigUint::from_bytes_be(&alpha_bytes);
        let beta = BigUint::from_bytes_be(&beta_bytes);
        let sum = (&alpha + &beta) % &q;
        let expected = (&a * &b) % &q;

        assert_eq!(sum, expected, "alpha + beta must equal a * b mod q");
    }

    #[test]
    fn cl_mta_with_check_correctness() {
        let setup = test_setup("3001");

        let q = curve_order();
        let q_bytes = q.to_bytes_be();

        // Sender's input b
        let b = BigUint::from(12345u32);
        let b_bytes = b.to_bytes_be();

        // Receiver's input a
        let a = BigUint::from(67890u32);
        let a_bytes = a.to_bytes_be();

        // Compute g^a for the auxiliary data (receiver's public point).
        let a_mod_q = &a % &q;
        let a_mod_bytes = a_mod_q.to_bytes_be();
        let mut a_padded = [0u8; 32];
        let a_len = a_mod_bytes.len().min(32);
        a_padded[32 - a_len..].copy_from_slice(&a_mod_bytes[..a_len]);
        let a_repr = k256::FieldBytes::from(a_padded);
        let a_scalar = Option::<k256::Scalar>::from(
            <k256::Scalar as elliptic_curve::PrimeField>::from_repr(a_repr),
        )
        .expect("a should be a valid scalar");
        let g_a = <Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * a_scalar;
        let g_a_bytes = g_a.to_bytes().to_vec();

        let mut rng = rand::thread_rng();

        // Step 1: Sender encrypts
        let (sender_msg, sender_state) =
            ClMtA::sender_encrypt(&setup, &b_bytes, &q_bytes, &mut rng)
                .expect("sender_encrypt should succeed");

        // Step 2: Receiver computes with check
        let (receiver_msg, alpha_bytes, check_proof) =
            ClMtA::receiver_compute_with_check(&setup, &a_bytes, &q_bytes, &sender_msg, &mut rng)
                .expect("receiver_compute_with_check should succeed");

        // Step 3: Sender decrypts
        let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
            .expect("sender_decrypt should succeed");

        // Step 4: Verify check
        let check_ok = ClMtA::verify_check(
            &setup,
            &sender_state,
            &q_bytes,
            &beta_bytes,
            &check_proof,
            &g_a_bytes,
        )
        .expect("verify_check should succeed");
        assert!(check_ok, "MtAwc consistency check must pass");

        // Also verify MtA correctness: alpha + beta = a * b mod q
        let alpha = BigUint::from_bytes_be(&alpha_bytes);
        let beta = BigUint::from_bytes_be(&beta_bytes);
        let sum = (&alpha + &beta) % &q;
        let expected = (&a * &b) % &q;
        assert_eq!(sum, expected, "alpha + beta must equal a * b mod q");
    }

    #[test]
    #[ignore = "redundant MtA variant"]
    fn cl_mta_with_check_multiple_runs() {
        let setup = test_setup("3002");

        let q = curve_order();
        let q_bytes = q.to_bytes_be();

        let mut rng = rand::thread_rng();
        let test_values: &[(u32, u32)] = &[(7, 11), (100, 200), (1, 1)];

        for &(a_val, b_val) in test_values {
            let a = BigUint::from(a_val);
            let b = BigUint::from(b_val);

            // Compute g^a
            let a_mod_q = &a % &q;
            let a_mod_bytes = a_mod_q.to_bytes_be();
            let mut a_padded = [0u8; 32];
            let a_len = a_mod_bytes.len().min(32);
            a_padded[32 - a_len..].copy_from_slice(&a_mod_bytes[..a_len]);
            let a_repr = k256::FieldBytes::from(a_padded);
            let a_scalar = Option::<k256::Scalar>::from(
                <k256::Scalar as elliptic_curve::PrimeField>::from_repr(a_repr),
            )
            .expect("a should be valid scalar");
            let g_a = <Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * a_scalar;
            let g_a_bytes = g_a.to_bytes().to_vec();

            let (sender_msg, sender_state) =
                ClMtA::sender_encrypt(&setup, &b.to_bytes_be(), &q_bytes, &mut rng)
                    .expect("sender_encrypt");

            let (receiver_msg, alpha_bytes, check_proof) = ClMtA::receiver_compute_with_check(
                &setup,
                &a.to_bytes_be(),
                &q_bytes,
                &sender_msg,
                &mut rng,
            )
            .expect("receiver_compute_with_check");

            let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
                .expect("sender_decrypt");

            let check_ok = ClMtA::verify_check(
                &setup,
                &sender_state,
                &q_bytes,
                &beta_bytes,
                &check_proof,
                &g_a_bytes,
            )
            .expect("verify_check");
            assert!(check_ok, "MtAwc check must pass for a={a_val}, b={b_val}");

            // Correctness check.
            let alpha = BigUint::from_bytes_be(&alpha_bytes);
            let beta = BigUint::from_bytes_be(&beta_bytes);
            let sum = (&alpha + &beta) % &q;
            let expected = (&a * &b) % &q;
            assert_eq!(sum, expected, "MtA correctness for a={a_val}, b={b_val}");
        }
    }
}
