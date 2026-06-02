// SPDX-License-Identifier: MIT OR Apache-2.0
//! Endemic 1-out-of-2 base OT from Diffie-Hellman.
//!
//! Implements a simple DH-based oblivious transfer protocol:
//!
//! 1. **Sender** picks random scalar `a`, publishes `A = a * G`.
//! 2. **Receiver** with choice bit `b`:
//!    - picks random scalar `x`
//!    - if `b = 0`: sends `B = x * G`
//!    - if `b = 1`: sends `B = A + x * G`   (so `B - A = x * G`)
//! 3. **Sender** computes `k0 = H(a * B)`, `k1 = H(a * (B - A))`.
//! 4. Sender XOR-encrypts `m0` with `k0`, `m1` with `k1`, sends both ciphertexts.
//! 5. Receiver decrypts `m_b` using `H(x * A)`.
//!
//! Messages are fixed at 32 bytes.  The hash function is SHA-256 with a
//! domain-separation prefix.
//!
//! # Security
//!
//! This is an **endemic** OT, secure against passive (semi-honest) adversaries.
//! For UC-secure OT (needed by `DKLs23`), a Masny-Rindal or similar construction
//! is required and will be added in Phase 2.

use elliptic_curve::{CurveArithmetic, FieldBytes, PrimeField};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use tecdsa_curve::TecdsaCurve;

/// Fixed message length for base OT payloads (bytes).
pub const MSG_LEN: usize = 32;

/// Domain-separation tag for the base-OT key derivation hash.
const HASH_TAG: &[u8] = b"tecdsa/base-ot/key-derive";

// ──────────────────────────────────────────────────────────────────────────────
// Key derivation: H(tag || point_bytes)
// ──────────────────────────────────────────────────────────────────────────────
fn derive_key(point_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_TAG);
    hasher.update(point_bytes);
    hasher.finalize().into()
}

// ──────────────────────────────────────────────────────────────────────────────
// XOR encryption/decryption (symmetric; msg and key must be 32 bytes)
// ──────────────────────────────────────────────────────────────────────────────
fn xor_encrypt(key: &[u8; 32], msg: &[u8; MSG_LEN]) -> [u8; MSG_LEN] {
    let mut out = [0u8; MSG_LEN];
    for i in 0..MSG_LEN {
        out[i] = key[i] ^ msg[i];
    }
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Protocol messages
// ──────────────────────────────────────────────────────────────────────────────

/// First message: Sender publishes their DH public key.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SenderSetup {
    /// Compressed SEC1 encoding of `A = a * G`.
    pub public_key: Vec<u8>,
}

/// Second message: Receiver responds with a choice-dependent public key.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReceiverResponse {
    /// Compressed SEC1 encoding of `B`.
    pub public_key: Vec<u8>,
}

/// Third message: Sender sends both encrypted payloads.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SenderPayload {
    /// `E(k0, m0)` — ciphertext for choice-bit 0.
    pub ct0: [u8; MSG_LEN],
    /// `E(k1, m1)` — ciphertext for choice-bit 1.
    pub ct1: [u8; MSG_LEN],
}

// ──────────────────────────────────────────────────────────────────────────────
// Sender
// ──────────────────────────────────────────────────────────────────────────────

/// Sender state for the DH-based 1-out-of-2 base OT.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BaseOtSender {
    /// Secret scalar `a`.
    secret: [u8; 32],
    /// Compressed SEC1 encoding of `A = a * G`.
    #[zeroize(skip)]
    public_key: Vec<u8>,
}

impl BaseOtSender {
    /// Generate the sender's keypair and first-round message.
    ///
    /// Returns `(sender_state, setup_message)`.
    #[must_use]
    pub fn setup(rng: &mut impl CryptoRngCore) -> (Self, SenderSetup) {
        use k256::Secp256k1;
        let a = Secp256k1::random_scalar(rng);

        // A = a * G
        let big_a: <Secp256k1 as CurveArithmetic>::ProjectivePoint = Secp256k1::generator() * a;
        let big_a_affine: <Secp256k1 as CurveArithmetic>::AffinePoint = big_a.into();
        let pk_bytes = Secp256k1::point_to_bytes(&big_a_affine);

        // Store the scalar bytes (big-endian repr) for later use.
        let a_repr: FieldBytes<Secp256k1> = a.into();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(a_repr.as_ref());

        let sender = Self {
            secret,
            public_key: pk_bytes.clone(),
        };
        let setup = SenderSetup {
            public_key: pk_bytes,
        };
        (sender, setup)
    }

    /// Encrypt both messages given the receiver's response.
    ///
    /// The sender derives two keys from the receiver's `B`:
    /// - `k0 = H(a * B)`
    /// - `k1 = H(a * (B - A))`
    ///
    /// and XOR-encrypts `m0` with `k0`, `m1` with `k1`.
    ///
    /// # Errors
    ///
    /// Returns an error if the receiver's public key or sender's own
    /// stored key cannot be decoded.
    pub fn encrypt(
        self,
        response: &ReceiverResponse,
        m0: &[u8; MSG_LEN],
        m1: &[u8; MSG_LEN],
    ) -> Result<SenderPayload, OtError> {
        use k256::Secp256k1;
        type Point = <Secp256k1 as CurveArithmetic>::ProjectivePoint;
        type Scalar = <Secp256k1 as CurveArithmetic>::Scalar;

        // Recover the scalar a.
        let a_bytes: FieldBytes<Secp256k1> = self
            .secret
            .as_slice()
            .try_into()
            .map_err(|_| OtError("invalid sender secret length".into()))?;
        let a: Scalar = Option::from(Scalar::from_repr(a_bytes))
            .ok_or_else(|| OtError("invalid sender secret scalar".into()))?;

        // Decode B (receiver's public key).
        let receiver_point = Secp256k1::point_from_bytes(&response.public_key)
            .map_err(|e| OtError(format!("invalid receiver key: {e}")))?;
        let big_b = Point::from(receiver_point);

        // Decode A (our own public key).
        let sender_point = Secp256k1::point_from_bytes(&self.public_key)
            .map_err(|e| OtError(format!("invalid sender public key: {e}")))?;
        let big_a = Point::from(sender_point);

        // k0 = H(a * B)
        let dh_for_zero: <Secp256k1 as CurveArithmetic>::AffinePoint = (big_b * a).into();
        let k0 = derive_key(&Secp256k1::point_to_bytes(&dh_for_zero));

        // k1 = H(a * (B - A))
        let dh_for_one: <Secp256k1 as CurveArithmetic>::AffinePoint = ((big_b - big_a) * a).into();
        let k1 = derive_key(&Secp256k1::point_to_bytes(&dh_for_one));

        let ct0 = xor_encrypt(&k0, m0);
        let ct1 = xor_encrypt(&k1, m1);

        Ok(SenderPayload { ct0, ct1 })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Receiver
// ──────────────────────────────────────────────────────────────────────────────

/// Receiver state for the DH-based 1-out-of-2 base OT.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BaseOtReceiver {
    /// Decryption key `H(x * A)`.
    key: [u8; 32],
    /// The choice bit.
    #[zeroize(skip)]
    choice: bool,
}

impl BaseOtReceiver {
    /// Generate the receiver's response given the sender's setup and a choice bit.
    ///
    /// Returns `(receiver_state, response_message)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the sender's public key cannot be decoded.
    pub fn choose(
        setup: &SenderSetup,
        choice: bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, ReceiverResponse), OtError> {
        use k256::Secp256k1;
        type Point = <Secp256k1 as CurveArithmetic>::ProjectivePoint;

        // Decode A from the sender.
        let sender_point = Secp256k1::point_from_bytes(&setup.public_key)
            .map_err(|e| OtError(format!("invalid sender key: {e}")))?;
        let big_a = Point::from(sender_point);

        // Pick random x.
        let x = Secp256k1::random_scalar(rng);

        // Compute B depending on choice.
        let x_g = Secp256k1::generator() * x;
        let big_b = if choice { big_a + x_g } else { x_g };

        let response_point: <Secp256k1 as CurveArithmetic>::AffinePoint = big_b.into();
        let b_bytes = Secp256k1::point_to_bytes(&response_point);

        // Decryption key = H(x * A).
        let shared: <Secp256k1 as CurveArithmetic>::AffinePoint = (big_a * x).into();
        let key = derive_key(&Secp256k1::point_to_bytes(&shared));

        let receiver = Self { key, choice };
        let response = ReceiverResponse {
            public_key: b_bytes,
        };
        Ok((receiver, response))
    }

    /// Decrypt the chosen message from the sender's payload.
    #[must_use]
    pub fn decrypt(self, payload: &SenderPayload) -> [u8; MSG_LEN] {
        let ct = if self.choice {
            &payload.ct1
        } else {
            &payload.ct0
        };
        xor_encrypt(&self.key, ct)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

/// Error type for OT operations.
#[derive(Debug, Clone)]
pub struct OtError(pub String);

impl std::fmt::Display for OtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OtError: {}", self.0)
    }
}

impl std::error::Error for OtError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn sender_receiver_choice_zero() {
        let mut rng = OsRng;
        let m0 = [0xAA_u8; MSG_LEN];
        let m1 = [0xBB_u8; MSG_LEN];

        let (sender, setup) = BaseOtSender::setup(&mut rng);
        let (receiver, response) =
            BaseOtReceiver::choose(&setup, false, &mut rng).expect("choose should succeed");
        let payload = sender
            .encrypt(&response, &m0, &m1)
            .expect("encrypt should succeed");
        let result = receiver.decrypt(&payload);

        assert_eq!(result, m0, "choice=0 should yield m0");
    }

    #[test]
    fn sender_receiver_choice_one() {
        let mut rng = OsRng;
        let m0 = [0xAA_u8; MSG_LEN];
        let m1 = [0xBB_u8; MSG_LEN];

        let (sender, setup) = BaseOtSender::setup(&mut rng);
        let (receiver, response) =
            BaseOtReceiver::choose(&setup, true, &mut rng).expect("choose should succeed");
        let payload = sender
            .encrypt(&response, &m0, &m1)
            .expect("encrypt should succeed");
        let result = receiver.decrypt(&payload);

        assert_eq!(result, m1, "choice=1 should yield m1");
    }

    #[test]
    fn receiver_cannot_learn_other_message() {
        let mut rng = OsRng;
        let m0 = [0xAA_u8; MSG_LEN];
        let m1 = [0xBB_u8; MSG_LEN];

        // Receiver chooses b=0
        let (sender, setup) = BaseOtSender::setup(&mut rng);
        let (receiver, response) =
            BaseOtReceiver::choose(&setup, false, &mut rng).expect("choose should succeed");
        let payload = sender
            .encrypt(&response, &m0, &m1)
            .expect("encrypt should succeed");

        // Receiver gets m0 correctly.
        let result = receiver.decrypt(&payload);
        assert_eq!(result, m0);

        // But ct1 XORed with the receiver's key should NOT yield m1
        // (it would only if the key matched k1, which it does not).
        let wrong_decrypt = xor_encrypt(&[0u8; 32], &payload.ct1);
        assert_ne!(
            wrong_decrypt, m1,
            "receiver should not be able to get m1 trivially"
        );
    }

    #[test]
    fn random_messages_roundtrip() {
        let mut rng = OsRng;

        for choice in [false, true] {
            let mut m0 = [0u8; MSG_LEN];
            let mut m1 = [0u8; MSG_LEN];
            rng.fill_bytes(&mut m0);
            rng.fill_bytes(&mut m1);

            let (sender, setup) = BaseOtSender::setup(&mut rng);
            let (receiver, response) =
                BaseOtReceiver::choose(&setup, choice, &mut rng).expect("choose should succeed");
            let payload = sender
                .encrypt(&response, &m0, &m1)
                .expect("encrypt should succeed");
            let result = receiver.decrypt(&payload);

            let expected = if choice { m1 } else { m0 };
            assert_eq!(result, expected);
        }
    }
}
