// SPDX-License-Identifier: MIT OR Apache-2.0
//! Paillier encryption wrapper for the `tecdsa` threshold ECDSA library.
//!
//! This crate is a thin facade over [`fast_paillier`], re-exporting its core
//! types and providing convenience wrappers with consistent naming for the
//! tecdsa workspace.
//!
//! # Re-exported types
//!
//! - [`EncryptionKey`] — the public Paillier encryption key.
//! - [`DecryptionKey`] — the secret Paillier decryption key (wraps primes `p, q`).
//! - [`Ciphertext`], [`Plaintext`], [`Nonce`] — type aliases for the backend
//!   big integer.
//!
//! # Convenience functions
//!
//! - [`keygen`] — generate a fresh Paillier key pair.
//! - [`encrypt`] — encrypt a plaintext with random nonce.
//! - [`decrypt`] — decrypt a ciphertext.
//! - [`add_ciphertexts`] — homomorphic addition of two ciphertexts.
//! - [`scalar_mul_ciphertext`] — homomorphic scalar multiplication.

#[allow(non_snake_case)]
pub mod mta;
pub mod threshold;
pub mod zk;

// Re-export core types from fast-paillier.
// Re-export the backend Integer for callers that need to construct
// plaintexts / nonces directly.
// `backend::Integer` is a re-export of `rug::Integer`; the helper methods this
// crate's callers need (`from_bytes_msf`, `one`, `combine`, ...) live on this
// extension trait and must be in scope to be used.
pub use fast_paillier::{
    backend, backend::BigIntExt, AnyEncryptionKey, AnyEncryptionKeyExt, Ciphertext, DecryptionKey,
    EncryptionKey, Error as PaillierError, Nonce, Plaintext,
};
use rand_core::{CryptoRng, RngCore};

/// Generate a fresh Paillier key pair.
///
/// Internally generates two 1536-bit safe primes for 128-bit security.
///
/// # Errors
///
/// Returns an error if the generated primes are invalid (should not happen
/// under normal operation).
pub fn keygen(rng: &mut (impl RngCore + CryptoRng)) -> Result<DecryptionKey, PaillierError> {
    DecryptionKey::generate(rng)
}

/// Encrypt a plaintext using an encryption key with a randomly sampled nonce.
///
/// The plaintext must be in the range `{-N/2, .., N/2}`.
///
/// # Errors
///
/// Returns an error if the plaintext is out of range.
pub fn encrypt<E: AnyEncryptionKey>(
    ek: &E,
    rng: &mut (impl RngCore + CryptoRng),
    plaintext: &Plaintext,
) -> Result<(Ciphertext, Nonce), PaillierError> {
    ek.encrypt_with_random(rng, plaintext)
}

/// Decrypt a ciphertext using the decryption key.
///
/// Returns the plaintext in `{-N/2, .., N/2}`.
///
/// # Errors
///
/// Returns an error if the ciphertext is not in `Z*_{N^2}`.
pub fn decrypt(dk: &DecryptionKey, ciphertext: &Ciphertext) -> Result<Plaintext, PaillierError> {
    dk.decrypt(ciphertext)
}

/// Homomorphic addition: `Enc(a) + Enc(b) = Enc(a + b)`.
///
/// # Errors
///
/// Returns an error if either ciphertext is not in `Z*_{N^2}`.
pub fn add_ciphertexts(
    ek: &dyn AnyEncryptionKey,
    c1: &Ciphertext,
    c2: &Ciphertext,
) -> Result<Ciphertext, PaillierError> {
    ek.oadd(c1, c2)
}

/// Homomorphic scalar multiplication: `a * Enc(c) = Enc(a * c)`.
///
/// # Errors
///
/// Returns an error if the scalar or ciphertext is out of range.
pub fn scalar_mul_ciphertext(
    ek: &dyn AnyEncryptionKey,
    scalar: &backend::Integer,
    ciphertext: &Ciphertext,
) -> Result<Ciphertext, PaillierError> {
    ek.omul(scalar, ciphertext)
}
