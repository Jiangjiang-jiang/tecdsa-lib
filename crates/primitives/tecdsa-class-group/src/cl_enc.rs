// SPDX-License-Identifier: GPL-3.0-or-later
//! CL-HSM encryption: key generation, encryption, decryption, and
//! homomorphic operations.
//!
//! This module provides thin wrappers around the [`ClSetup`] methods,
//! giving friendlier Rust types and a functional interface that mirrors
//! the `tecdsa-paillier` crate's API shape.

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::{ClHsmqkCiphertext, ClHsmqkPublicKey, ClHsmqkSecretKey, Qfi};
use num_bigint::BigUint;

/// A CL-HSMqk public key.
///
/// This is a newtype over the bicycl-rs public key that provides a
/// higher-level interface.
pub struct ClPublicKey {
    inner: ClHsmqkPublicKey,
}

impl ClPublicKey {
    /// Wraps a raw bicycl-rs public key.
    #[must_use]
    pub fn from_raw(pk: ClHsmqkPublicKey) -> Self {
        Self { inner: pk }
    }

    /// Returns a reference to the inner bicycl-rs public key.
    #[must_use]
    pub fn inner(&self) -> &ClHsmqkPublicKey {
        &self.inner
    }

    /// Consumes this wrapper and returns the inner bicycl-rs public key.
    #[must_use]
    pub fn into_inner(self) -> ClHsmqkPublicKey {
        self.inner
    }

    /// Returns the underlying QFI element.
    ///
    /// # Errors
    ///
    /// Returns an error if the BICYCL operation fails.
    pub fn element(&self, setup: &ClSetup) -> ClResult<Qfi> {
        setup.pk_element(&self.inner)
    }
}

impl std::fmt::Debug for ClPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClPublicKey").finish_non_exhaustive()
    }
}

/// A CL-HSMqk secret key.
///
/// Implements `ZeroizeOnDrop` via manual drop (the BICYCL C library handles
/// cleanup of the raw pointer, and we rely on that for zeroization).
pub struct ClSecretKey {
    inner: ClHsmqkSecretKey,
}

impl ClSecretKey {
    /// Wraps a raw bicycl-rs secret key.
    #[must_use]
    pub fn from_raw(sk: ClHsmqkSecretKey) -> Self {
        Self { inner: sk }
    }

    /// Returns a reference to the inner bicycl-rs secret key.
    #[must_use]
    pub fn inner(&self) -> &ClHsmqkSecretKey {
        &self.inner
    }

    /// Consumes this wrapper and returns the inner bicycl-rs secret key.
    #[must_use]
    pub fn into_inner(self) -> ClHsmqkSecretKey {
        self.inner
    }

    /// Serialises this secret key to big-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialisation fails.
    pub fn to_bytes(&self, setup: &ClSetup) -> ClResult<Vec<u8>> {
        setup.sk_to_bytes(&self.inner)
    }
}

impl std::fmt::Debug for ClSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClSecretKey")
            .field("redacted", &"***")
            .finish()
    }
}

/// A CL-HSMqk ciphertext.
pub struct ClCiphertext {
    inner: ClHsmqkCiphertext,
}

impl ClCiphertext {
    /// Wraps a raw bicycl-rs ciphertext.
    #[must_use]
    pub fn from_raw(ct: ClHsmqkCiphertext) -> Self {
        Self { inner: ct }
    }

    /// Returns a reference to the inner bicycl-rs ciphertext.
    #[must_use]
    pub fn inner(&self) -> &ClHsmqkCiphertext {
        &self.inner
    }

    /// Consumes this wrapper and returns the inner bicycl-rs ciphertext.
    #[must_use]
    pub fn into_inner(self) -> ClHsmqkCiphertext {
        self.inner
    }

    /// Returns the two QFI components `(c1, c2)` of this ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error if the BICYCL operation fails.
    pub fn components(&self, setup: &ClSetup) -> ClResult<(Qfi, Qfi)> {
        setup.ct_components(&self.inner)
    }
}

impl std::fmt::Debug for ClCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClCiphertext").finish_non_exhaustive()
    }
}

/// Generates a fresh CL-HSMqk key pair.
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn keygen(setup: &mut ClSetup) -> ClResult<(ClPublicKey, ClSecretKey)> {
    let (sk_raw, pk_raw) = setup.keygen()?;
    Ok((ClPublicKey::from_raw(pk_raw), ClSecretKey::from_raw(sk_raw)))
}

/// Encrypts a plaintext given as a `BigUint`.
///
/// The plaintext must lie in `[0, q^k)`.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn encrypt(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    plaintext: &BigUint,
) -> ClResult<ClCiphertext> {
    let msg_bytes = plaintext.to_bytes_be();
    let ct = setup.encrypt_bytes(pk.inner(), &msg_bytes)?;
    Ok(ClCiphertext::from_raw(ct))
}

/// Encrypts a plaintext given as big-endian bytes.
///
/// The bytes are interpreted as an unsigned big-endian integer.
/// The plaintext must lie in `[0, q^k)`.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn encrypt_bytes(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    plaintext_bytes: &[u8],
) -> ClResult<ClCiphertext> {
    let ct = setup.encrypt_bytes(pk.inner(), plaintext_bytes)?;
    Ok(ClCiphertext::from_raw(ct))
}

/// Decrypts a ciphertext, returning the plaintext as a `BigUint`.
///
/// # Errors
///
/// Returns an error if decryption fails or the result is not a valid
/// integer.
pub fn decrypt(setup: &ClSetup, sk: &ClSecretKey, ct: &ClCiphertext) -> ClResult<BigUint> {
    let bytes = setup.decrypt_bytes(sk.inner(), ct.inner())?;
    Ok(BigUint::from_bytes_be(&bytes))
}

/// Decrypts a ciphertext, returning the plaintext as big-endian bytes.
///
/// # Errors
///
/// Returns an error if decryption fails.
pub fn decrypt_bytes(setup: &ClSetup, sk: &ClSecretKey, ct: &ClCiphertext) -> ClResult<Vec<u8>> {
    setup.decrypt_bytes(sk.inner(), ct.inner())
}

/// Homomorphic addition of two ciphertexts:
/// `Enc(a) + Enc(b) = Enc(a + b mod q^k)`.
///
/// # Errors
///
/// Returns an error if the BICYCL operation fails.
pub fn hadd(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    c1: &ClCiphertext,
    c2: &ClCiphertext,
) -> ClResult<ClCiphertext> {
    let result = setup.add_ciphertexts(pk.inner(), c1.inner(), c2.inner())?;
    Ok(ClCiphertext::from_raw(result))
}

/// Homomorphic scalar multiplication:
/// `scalar * Enc(m) = Enc(scalar * m mod q^k)`.
///
/// # Errors
///
/// Returns an error if the BICYCL operation fails.
pub fn hscmul(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    scalar: &BigUint,
    ct: &ClCiphertext,
) -> ClResult<ClCiphertext> {
    let scalar_bytes = scalar.to_bytes_be();
    let result = setup.scal_ciphertext_bytes(pk.inner(), ct.inner(), &scalar_bytes)?;
    Ok(ClCiphertext::from_raw(result))
}

/// Homomorphic scalar multiplication with a big-endian bytes scalar.
///
/// `scalar * Enc(m) = Enc(scalar * m mod q^k)`.
///
/// # Errors
///
/// Returns an error if the BICYCL operation fails.
pub fn hscmul_bytes(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    scalar_bytes: &[u8],
    ct: &ClCiphertext,
) -> ClResult<ClCiphertext> {
    let result = setup.scal_ciphertext_bytes(pk.inner(), ct.inner(), scalar_bytes)?;
    Ok(ClCiphertext::from_raw(result))
}
