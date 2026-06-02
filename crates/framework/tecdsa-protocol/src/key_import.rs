// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key import/export traits for threshold ECDSA protocols.
//!
//! These traits are gated behind `key-import` and `key-export` feature flags
//! because they inherently create a Single Point of Failure (SPOF): the full
//! secret key exists in a single process during import/export.

#[cfg(feature = "key-import")]
use rand_core::CryptoRngCore;
#[cfg(any(feature = "key-import", feature = "key-export"))]
use tecdsa_core::TecdsaError;

/// Import a raw secret key into threshold key shares.
///
/// # Security Warning
///
/// This creates a SPOF: the full secret key exists in the calling process.
/// Use only for key migration, not for initial key generation (use interactive
/// DKG instead).
#[cfg(feature = "key-import")]
pub trait KeyImport: super::Protocol {
    fn import_key(
        secret_key: &[u8],
        threshold: u16,
        total: u16,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Self::KeyShare>, TecdsaError>;
}

/// Export threshold key shares back to a raw secret key.
///
/// # Security Warning
///
/// This reconstructs the full secret key in memory. The exported key material
/// must be handled with extreme care (encrypted storage, secure deletion).
#[cfg(feature = "key-export")]
pub trait KeyExport: super::Protocol {
    fn export_key(shares: &[Self::KeyShare]) -> Result<Vec<u8>, TecdsaError>;
}
