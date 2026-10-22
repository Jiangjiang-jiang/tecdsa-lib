// SPDX-License-Identifier: MIT OR Apache-2.0
//! Paillier encryption, ZK proofs and MtA for the `tecdsa` threshold ECDSA library.
//!
//! [`scheme`] holds the encryption scheme, [`zk`] the proofs, [`mta`] the
//! multiplicative-to-additive conversions and [`threshold`] threshold decryption.

#[allow(non_snake_case)]
pub mod mta;
pub mod scheme;
pub mod threshold;
pub mod zk;

pub use scheme::{
    AnyEncryptionKey, Ciphertext, DecryptionKey, EncryptionKey, Error as PaillierError, Nonce,
    Plaintext,
};
// Re-exported so callers get `Integer`'s helper methods without also
// depending on tecdsa-bigint directly.
pub use tecdsa_bigint::BigIntExt;
