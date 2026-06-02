// SPDX-License-Identifier: MIT OR Apache-2.0
//! Joye-Libert encryption scheme for the `tecdsa` threshold ECDSA library.
//!
//! Implements the Joye-Libert (JL) cryptosystem as used in the XAL23 protocol.
//! The scheme encrypts messages in `Z_{2^k}` under a composite modulus
//! `N = p*q` where `p = 2^k * p' + 1` (with `p'` an odd prime) and
//! `q = 2*q' + 1` (a safe prime).
//!
//! # Modules
//!
//! - [`kgen`] — key generation at multiple security levels
//! - [`enc_dec`] — encryption and decryption
//! - [`hom`] — homomorphic operations (addition, scalar multiplication)
//! - [`zk`] — zero-knowledge proof stubs (only `zkjl_enc` is functional)
//! - [`mta`] — multiplicative-to-additive share conversion stubs

pub mod enc_dec;
pub mod hom;
pub mod kgen;
pub mod mta;
pub mod zk;

pub use enc_dec::{decrypt, encrypt, JlCiphertext};
pub use hom::{hadd, hscmul};
pub use kgen::{
    generate_keypair, generate_keypair_with_qnr, JlPublicKey, JlSecretKey, SecurityLevel,
};
