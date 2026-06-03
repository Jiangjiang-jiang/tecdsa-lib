// SPDX-License-Identifier: GPL-3.0-or-later
//! LLZ25 error types.

use std::str::FromStr;

use tecdsa_class_group::cl::{Mpz, Qfi};

/// Errors in the LLZ25 protocol.
#[derive(Debug, thiserror::Error)]
pub enum Llz25Error {
    /// CL class-group operation failure.
    #[error("class-group error: {0}")]
    ClassGroup(String),

    /// Invalid proof.
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    /// Protocol violation (wrong round, unknown party, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Signature verification failure.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    /// Generic wrapping for upstream errors.
    #[error("{0}")]
    Other(String),
}

impl From<tecdsa_class_group::cl::ClError> for Llz25Error {
    fn from(e: tecdsa_class_group::cl::ClError) -> Self {
        Self::ClassGroup(e.to_string())
    }
}

impl From<tecdsa_core::TecdsaError> for Llz25Error {
    fn from(e: tecdsa_core::TecdsaError) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<Llz25Error> for tecdsa_core::TecdsaError {
    fn from(e: Llz25Error) -> Self {
        match e {
            Llz25Error::InvalidProof(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Llz25Error::SignatureVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Llz25Error::ClassGroup(msg) | Llz25Error::Protocol(msg) | Llz25Error::Other(msg) => {
                tecdsa_core::TecdsaError::Other(msg)
            }
        }
    }
}

/// Helper to convert a QFI to its (a, b, c) decimal representation.
pub fn qfi_to_abc(
    qfi: &tecdsa_class_group::cl::Qfi,
) -> Result<(String, String, String), Llz25Error> {
    let a = qfi.a().to_string();
    let b = qfi.b().to_string();
    let c = qfi.c().to_string();
    Ok((a, b, c))
}

/// Helper to reconstruct a QFI from its (a, b, c) decimal representation.
pub fn qfi_from_abc(a: &str, b: &str, c: &str) -> Result<tecdsa_class_group::cl::Qfi, Llz25Error> {
    Ok(Qfi::from_abc(
        Mpz::from_str(a).map_err(|e| Llz25Error::ClassGroup(format!("{e}")))?,
        Mpz::from_str(b).map_err(|e| Llz25Error::ClassGroup(format!("{e}")))?,
        Mpz::from_str(c).map_err(|e| Llz25Error::ClassGroup(format!("{e}")))?,
    ))
}
