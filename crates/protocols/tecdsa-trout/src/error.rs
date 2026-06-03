// SPDX-License-Identifier: GPL-3.0-or-later
//! Error types for the Trout protocol.

use std::str::FromStr;

use tecdsa_class_group::cl::{Mpz, Qfi};

/// Errors that can occur during the Trout protocol execution.
#[derive(Debug, thiserror::Error)]
pub enum TroutError {
    /// Class-group operation failure.
    #[error("class-group error: {0}")]
    ClassGroup(#[from] tecdsa_class_group::cl::ClError),

    /// BICYCL low-level error (QFI serialization, etc.).
    #[error("bicycl error: {0}")]
    Bicycl(String),

    /// Invalid proof verification.
    #[error("proof verification failed: {0}")]
    ProofFailed(String),

    /// Invalid parameter.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    /// ECDSA verification failure.
    #[error("ECDSA verification failed: {0}")]
    EcdsaFailed(String),

    /// Core library error.
    #[error("tecdsa-core: {0}")]
    Core(#[from] tecdsa_core::TecdsaError),
}

/// Helper to convert a QFI to its (a, b, c) decimal representation.
///
/// Uses the methods directly on the `Qfi` type (from bicycl-rs via
/// `tecdsa_class_group::bicycl_glue::Qfi`).
pub fn qfi_to_abc(qfi: &tecdsa_class_group::cl::Qfi) -> TroutResult<(String, String, String)> {
    let a = qfi.a().to_string();
    let b = qfi.b().to_string();
    let c = qfi.c().to_string();
    Ok((a, b, c))
}

/// Helper to reconstruct a QFI from its (a, b, c) decimal representation.
pub fn qfi_from_abc(a: &str, b: &str, c: &str) -> TroutResult<tecdsa_class_group::cl::Qfi> {
    Ok(Qfi::from_abc(
        Mpz::from_str(a).map_err(|e| TroutError::Bicycl(format!("{e}")))?,
        Mpz::from_str(b).map_err(|e| TroutError::Bicycl(format!("{e}")))?,
        Mpz::from_str(c).map_err(|e| TroutError::Bicycl(format!("{e}")))?,
    ))
}

impl From<TroutError> for tecdsa_core::TecdsaError {
    fn from(e: TroutError) -> Self {
        match e {
            TroutError::ProofFailed(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            TroutError::EcdsaFailed(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            TroutError::ClassGroup(inner) => tecdsa_core::TecdsaError::Other(inner.to_string()),
            TroutError::Bicycl(msg) | TroutError::InvalidParam(msg) => {
                tecdsa_core::TecdsaError::Other(msg)
            }
            TroutError::Core(inner) => inner,
        }
    }
}

/// Result alias for Trout operations.
pub type TroutResult<T> = Result<T, TroutError>;
