// SPDX-License-Identifier: GPL-3.0-or-later
//! Error type for TX25 protocol operations.

/// Error type for TX25 operations.
#[derive(Debug, thiserror::Error)]
pub enum Tx25Error {
    /// CL operation failed.
    #[error("CL operation failed: {0}")]
    ClError(#[from] tecdsa_class_group::bicycl_glue::ClError),

    /// Verification of a ZK proof or commitment failed.
    #[error("verification failed")]
    VerificationFailed,

    /// Invalid input to a TX25 operation.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Scalar conversion between k256::Scalar and decimal string failed.
    #[error("scalar conversion failed: {0}")]
    ScalarConversion(String),
}

impl From<Tx25Error> for tecdsa_core::TecdsaError {
    fn from(e: Tx25Error) -> Self {
        match e {
            Tx25Error::VerificationFailed => {
                tecdsa_core::TecdsaError::InvalidProof("verification failed".into())
            }
            Tx25Error::ClError(inner) => tecdsa_core::TecdsaError::Other(inner.to_string()),
            Tx25Error::InvalidInput(msg) | Tx25Error::ScalarConversion(msg) => {
                tecdsa_core::TecdsaError::Other(msg)
            }
        }
    }
}

/// Result alias for TX25 operations.
pub type Tx25Result<T> = Result<T, Tx25Error>;
