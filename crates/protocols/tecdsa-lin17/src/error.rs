// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error types for the Lin17 two-party ECDSA protocol.

use thiserror::Error;

/// Errors that may occur during the Lindell 2017 two-party ECDSA protocol.
#[derive(Debug, Error)]
pub enum Lin17Error {
    /// DLog proof verification failed.
    #[error("DLog proof verification failed: {0}")]
    DlogVerification(String),

    /// Hash commitment verification failed.
    #[error("commitment verification failed: {0}")]
    CommitmentVerification(String),

    /// Paillier encryption/decryption error.
    #[error("Paillier error: {0}")]
    Paillier(String),

    /// ECDSA signature verification failed (P_1 checks before output).
    #[error("ECDSA verification failed: {0}")]
    EcdsaVerification(String),

    /// Invalid protocol state (wrong round, missing data, etc.).
    #[error("protocol state error: {0}")]
    ProtocolState(String),

    /// NICorrectKeyProof verification failed.
    #[error("correct key proof verification failed: {0}")]
    CorrectKeyVerification(String),

    /// PDL (Paillier Discrete Log) verification failed.
    #[error("PDL verification failed: {0}")]
    PdlVerification(String),

    /// Range proof verification failed.
    #[error("range proof verification failed: {0}")]
    RangeProofVerification(String),

    /// Ciphertext validation failed.
    #[error("ciphertext validation failed: {0}")]
    CiphertextValidation(String),

    /// Round mismatch.
    #[error("round mismatch: expected {expected}, got {got}")]
    RoundMismatch { expected: u16, got: u16 },
}

impl From<tecdsa_paillier::zk::pdl::PdlError> for Lin17Error {
    fn from(e: tecdsa_paillier::zk::pdl::PdlError) -> Self {
        Self::Paillier(e.to_string())
    }
}

impl From<tecdsa_paillier::zk::range_ni::RangeProofNiError> for Lin17Error {
    fn from(e: tecdsa_paillier::zk::range_ni::RangeProofNiError) -> Self {
        Lin17Error::Paillier(e.to_string())
    }
}

impl From<Lin17Error> for tecdsa_core::TecdsaError {
    fn from(e: Lin17Error) -> Self {
        match e {
            Lin17Error::DlogVerification(msg)
            | Lin17Error::EcdsaVerification(msg)
            | Lin17Error::CorrectKeyVerification(msg)
            | Lin17Error::PdlVerification(msg)
            | Lin17Error::RangeProofVerification(msg) => {
                tecdsa_core::TecdsaError::InvalidProof(msg)
            }
            Lin17Error::CommitmentVerification(msg) => {
                tecdsa_core::TecdsaError::InvalidCommitment(msg)
            }
            Lin17Error::Paillier(msg)
            | Lin17Error::ProtocolState(msg)
            | Lin17Error::CiphertextValidation(msg) => tecdsa_core::TecdsaError::Other(msg),
            Lin17Error::RoundMismatch { expected, got } => {
                tecdsa_core::TecdsaError::RoundMismatch { expected, got }
            }
        }
    }
}
