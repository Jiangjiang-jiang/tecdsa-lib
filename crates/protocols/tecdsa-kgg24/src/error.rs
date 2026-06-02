// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error types for the KGG24 two-party ECDSA protocol.

use thiserror::Error;

/// Errors that may occur during the KGG24 two-party ECDSA protocol.
#[derive(Debug, Error)]
pub enum Kgg24Error {
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

    /// Pi_GCD (correct key) proof verification failed.
    #[error("Pi_GCD verification failed: {0}")]
    PiGcdVerification(String),

    /// Pi_eq (loose consistency) proof verification failed.
    #[error("Pi_eq verification failed: {0}")]
    PiEqVerification(String),

    /// Divisibility check failed during signing.
    /// This indicates a potentially malicious P_2 or corrupted ciphertext.
    /// The protocol recommends a refresh rather than a full keygen restart.
    #[error("divisibility check failed: {0}")]
    DivisibilityCheck(String),

    /// Refresh protocol error.
    #[error("refresh error: {0}")]
    Refresh(String),

    /// Invalid protocol state (wrong round, missing data, etc.).
    #[error("protocol state error: {0}")]
    ProtocolState(String),

    /// Round mismatch.
    #[error("round mismatch: expected {expected}, got {got}")]
    RoundMismatch { expected: u16, got: u16 },
}

impl From<Kgg24Error> for tecdsa_core::TecdsaError {
    fn from(e: Kgg24Error) -> Self {
        match e {
            Kgg24Error::DlogVerification(msg)
            | Kgg24Error::EcdsaVerification(msg)
            | Kgg24Error::PiGcdVerification(msg)
            | Kgg24Error::PiEqVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Kgg24Error::CommitmentVerification(msg) => {
                tecdsa_core::TecdsaError::InvalidCommitment(msg)
            }
            Kgg24Error::Paillier(msg)
            | Kgg24Error::DivisibilityCheck(msg)
            | Kgg24Error::Refresh(msg)
            | Kgg24Error::ProtocolState(msg) => tecdsa_core::TecdsaError::Other(msg),
            Kgg24Error::RoundMismatch { expected, got } => {
                tecdsa_core::TecdsaError::RoundMismatch { expected, got }
            }
        }
    }
}
