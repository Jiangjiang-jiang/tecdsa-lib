// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error types for the XAL+21 two-party ECDSA protocol.

use thiserror::Error;

/// Errors that may occur during the XAL+21 two-party ECDSA protocol.
#[derive(Debug, Error)]
pub enum Xal21Error {
    /// DLog proof verification failed.
    #[error("DLog proof verification failed: {0}")]
    DlogVerification(String),

    /// Hash commitment verification failed.
    #[error("commitment verification failed: {0}")]
    CommitmentVerification(String),

    /// Pi_GCD (correct key) proof verification failed.
    #[error("Pi_GCD proof verification failed: {0}")]
    PiGcdVerification(String),

    /// MtA ZK proof verification failed (PiB or PiA).
    #[error("MtA proof verification failed: {0}")]
    MtaProofVerification(String),

    /// Paillier encryption/decryption error.
    #[error("Paillier error: {0}")]
    Paillier(String),

    /// Consistency check failed (Step 2 of offline signing).
    #[error("consistency check failed: {0}")]
    ConsistencyCheck(String),

    /// ECDSA signature verification failed (P_1 checks before output).
    #[error("ECDSA verification failed: {0}")]
    EcdsaVerification(String),

    /// Invalid protocol state (wrong round, missing data, etc.).
    #[error("protocol state error: {0}")]
    ProtocolState(String),

    /// Round mismatch.
    #[error("round mismatch: expected {expected}, got {got}")]
    RoundMismatch { expected: u16, got: u16 },
}

impl From<Xal21Error> for tecdsa_core::TecdsaError {
    fn from(e: Xal21Error) -> Self {
        match e {
            Xal21Error::DlogVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::CommitmentVerification(msg) => {
                tecdsa_core::TecdsaError::InvalidCommitment(msg)
            }
            Xal21Error::PiGcdVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::MtaProofVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::Paillier(msg) => tecdsa_core::TecdsaError::Other(msg),
            Xal21Error::ConsistencyCheck(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::EcdsaVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::ProtocolState(msg) => tecdsa_core::TecdsaError::Other(msg),
            Xal21Error::RoundMismatch { expected, got } => {
                tecdsa_core::TecdsaError::RoundMismatch { expected, got }
            }
        }
    }
}
