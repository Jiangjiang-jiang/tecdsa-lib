// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error types for the ABC+24 two-party ECDSA protocol.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Abc24Error {
    #[error("DLog proof verification failed: {0}")]
    DlogVerification(String),

    #[error("commitment verification failed: {0}")]
    CommitmentVerification(String),

    #[error("Paillier error: {0}")]
    Paillier(String),

    #[error("ECDSA verification failed: {0}")]
    EcdsaVerification(String),

    #[error("DH tuple check failed: {0}")]
    DhTupleCheck(String),

    #[error("ZK proof verification failed: {0}")]
    ZkVerification(String),

    #[error("Pi_GCD (correct key) proof verification failed: {0}")]
    PiGcdVerification(String),

    #[error("PDL verification failed: {0}")]
    PdlVerification(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("protocol state error: {0}")]
    ProtocolState(String),

    #[error("round mismatch: expected {expected}, got {got}")]
    RoundMismatch { expected: u16, got: u16 },
}

impl From<tecdsa_paillier::zk::pdl::PdlError> for Abc24Error {
    fn from(e: tecdsa_paillier::zk::pdl::PdlError) -> Self {
        Self::Paillier(e.to_string())
    }
}

impl From<Abc24Error> for tecdsa_core::TecdsaError {
    fn from(e: Abc24Error) -> Self {
        match e {
            Abc24Error::DlogVerification(msg)
            | Abc24Error::ZkVerification(msg)
            | Abc24Error::DhTupleCheck(msg)
            | Abc24Error::EcdsaVerification(msg)
            | Abc24Error::PiGcdVerification(msg)
            | Abc24Error::PdlVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Abc24Error::CommitmentVerification(msg) => {
                tecdsa_core::TecdsaError::InvalidCommitment(msg)
            }
            Abc24Error::Paillier(msg)
            | Abc24Error::ProtocolState(msg)
            | Abc24Error::InvalidInput(msg) => tecdsa_core::TecdsaError::Other(msg),
            Abc24Error::RoundMismatch { expected, got } => {
                tecdsa_core::TecdsaError::RoundMismatch { expected, got }
            }
        }
    }
}
