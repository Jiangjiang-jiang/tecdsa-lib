// SPDX-License-Identifier: MIT OR Apache-2.0
//! LLZ25 error types.

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
