// SPDX-License-Identifier: MIT OR Apache-2.0
use thiserror::Error;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error)]
pub enum TecdsaError {
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("invalid commitment: {0}")]
    InvalidCommitment(String),

    #[error("invalid share: {0}")]
    InvalidShare(String),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("protocol abort: {0}")]
    Abort(String),

    #[error("round mismatch: expected {expected}, got {got}")]
    RoundMismatch { expected: u16, got: u16 },

    #[error("unknown sender: {0}")]
    UnknownSender(u16),

    #[error("duplicate message from party {0}")]
    DuplicateMessage(u16),

    #[error("serialization: {0}")]
    Serialization(String),

    #[error("range overflow")]
    RangeOverflow,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = core::result::Result<T, TecdsaError>;
