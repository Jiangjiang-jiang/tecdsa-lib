//! Error type for the crate.

use core::fmt;

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, ClassGroupError>;

/// Errors produced while constructing parameters, parsing, or validating inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassGroupError {
    /// A supplied value violated a precondition (out of range, wrong sign, ...).
    InvalidArgument(String),
    /// The parameters do not satisfy the CL-HSM_qk setup constraints.
    InvalidParameter(String),
    /// A string could not be parsed into an integer.
    ParseError(String),
    /// A value was outside the bound required by the scheme.
    OutOfBounds(String),
}

impl fmt::Display for ClassGroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClassGroupError::InvalidArgument(s) => write!(f, "invalid argument: {s}"),
            ClassGroupError::InvalidParameter(s) => write!(f, "invalid parameter: {s}"),
            ClassGroupError::ParseError(s) => write!(f, "parse error: {s}"),
            ClassGroupError::OutOfBounds(s) => write!(f, "out of bounds: {s}"),
        }
    }
}

impl std::error::Error for ClassGroupError {}
