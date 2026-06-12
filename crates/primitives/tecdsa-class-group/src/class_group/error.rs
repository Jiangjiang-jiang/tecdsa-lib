use core::fmt;

pub type Result<T> = core::result::Result<T, ClassGroupError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassGroupError {
    InvalidArgument(String),
    InvalidParameter(String),
    ParseError(String),
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
