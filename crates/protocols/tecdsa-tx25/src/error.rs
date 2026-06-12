#[derive(Debug, thiserror::Error)]
pub enum Tx25Error {
    #[error("CL operation failed: {0}")]
    ClError(#[from] tecdsa_class_group::cl::ClError),

    #[error("verification failed")]
    VerificationFailed,

    #[error("invalid input: {0}")]
    InvalidInput(String),

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

pub type Tx25Result<T> = Result<T, Tx25Error>;
