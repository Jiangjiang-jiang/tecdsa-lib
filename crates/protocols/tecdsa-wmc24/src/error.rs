#[derive(Debug, thiserror::Error)]
pub enum Wmc24Error {
    #[error("CL operation failed: {0}")]
    ClError(#[from] tecdsa_class_group::cl::ClError),
    #[error("verification failed")]
    VerificationFailed,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("scalar conversion: {0}")]
    ScalarConversion(String),
}

impl From<Wmc24Error> for tecdsa_core::TecdsaError {
    fn from(e: Wmc24Error) -> Self {
        match e {
            Wmc24Error::VerificationFailed => {
                tecdsa_core::TecdsaError::InvalidProof("verification failed".into())
            }
            Wmc24Error::ClError(inner) => tecdsa_core::TecdsaError::Other(inner.to_string()),
            Wmc24Error::InvalidInput(msg) | Wmc24Error::ScalarConversion(msg) => {
                tecdsa_core::TecdsaError::Other(msg)
            }
        }
    }
}
