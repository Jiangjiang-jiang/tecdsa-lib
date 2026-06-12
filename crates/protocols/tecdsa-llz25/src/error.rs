#[derive(Debug, thiserror::Error)]
pub enum Llz25Error {
    #[error("class-group error: {0}")]
    ClassGroup(String),

    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

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
