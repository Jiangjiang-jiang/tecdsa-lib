use thiserror::Error;

#[derive(Debug, Error)]
pub enum Lin17Error {
    #[error("DLog proof verification failed: {0}")]
    DlogVerification(String),

    #[error("commitment verification failed: {0}")]
    CommitmentVerification(String),

    #[error("Paillier error: {0}")]
    Paillier(String),

    #[error("ECDSA verification failed: {0}")]
    EcdsaVerification(String),

    #[error("protocol state error: {0}")]
    ProtocolState(String),

    #[error("correct key proof verification failed: {0}")]
    CorrectKeyVerification(String),

    #[error("PDL verification failed: {0}")]
    PdlVerification(String),

    #[error("range proof verification failed: {0}")]
    RangeProofVerification(String),

    #[error("ciphertext validation failed: {0}")]
    CiphertextValidation(String),

    #[error("round mismatch: expected {expected}, got {got}")]
    RoundMismatch { expected: u16, got: u16 },
}

impl From<tecdsa_paillier::zk::pdl::PdlError> for Lin17Error {
    fn from(e: tecdsa_paillier::zk::pdl::PdlError) -> Self {
        Self::Paillier(e.to_string())
    }
}

impl From<tecdsa_paillier::zk::range_ni::RangeProofNiError> for Lin17Error {
    fn from(e: tecdsa_paillier::zk::range_ni::RangeProofNiError) -> Self {
        Lin17Error::Paillier(e.to_string())
    }
}

impl From<Lin17Error> for tecdsa_core::TecdsaError {
    fn from(e: Lin17Error) -> Self {
        match e {
            Lin17Error::DlogVerification(msg)
            | Lin17Error::EcdsaVerification(msg)
            | Lin17Error::CorrectKeyVerification(msg)
            | Lin17Error::PdlVerification(msg)
            | Lin17Error::RangeProofVerification(msg) => {
                tecdsa_core::TecdsaError::InvalidProof(msg)
            }
            Lin17Error::CommitmentVerification(msg) => {
                tecdsa_core::TecdsaError::InvalidCommitment(msg)
            }
            Lin17Error::Paillier(msg)
            | Lin17Error::ProtocolState(msg)
            | Lin17Error::CiphertextValidation(msg) => tecdsa_core::TecdsaError::Other(msg),
            Lin17Error::RoundMismatch { expected, got } => {
                tecdsa_core::TecdsaError::RoundMismatch { expected, got }
            }
        }
    }
}
