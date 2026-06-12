use thiserror::Error;

#[derive(Debug, Error)]
pub enum Kgg24Error {
    #[error("DLog proof verification failed: {0}")]
    DlogVerification(String),

    #[error("commitment verification failed: {0}")]
    CommitmentVerification(String),

    #[error("Paillier error: {0}")]
    Paillier(String),

    #[error("ECDSA verification failed: {0}")]
    EcdsaVerification(String),

    #[error("Pi_GCD verification failed: {0}")]
    PiGcdVerification(String),

    #[error("Pi_eq verification failed: {0}")]
    PiEqVerification(String),

    #[error("divisibility check failed: {0}")]
    DivisibilityCheck(String),

    #[error("refresh error: {0}")]
    Refresh(String),

    #[error("protocol state error: {0}")]
    ProtocolState(String),

    #[error("round mismatch: expected {expected}, got {got}")]
    RoundMismatch { expected: u16, got: u16 },
}

impl From<Kgg24Error> for tecdsa_core::TecdsaError {
    fn from(e: Kgg24Error) -> Self {
        match e {
            Kgg24Error::DlogVerification(msg)
            | Kgg24Error::EcdsaVerification(msg)
            | Kgg24Error::PiGcdVerification(msg)
            | Kgg24Error::PiEqVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Kgg24Error::CommitmentVerification(msg) => {
                tecdsa_core::TecdsaError::InvalidCommitment(msg)
            }
            Kgg24Error::Paillier(msg)
            | Kgg24Error::DivisibilityCheck(msg)
            | Kgg24Error::Refresh(msg)
            | Kgg24Error::ProtocolState(msg) => tecdsa_core::TecdsaError::Other(msg),
            Kgg24Error::RoundMismatch { expected, got } => {
                tecdsa_core::TecdsaError::RoundMismatch { expected, got }
            }
        }
    }
}
