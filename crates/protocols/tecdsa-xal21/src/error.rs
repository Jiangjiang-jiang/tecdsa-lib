use thiserror::Error;

#[derive(Debug, Error)]
pub enum Xal21Error {
    #[error("DLog proof verification failed: {0}")]
    DlogVerification(String),

    #[error("commitment verification failed: {0}")]
    CommitmentVerification(String),

    #[error("Pi_GCD proof verification failed: {0}")]
    PiGcdVerification(String),

    #[error("MtA proof verification failed: {0}")]
    MtaProofVerification(String),

    #[error("Paillier error: {0}")]
    Paillier(String),

    #[error("consistency check failed: {0}")]
    ConsistencyCheck(String),

    #[error("ECDSA verification failed: {0}")]
    EcdsaVerification(String),

    #[error("protocol state error: {0}")]
    ProtocolState(String),

    #[error("round mismatch: expected {expected}, got {got}")]
    RoundMismatch { expected: u16, got: u16 },
}

impl From<Xal21Error> for tecdsa_core::TecdsaError {
    fn from(e: Xal21Error) -> Self {
        match e {
            Xal21Error::DlogVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::CommitmentVerification(msg) => {
                tecdsa_core::TecdsaError::InvalidCommitment(msg)
            }
            Xal21Error::PiGcdVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::MtaProofVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::Paillier(msg) => tecdsa_core::TecdsaError::Other(msg),
            Xal21Error::ConsistencyCheck(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::EcdsaVerification(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            Xal21Error::ProtocolState(msg) => tecdsa_core::TecdsaError::Other(msg),
            Xal21Error::RoundMismatch { expected, got } => {
                tecdsa_core::TecdsaError::RoundMismatch { expected, got }
            }
        }
    }
}
