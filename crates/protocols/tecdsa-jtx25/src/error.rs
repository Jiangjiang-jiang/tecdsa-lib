// SPDX-License-Identifier: GPL-3.0-or-later
#[derive(Debug, thiserror::Error)]
pub enum Jtx25Error {
    #[error("CL operation failed: {0}")]
    ClError(#[from] tecdsa_class_group::cl::ClError),
    #[error("verification failed")]
    VerificationFailed,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("scalar conversion: {0}")]
    ScalarConversion(String),
}

impl From<Jtx25Error> for tecdsa_core::TecdsaError {
    fn from(e: Jtx25Error) -> Self {
        match e {
            Jtx25Error::VerificationFailed => {
                tecdsa_core::TecdsaError::InvalidProof("verification failed".into())
            }
            Jtx25Error::ClError(inner) => tecdsa_core::TecdsaError::Other(inner.to_string()),
            Jtx25Error::InvalidInput(msg) | Jtx25Error::ScalarConversion(msg) => {
                tecdsa_core::TecdsaError::Other(msg)
            }
        }
    }
}
