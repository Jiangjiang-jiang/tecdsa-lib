use std::str::FromStr;

use tecdsa_class_group::cl::{Mpz, Qfi};

#[derive(Debug, thiserror::Error)]
pub enum TroutError {
    #[error("class-group error: {0}")]
    ClassGroup(#[from] tecdsa_class_group::cl::ClError),

    #[error("bicycl error: {0}")]
    Bicycl(String),

    #[error("proof verification failed: {0}")]
    ProofFailed(String),

    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    #[error("ECDSA verification failed: {0}")]
    EcdsaFailed(String),

    #[error("tecdsa-core: {0}")]
    Core(#[from] tecdsa_core::TecdsaError),
}

pub fn qfi_to_abc(qfi: &tecdsa_class_group::cl::Qfi) -> TroutResult<(String, String, String)> {
    let a = qfi.a().to_string();
    let b = qfi.b().to_string();
    let c = qfi.c().to_string();
    Ok((a, b, c))
}

pub fn qfi_from_abc(a: &str, b: &str, c: &str) -> TroutResult<tecdsa_class_group::cl::Qfi> {
    Ok(Qfi::from_abc(
        Mpz::from_str(a).map_err(|e| TroutError::Bicycl(format!("{e}")))?,
        Mpz::from_str(b).map_err(|e| TroutError::Bicycl(format!("{e}")))?,
        Mpz::from_str(c).map_err(|e| TroutError::Bicycl(format!("{e}")))?,
    ))
}

impl From<TroutError> for tecdsa_core::TecdsaError {
    fn from(e: TroutError) -> Self {
        match e {
            TroutError::ProofFailed(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            TroutError::EcdsaFailed(msg) => tecdsa_core::TecdsaError::InvalidProof(msg),
            TroutError::ClassGroup(inner) => tecdsa_core::TecdsaError::Other(inner.to_string()),
            TroutError::Bicycl(msg) | TroutError::InvalidParam(msg) => {
                tecdsa_core::TecdsaError::Other(msg)
            }
            TroutError::Core(inner) => inner,
        }
    }
}

pub type TroutResult<T> = Result<T, TroutError>;
