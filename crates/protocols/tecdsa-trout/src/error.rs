// SPDX-License-Identifier: GPL-3.0-or-later
//! Error types for the Trout protocol.

/// Errors that can occur during the Trout protocol execution.
#[derive(Debug, thiserror::Error)]
pub enum TroutError {
    /// Class-group operation failure.
    #[error("class-group error: {0}")]
    ClassGroup(#[from] tecdsa_class_group::bicycl_glue::ClError),

    /// BICYCL low-level error (QFI serialization, etc.).
    #[error("bicycl error: {0}")]
    Bicycl(String),

    /// Invalid proof verification.
    #[error("proof verification failed: {0}")]
    ProofFailed(String),

    /// Invalid parameter.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    /// ECDSA verification failure.
    #[error("ECDSA verification failed: {0}")]
    EcdsaFailed(String),

    /// Core library error.
    #[error("tecdsa-core: {0}")]
    Core(#[from] tecdsa_core::TecdsaError),
}

/// Helper to convert a QFI to its (a, b, c) decimal representation.
///
/// Uses the methods directly on the `Qfi` type (from bicycl-rs via
/// `tecdsa_class_group::bicycl_glue::BicyclQfi`).
pub fn qfi_to_abc(
    ctx: &tecdsa_class_group::bicycl_glue::BicyclContext,
    qfi: &tecdsa_class_group::bicycl_glue::BicyclQfi,
) -> TroutResult<(String, String, String)> {
    let a = qfi
        .a_decimal(ctx)
        .map_err(|e| TroutError::Bicycl(format!("{e}")))?;
    let b = qfi
        .b_decimal(ctx)
        .map_err(|e| TroutError::Bicycl(format!("{e}")))?;
    let c = qfi
        .c_decimal(ctx)
        .map_err(|e| TroutError::Bicycl(format!("{e}")))?;
    Ok((a, b, c))
}

/// Helper to reconstruct a QFI from its (a, b, c) decimal representation.
pub fn qfi_from_abc(
    ctx: &tecdsa_class_group::bicycl_glue::BicyclContext,
    a: &str,
    b: &str,
    c: &str,
) -> TroutResult<tecdsa_class_group::bicycl_glue::BicyclQfi> {
    tecdsa_class_group::bicycl_glue::BicyclQfi::from_abc_decimal(ctx, a, b, c)
        .map_err(|e| TroutError::Bicycl(format!("{e}")))
}

/// Helper to negate a QFI element in the class group.
pub fn qfi_neg(
    ctx: &tecdsa_class_group::bicycl_glue::BicyclContext,
    qfi: &tecdsa_class_group::bicycl_glue::BicyclQfi,
) -> TroutResult<tecdsa_class_group::bicycl_glue::BicyclQfi> {
    qfi.neg(ctx).map_err(|e| TroutError::Bicycl(format!("{e}")))
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

/// Result alias for Trout operations.
pub type TroutResult<T> = Result<T, TroutError>;
