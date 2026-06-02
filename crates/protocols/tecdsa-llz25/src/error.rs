// SPDX-License-Identifier: GPL-3.0-or-later
//! LLZ25 error types.

/// Errors in the LLZ25 protocol.
#[derive(Debug, thiserror::Error)]
pub enum Llz25Error {
    /// CL class-group operation failure.
    #[error("class-group error: {0}")]
    ClassGroup(String),

    /// Invalid proof.
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    /// Protocol violation (wrong round, unknown party, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Signature verification failure.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    /// Generic wrapping for upstream errors.
    #[error("{0}")]
    Other(String),
}

impl From<tecdsa_class_group::bicycl_glue::ClError> for Llz25Error {
    fn from(e: tecdsa_class_group::bicycl_glue::ClError) -> Self {
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

/// Helper to convert a QFI to its (a, b, c) decimal representation.
pub fn qfi_to_abc(
    ctx: &tecdsa_class_group::bicycl_glue::BicyclContext,
    qfi: &tecdsa_class_group::bicycl_glue::BicyclQfi,
) -> Result<(String, String, String), Llz25Error> {
    let a = qfi
        .a_decimal(ctx)
        .map_err(|e| Llz25Error::ClassGroup(format!("{e}")))?;
    let b = qfi
        .b_decimal(ctx)
        .map_err(|e| Llz25Error::ClassGroup(format!("{e}")))?;
    let c = qfi
        .c_decimal(ctx)
        .map_err(|e| Llz25Error::ClassGroup(format!("{e}")))?;
    Ok((a, b, c))
}

/// Helper to reconstruct a QFI from its (a, b, c) decimal representation.
pub fn qfi_from_abc(
    ctx: &tecdsa_class_group::bicycl_glue::BicyclContext,
    a: &str,
    b: &str,
    c: &str,
) -> Result<tecdsa_class_group::bicycl_glue::BicyclQfi, Llz25Error> {
    tecdsa_class_group::bicycl_glue::BicyclQfi::from_abc_decimal(ctx, a, b, c)
        .map_err(|e| Llz25Error::ClassGroup(format!("{e}")))
}
