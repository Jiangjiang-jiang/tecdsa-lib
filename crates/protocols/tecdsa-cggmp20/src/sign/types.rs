// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signing-related types for the CGGMP20 threshold ECDSA protocol.
//!
//! `DataToSign` and `Signature` are re-exported from `tecdsa-protocol` (universal ECDSA types).
//! `Presignature`, `PresignaturePublicData`, `PresignatureCommitment`, and `PartialSignature`
//! are CGGMP20-specific.

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
pub use tecdsa_protocol::{DataToSign, Signature};
use zeroize::Zeroize;

/// Output of the presigning protocol.
#[derive(Clone)]
pub struct Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub big_r: C::ProjectivePoint,
    pub k_tilde: <C as CurveArithmetic>::Scalar,
    pub chi_tilde: <C as CurveArithmetic>::Scalar,
}

impl<C: TecdsaCurve> Zeroize for Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k_tilde.zeroize();
        self.chi_tilde.zeroize();
    }
}

/// Public portion of a presignature (safe to broadcast).
#[derive(Debug, Clone)]
pub struct PresignaturePublicData<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub big_r: C::ProjectivePoint,
    pub commitments: Vec<PresignatureCommitment<C>>,
}

/// Per-party commitment used to verify partial signatures.
#[derive(Debug, Clone)]
pub struct PresignatureCommitment<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub tilde_delta: C::ProjectivePoint,
    pub tilde_s: C::ProjectivePoint,
}

/// A single party's partial signature contribution.
#[derive(Debug, Clone)]
pub struct PartialSignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub sigma: <C as CurveArithmetic>::Scalar,
}
