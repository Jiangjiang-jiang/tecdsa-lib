// SPDX-License-Identifier: MIT OR Apache-2.0
use elliptic_curve::{
    group::Curve as CurveGroup, ops::LinearCombination, sec1::ModulusSize, CurveArithmetic, Field,
    FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;

/// Message digest prepared for signing.
///
/// Wraps a scalar that is the hash-to-scalar output of the message to sign.
/// This type is protocol-agnostic — all threshold ECDSA schemes use it.
#[derive(Debug, Clone, Copy)]
pub struct DataToSign<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    digest: <C as CurveArithmetic>::Scalar,
}

impl<C: TecdsaCurve> DataToSign<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn from_digest(digest: <C as CurveArithmetic>::Scalar) -> Self {
        Self { digest }
    }

    #[must_use]
    pub fn digest(&self) -> &<C as CurveArithmetic>::Scalar {
        &self.digest
    }
}

/// A complete ECDSA signature `(r, s)`.
#[derive(Debug, Clone)]
pub struct Signature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub r: <C as CurveArithmetic>::Scalar,
    pub s: <C as CurveArithmetic>::Scalar,
}

/// Normalize `s` to low-S form (BIP-146): pick `min(s, -s)` by big-endian byte order.
#[must_use]
pub fn low_s_normalize<C: TecdsaCurve>(s: C::Scalar) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let s_bytes = s.to_repr();
    let neg_s = -s;
    let neg_s_bytes = neg_s.to_repr();
    let s_slice: &[u8] = s_bytes.as_ref();
    let neg_s_slice: &[u8] = neg_s_bytes.as_ref();
    if s_slice > neg_s_slice {
        neg_s
    } else {
        s
    }
}

/// Verify an ECDSA signature `(r, s)` against public key and message digest.
///
/// Checks: `s⁻¹ · (m·G + r·PK)` has x-coordinate equal to `r`.
pub fn verify_ecdsa<C: TecdsaCurve>(
    sig: &Signature<C>,
    public_key: &C::ProjectivePoint,
    message: &DataToSign<C>,
) -> tecdsa_core::Result<()>
where
    FieldBytesSize<C>: ModulusSize,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let m = *message.digest();
    let s_inv = sig
        .s
        .invert()
        .into_option()
        .ok_or_else(|| TecdsaError::InvalidShare("s is zero, cannot invert".into()))?;
    let u1 = m * s_inv;
    let u2 = sig.r * s_inv;
    let check_point = C::ProjectivePoint::lincomb(&[(C::generator(), u1), (*public_key, u2)]);
    let check_r = C::xcoord_mod_q(&check_point.to_affine());

    if check_r != sig.r {
        return Err(TecdsaError::InvalidProof(
            "ECDSA verification failed: reconstructed r does not match".into(),
        ));
    }
    Ok(())
}
