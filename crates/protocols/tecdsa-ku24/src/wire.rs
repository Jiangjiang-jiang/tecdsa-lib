// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixed-width encoding of scalars and group elements for KU24 wire messages.
//!
//! KU24 messages are dominated by long vectors of scalars (one per element of
//! the presignature batch), so they are packed into flat, fixed-width blobs
//! rather than `Vec<Vec<u8>>`: with bincode's fixed-int encoding the latter
//! would add eight length bytes per element, which for a batch of `m = 10 000`
//! is a very real overhead.

use elliptic_curve::{
    group::{Curve as CurveGroup, Group},
    sec1::ModulusSize,
    FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;

use crate::error::{Ku24Error, Ku24Result};

/// Encoded length of one group element (SEC1 compressed).
fn point_len<C: TecdsaCurve>() -> usize
where
    FieldBytesSize<C>: ModulusSize,
{
    C::point_to_bytes(&C::generator().to_affine()).len()
}

/// Pack a scalar into `C::SCALAR_BYTES` big-endian bytes.
#[must_use]
pub fn encode_scalar<C: TecdsaCurve>(s: &C::Scalar) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    tecdsa_curve::conv::scalar_to_bytes::<C>(s)
}

/// Pack a slice of scalars into a flat blob.
#[must_use]
pub fn encode_scalars<C: TecdsaCurve>(values: &[C::Scalar]) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut out = Vec::with_capacity(values.len() * C::SCALAR_BYTES);
    for v in values {
        out.extend_from_slice(&tecdsa_curve::conv::scalar_to_bytes::<C>(v));
    }
    out
}

/// Unpack exactly one scalar, rejecting non-canonical encodings.
///
/// # Errors
/// Fails on a wrong length or a value that is not a canonical field element.
pub fn decode_scalar<C: TecdsaCurve>(bytes: &[u8]) -> Ku24Result<C::Scalar>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if bytes.len() != C::SCALAR_BYTES {
        return Err(Ku24Error::Malformed(format!(
            "expected {} scalar bytes, got {}",
            C::SCALAR_BYTES,
            bytes.len()
        )));
    }
    let mut repr = FieldBytes::<C>::default();
    repr.copy_from_slice(bytes);
    Option::from(<C::Scalar as PrimeField>::from_repr(repr))
        .ok_or_else(|| Ku24Error::Malformed("scalar is not canonically reduced".into()))
}

/// Unpack exactly `expected` scalars from a flat blob.
///
/// # Errors
/// Fails on a wrong length or a non-canonical element.
pub fn decode_scalars<C: TecdsaCurve>(bytes: &[u8], expected: usize) -> Ku24Result<Vec<C::Scalar>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let width = C::SCALAR_BYTES;
    if bytes.len() != expected * width {
        return Err(Ku24Error::Malformed(format!(
            "expected {} scalars ({} bytes), got {} bytes",
            expected,
            expected * width,
            bytes.len()
        )));
    }
    bytes.chunks_exact(width).map(decode_scalar::<C>).collect()
}

/// Pack a slice of group elements into a flat blob of SEC1-compressed points.
///
/// # Errors
/// Fails if any element is the identity, which has a variable-width SEC1
/// encoding and never occurs in an honest KU24 execution.
pub fn encode_points<C: TecdsaCurve>(values: &[C::ProjectivePoint]) -> Ku24Result<Vec<u8>>
where
    FieldBytesSize<C>: ModulusSize,
{
    let width = point_len::<C>();
    let mut out = Vec::with_capacity(values.len() * width);
    for v in values {
        if bool::from(v.is_identity()) {
            return Err(Ku24Error::Malformed(
                "refusing to encode the identity element".into(),
            ));
        }
        let bytes = C::point_to_bytes(&v.to_affine());
        debug_assert_eq!(bytes.len(), width);
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

/// Unpack exactly `expected` group elements from a flat blob.
///
/// The identity element is rejected: KU24 aborts on a degenerate `R_i` anyway.
///
/// # Errors
/// Fails on a wrong length, an invalid encoding, or the identity element.
pub fn decode_points<C: TecdsaCurve>(
    bytes: &[u8],
    expected: usize,
) -> Ku24Result<Vec<C::ProjectivePoint>>
where
    FieldBytesSize<C>: ModulusSize,
{
    let width = point_len::<C>();
    if bytes.len() != expected * width {
        return Err(Ku24Error::Malformed(format!(
            "expected {} points ({} bytes), got {} bytes",
            expected,
            expected * width,
            bytes.len()
        )));
    }
    bytes
        .chunks_exact(width)
        .map(|chunk| {
            let affine =
                C::point_from_bytes(chunk).map_err(|e| Ku24Error::Malformed(e.to_string()))?;
            let point = C::ProjectivePoint::from(affine);
            if bool::from(point.is_identity()) {
                return Err(Ku24Error::Malformed("point is the identity".into()));
            }
            Ok(point)
        })
        .collect()
}

/// Pack a single group element.
///
/// # Errors
/// Fails if the element is the identity.
pub fn encode_point<C: TecdsaCurve>(value: &C::ProjectivePoint) -> Ku24Result<Vec<u8>>
where
    FieldBytesSize<C>: ModulusSize,
{
    encode_points::<C>(core::slice::from_ref(value))
}

/// Unpack a single group element.
///
/// # Errors
/// Fails on an invalid encoding or the identity element.
pub fn decode_point<C: TecdsaCurve>(bytes: &[u8]) -> Ku24Result<C::ProjectivePoint>
where
    FieldBytesSize<C>: ModulusSize,
{
    Ok(decode_points::<C>(bytes, 1)?[0])
}
