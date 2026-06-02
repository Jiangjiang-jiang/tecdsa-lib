// SPDX-License-Identifier: MIT OR Apache-2.0
//! Scalar <-> big-endian byte conversions for use with Paillier big integers.

use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};

use crate::TecdsaCurve;

/// Serialize a scalar to big-endian bytes.
#[must_use]
pub fn scalar_to_bytes<C: TecdsaCurve>(s: &C::Scalar) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let repr = s.to_repr();
    let slice: &[u8] = repr.as_ref();
    slice.to_vec()
}

/// Convert big-endian bytes to a scalar by reducing modulo the group order.
///
/// Returns `Scalar::ZERO` if the reduction yields an invalid representation
/// (should not happen after mod-q reduction, but provides defense in depth).
#[must_use]
pub fn bytes_to_scalar<C: TecdsaCurve>(bytes: &[u8]) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_traits::One;

    let value = BigUint::from_bytes_be(bytes);

    let q_bytes = scalar_to_bytes::<C>(&(-C::Scalar::ONE));
    let q = BigUint::from_bytes_be(&q_bytes) + BigUint::one();

    let reduced = value.mod_floor(&q);
    let reduced_bytes = reduced.to_bytes_be();

    let mut fb = FieldBytes::<C>::default();
    let fb_len = fb.len();
    if reduced_bytes.len() >= fb_len {
        fb.copy_from_slice(&reduced_bytes[reduced_bytes.len() - fb_len..]);
    } else {
        fb[fb_len - reduced_bytes.len()..].copy_from_slice(&reduced_bytes);
    }
    Option::from(<C::Scalar as PrimeField>::from_repr(fb)).unwrap_or_else(C::Scalar::default)
}

/// Convert a `BigUint` to a scalar, reducing modulo the group order.
#[must_use]
pub fn biguint_to_scalar<C: TecdsaCurve>(val: &num_bigint::BigUint) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    bytes_to_scalar::<C>(&val.to_bytes_be())
}

/// Convert a scalar to a `BigUint` (big-endian unsigned).
#[must_use]
pub fn scalar_to_biguint<C: TecdsaCurve>(s: &C::Scalar) -> num_bigint::BigUint
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    num_bigint::BigUint::from_bytes_be(&scalar_to_bytes::<C>(s))
}

/// Returns the group order `q` as a `BigUint`.
#[must_use]
pub fn curve_order<C: TecdsaCurve>() -> num_bigint::BigUint
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use num_traits::One;
    scalar_to_biguint::<C>(&(-C::Scalar::ONE)) + num_bigint::BigUint::one()
}
