use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
use rug::{integer::Order, Integer};

use crate::TecdsaCurve;

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

#[must_use]
pub fn bytes_to_scalar<C: TecdsaCurve>(bytes: &[u8]) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let value = Integer::from_digits(bytes, Order::Msf);

    let q_bytes = scalar_to_bytes::<C>(&(-C::Scalar::ONE));
    let q = Integer::from_digits(&q_bytes, Order::Msf) + 1;

    let reduced = value.modulo(&q);
    let reduced_bytes = reduced.to_digits::<u8>(Order::Msf);

    let mut fb = FieldBytes::<C>::default();
    let fb_len = fb.len();
    if reduced_bytes.len() >= fb_len {
        fb.copy_from_slice(&reduced_bytes[reduced_bytes.len() - fb_len..]);
    } else {
        fb[fb_len - reduced_bytes.len()..].copy_from_slice(&reduced_bytes);
    }
    Option::from(<C::Scalar as PrimeField>::from_repr(fb)).unwrap_or_else(C::Scalar::default)
}

#[must_use]
pub fn integer_to_scalar<C: TecdsaCurve>(val: &Integer) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let scalar = bytes_to_scalar::<C>(&val.to_digits::<u8>(Order::Msf));
    if val.cmp0() == core::cmp::Ordering::Less {
        -scalar
    } else {
        scalar
    }
}

#[must_use]
pub fn scalar_to_integer<C: TecdsaCurve>(s: &C::Scalar) -> Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    Integer::from_digits(&scalar_to_bytes::<C>(s), Order::Msf)
}

#[must_use]
pub fn curve_order<C: TecdsaCurve>() -> Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    scalar_to_integer::<C>(&(-C::Scalar::ONE)) + 1
}
