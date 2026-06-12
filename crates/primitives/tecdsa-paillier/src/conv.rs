use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
use fast_paillier::backend::Integer;
use tecdsa_curve::TecdsaCurve;

#[must_use]
pub fn scalar_to_integer<C: TecdsaCurve>(
    s: &<C as elliptic_curve::CurveArithmetic>::Scalar,
) -> Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let repr = s.to_repr();
    Integer::from_bytes_msf(repr.as_ref())
}

#[must_use]
pub fn integer_to_scalar<C: TecdsaCurve>(
    i: &Integer,
) -> <C as elliptic_curve::CurveArithmetic>::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    tecdsa_curve::conv::bytes_to_scalar::<C>(&i.to_bytes_msf())
}

#[must_use]
pub fn group_order_integer<C: TecdsaCurve>() -> Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    scalar_to_integer::<C>(&(-C::Scalar::ONE)) + Integer::one()
}
