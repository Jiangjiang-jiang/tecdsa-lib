#![doc = "Curve-generic trait and adapters for the tecdsa threshold ECDSA library."]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod adapters;
pub mod conv;
pub mod elgamal_exp;
pub mod serde_projective;
pub mod zk;

use elliptic_curve::{
    group::GroupEncoding,
    point::AffineCoordinates,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
    CurveArithmetic, Field, FieldBytes, FieldBytesSize, PrimeCurve, PrimeField,
};

pub type CurvePoint<C> = <C as CurveArithmetic>::ProjectivePoint;

pub type CurveAffine<C> = <C as CurveArithmetic>::AffinePoint;

pub type CurveScalar<C> = <C as CurveArithmetic>::Scalar;

pub trait TecdsaCurve:
    PrimeCurve
    + CurveArithmetic<
        ProjectivePoint: GroupEncoding,
        AffinePoint: AffineCoordinates + FromSec1Point<Self> + ToSec1Point<Self>,
    > + 'static
where
    FieldBytesSize<Self>: ModulusSize,
{
    const CURVE_NAME: &'static str;

    const SCALAR_BYTES: usize;

    const HASH_DST: &'static [u8];

    fn generator() -> Self::ProjectivePoint;

    fn xcoord_mod_q(p: &Self::AffinePoint) -> Self::Scalar;

    fn point_to_bytes(p: &Self::AffinePoint) -> Vec<u8>;

    fn point_from_bytes(bytes: &[u8]) -> tecdsa_core::Result<Self::AffinePoint>;

    fn nums_pedersen_h() -> Self::ProjectivePoint;

    fn random_scalar(rng: &mut impl rand_core::CryptoRngCore) -> Self::Scalar
    where
        Self::Scalar: PrimeField<Repr = FieldBytes<Self>>,
    {
        loop {
            let mut bytes = FieldBytes::<Self>::default();
            rng.fill_bytes(&mut bytes);
            if let Some(s) = Option::from(<Self::Scalar as PrimeField>::from_repr(bytes)) {
                if !bool::from(Field::is_zero(&s)) {
                    return s;
                }
            }
        }
    }
}
