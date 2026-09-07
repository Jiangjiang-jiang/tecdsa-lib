// SPDX-License-Identifier: MIT OR Apache-2.0
#![doc = "Curve-generic trait and adapters for the tecdsa threshold ECDSA library."]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod adapters;
pub mod elgamal_exp;
pub mod ext;
pub mod serde_projective;
pub mod serde_scalar;
pub mod zk;

use elliptic_curve::{
    group::GroupEncoding,
    ops::Reduce,
    point::AffineCoordinates,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
    CurveArithmetic, Field, FieldBytes, FieldBytesSize, PrimeCurve, PrimeField,
};
pub use ext::{PointExt, ScalarExt};
use rug::{integer::Order, Integer};

/// Projective point type for curve `C`.
pub type CurvePoint<C> = <C as CurveArithmetic>::ProjectivePoint;

/// Affine point type for curve `C`.
pub type CurveAffine<C> = <C as CurveArithmetic>::AffinePoint;

/// Scalar field element type for curve `C`.
pub type CurveScalar<C> = <C as CurveArithmetic>::Scalar;

/// Extension trait that adds tecdsa-specific behaviour to a `PrimeCurve + CurveArithmetic` type.
///
/// Implementors provide serialisation helpers, the group generator, x-coordinate extraction,
/// and a NUMS Pedersen auxiliary point.
pub trait TecdsaCurve:
    PrimeCurve
    + CurveArithmetic<
        ProjectivePoint: GroupEncoding,
        AffinePoint: AffineCoordinates + FromSec1Point<Self> + ToSec1Point<Self>,
        Scalar: PrimeField<Repr = FieldBytes<Self>> + Reduce<FieldBytes<Self>>,
    > + 'static
where
    FieldBytesSize<Self>: ModulusSize,
{
    /// Human-readable curve identifier (e.g. `"secp256k1"`).
    const CURVE_NAME: &'static str;

    /// Byte length of a scalar.
    const SCALAR_BYTES: usize;

    /// Domain-separation tag for hash-to-scalar operations.
    const HASH_DST: &'static [u8];

    /// Return the standard group generator *G*.
    fn generator() -> Self::ProjectivePoint;

    /// Extract the affine x-coordinate of `p` and reduce it modulo the group order.
    ///
    /// # Panics
    /// Panics if `p` is the point at infinity.
    fn xcoord_mod_q(p: &Self::AffinePoint) -> Self::Scalar;

    /// Serialize `p` to compressed SEC1 bytes.
    fn point_to_bytes(p: &Self::AffinePoint) -> Vec<u8>;

    /// Deserialize a compressed (or uncompressed) SEC1-encoded affine point.
    ///
    /// # Errors
    /// Returns [`tecdsa_core::TecdsaError::InvalidKey`] if the bytes are not a valid point.
    fn point_from_bytes(bytes: &[u8]) -> tecdsa_core::Result<Self::AffinePoint>;

    /// The group order `q`, i.e. the modulus of the scalar field.
    ///
    /// Derived from `-1`, which is `q - 1`; this agrees with [`elliptic_curve::Curve::ORDER`]
    /// and avoids depending on the `Uint` width.
    #[must_use]
    fn order() -> Integer {
        Integer::from_digits((-Self::Scalar::ONE).to_repr().as_ref(), Order::Msf) + 1u32
    }

    /// Interpret big-endian `bytes` as an integer and reduce it into the scalar field.
    ///
    /// Inputs no wider than a scalar are zero-extended and reduced with the
    /// field's own constant-time [`Reduce`]. Wider inputs are first narrowed
    /// with `rug`, which is variable-time; that path exists only for callers
    /// hashing into more bytes than a scalar holds.
    #[must_use]
    fn scalar_from_bytes(bytes: &[u8]) -> Self::Scalar {
        let mut repr = FieldBytes::<Self>::default();
        let width = <FieldBytes<Self> as AsRef<[u8]>>::as_ref(&repr).len();
        if bytes.len() <= width {
            repr[width - bytes.len()..].copy_from_slice(bytes);
        } else {
            let narrowed = Integer::from_digits(bytes, Order::Msf).modulo(&Self::order());
            let digits = narrowed.to_digits::<u8>(Order::Msf);
            repr[width - digits.len()..].copy_from_slice(&digits);
        }
        <Self::Scalar as Reduce<FieldBytes<Self>>>::reduce(&repr)
    }

    /// Reduce `v` into the scalar field, mapping negative values to `q - |v|`.
    #[must_use]
    fn scalar_from_integer(v: &Integer) -> Self::Scalar {
        let magnitude = Self::scalar_from_bytes(&v.to_digits::<u8>(Order::Msf));
        if v.cmp0().is_lt() {
            -magnitude
        } else {
            magnitude
        }
    }

    /// Return the NUMS (Nothing-Up-My-Sleeve) auxiliary point *H* for Pedersen commitments.
    ///
    /// *H* is deterministically derived from a fixed domain-separation tag so that the
    /// discrete-log relationship between *G* and *H* is unknown.
    fn nums_pedersen_h() -> Self::ProjectivePoint;

    /// Sample a uniformly random non-zero scalar via rejection sampling.
    ///
    /// Fills `FieldBytes` from the RNG and attempts `from_repr`; rejects zero
    /// and out-of-range values.  Expected to terminate after ~1 attempt for
    /// 256-bit curves.
    fn random_scalar(rng: &mut impl rand_core::CryptoRngCore) -> Self::Scalar {
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
