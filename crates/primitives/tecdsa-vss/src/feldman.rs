use elliptic_curve::{
    group::Group, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;

use crate::shamir::Share;

pub fn split<C>(
    secret: &C::Scalar,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> (Vec<Share<C>>, Vec<C::ProjectivePoint>)
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    assert!(threshold > 0, "threshold must be >= 1");
    assert!(threshold <= n, "threshold must be <= n");

    let mut coeffs: Vec<C::Scalar> = Vec::with_capacity(threshold as usize);
    coeffs.push(*secret);
    for _ in 1..threshold {
        coeffs.push(C::random_scalar(rng));
    }

    let commitments: Vec<C::ProjectivePoint> = coeffs.iter().map(|c| C::generator() * c).collect();

    let shares = (1..=n)
        .map(|i| {
            let x = C::Scalar::from(u64::from(i));
            let mut y = C::Scalar::ZERO;
            let mut x_pow = C::Scalar::ONE;
            for c in &coeffs {
                y += *c * x_pow;
                x_pow *= x;
            }
            Share { index: i, value: y }
        })
        .collect();

    (shares, commitments)
}

#[must_use]
pub fn verify<C>(share_value: &C::Scalar, index: u16, commitments: &[C::ProjectivePoint]) -> bool
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let lhs = C::generator() * share_value;
    let x = C::Scalar::from(u64::from(index));
    let mut rhs = C::ProjectivePoint::identity();
    let mut x_pow = C::Scalar::ONE;
    for com in commitments {
        rhs += *com * x_pow;
        x_pow *= x;
    }
    lhs == rhs
}
