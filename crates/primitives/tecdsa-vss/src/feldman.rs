// SPDX-License-Identifier: MIT OR Apache-2.0
//! Feldman VSS: Shamir sharing with EC commitments to polynomial coefficients.

use crate::shamir::Share;
use elliptic_curve::{
    group::Group, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;

/// Split `secret` into `n` Feldman VSS shares with threshold `threshold`.
///
/// Returns `(shares, commitments)` where `commitments[j] = a_j * G`.
/// Participants can verify their share against the public commitments.
///
/// # Panics
/// Panics if `threshold == 0` or `threshold > n`.
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

    // Build polynomial coefficients: a_0 = secret, a_1..a_{t-1} = random.
    let mut coeffs: Vec<C::Scalar> = Vec::with_capacity(threshold as usize);
    coeffs.push(*secret);
    for _ in 1..threshold {
        coeffs.push(C::random_scalar(rng));
    }

    // Public commitments: C_j = a_j * G.
    let commitments: Vec<C::ProjectivePoint> = coeffs.iter().map(|c| C::generator() * c).collect();

    // Evaluate shares: f(i) = sum_{j=0}^{t-1} a_j * i^j.
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

/// Verify that a share `(index, share_value)` is consistent with the public `commitments`.
///
/// Check: `share_value * G == sum_{j=0}^{t-1} commitments[j] * index^j`
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
