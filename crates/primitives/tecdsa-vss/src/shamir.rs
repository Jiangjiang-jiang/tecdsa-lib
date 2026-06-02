// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shamir secret sharing: polynomial-based `t`-of-`n` secret splitting.

use elliptic_curve::{
    sec1::ModulusSize, CurveArithmetic, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

/// A single Shamir share: the index `i` and value `f(i)`.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct Share<C: CurveArithmetic> {
    /// 1-based participant index.
    pub index: u16,
    /// Polynomial evaluation `f(index)`.
    pub value: C::Scalar,
}

/// Split `secret` into `n` shares with reconstruction threshold `threshold`.
///
/// Any `threshold` shares suffice to reconstruct; fewer reveal nothing.
///
/// # Panics
/// Panics if `threshold == 0` or `threshold > n`.
pub fn split<C>(
    secret: &C::Scalar,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Vec<Share<C>>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    assert!(threshold > 0, "threshold must be >= 1");
    assert!(threshold <= n, "threshold must be <= n");

    // Polynomial coefficients: a_0 = secret, a_1..a_{t-1} = random.
    let mut coeffs: Vec<C::Scalar> = Vec::with_capacity(threshold as usize);
    coeffs.push(*secret);
    for _ in 1..threshold {
        coeffs.push(C::random_scalar(rng));
    }

    // Evaluate f(i) = sum_{j=0}^{t-1} a_j * i^j for each participant.
    (1..=n)
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
        .collect()
}

/// Reconstruct the secret from exactly `threshold` shares using Lagrange interpolation.
///
/// The caller is responsible for passing exactly `threshold` valid shares.
pub fn reconstruct<C>(shares: &[Share<C>]) -> C::Scalar
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let indices: Vec<u16> = shares.iter().map(|s| s.index).collect();
    let coeffs = crate::lagrange::coefficients::<C>(&indices);
    shares
        .iter()
        .zip(coeffs.iter())
        .fold(C::Scalar::ZERO, |acc, (share, coeff)| {
            acc + share.value * coeff
        })
}
