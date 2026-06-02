// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lagrange interpolation coefficients evaluated at x = 0.

use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;

/// Compute Lagrange basis coefficients for the given 1-based participant `indices`,
/// evaluated at x = 0 (i.e., the constant term of the interpolating polynomial).
///
/// The coefficient for index `i` is:
/// `l_i(0) = prod_{j != i} j / (j - i)`
///
/// # Panics
/// Panics if any two indices are equal (degenerate input).
#[must_use]
pub fn coefficients<C>(indices: &[u16]) -> Vec<C::Scalar>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    indices
        .iter()
        .map(|&i| {
            let xi = C::Scalar::from(u64::from(i));
            indices
                .iter()
                .filter(|&&j| j != i)
                .fold(C::Scalar::ONE, |acc, &j| {
                    let xj = C::Scalar::from(u64::from(j));
                    // l_i *= xj / (xj - xi)
                    acc * xj
                        * (xj - xi)
                            .invert()
                            .expect("distinct indices guarantee non-zero denominator")
                })
        })
        .collect()
}
