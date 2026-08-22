// SPDX-License-Identifier: MIT OR Apache-2.0
//! Checked Lagrange interpolation over a fixed evaluation set.
//!
//! This implements the `interpolate_d(j, S, {y_i})` notation of the paper
//! (Section 2.1): given values on `|S| >= d + 1` points, reconstruct the value
//! of the degree-`d` polynomial at `j`, *returning `None` if the values are not
//! consistent with any polynomial of degree at most `d`*.
//!
//! Every interpolation performed by KU25 uses the same evaluation set (the
//! indices of all `n` parties) and the same target point (`x = 0`), so the
//! Lagrange coefficients are precomputed once in [`Interp::new`] and reused.
//!
//! Consistency checking only has teeth when `|S| > d + 1`.  With the paper's
//! `n = 2t + 1` this means degree-`t` openings (`w_i`, `R_i`, `r`, `beta`, `T_j`)
//! are checked against `t` redundant points, while degree-`2t` openings (the
//! `F_wmult` broadcasts and the partial signatures) are exactly determined --
//! which is precisely why `F_wmult` is only secure *up to additive attacks* and
//! why the batch check of `Pi_triple` is needed.

use elliptic_curve::{
    group::Group, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;

/// Precomputed Lagrange data for interpolating at `x = 0` over a fixed index set.
#[derive(Clone, Debug)]
pub struct Interp<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Number of evaluation points (all parties).
    len: usize,
    /// Degree of the polynomial being reconstructed.
    degree: usize,
    /// Coefficients `l_i(0)` for the first `degree + 1` indices.
    coeffs_at_zero: Vec<C::Scalar>,
    /// For each redundant point (position in the index vector), the coefficients
    /// `l_i(x_pos)` over the first `degree + 1` indices.
    checks: Vec<(usize, Vec<C::Scalar>)>,
}

/// Lagrange basis coefficients `l_i(x)` for the given 1-based `indices`.
///
/// # Panics
/// Panics if `indices` contains duplicates.
fn coefficients_at<C>(indices: &[u16], x: &C::Scalar) -> Vec<C::Scalar>
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
                    acc * (*x - xj)
                        * (xi - xj)
                            .invert()
                            .expect("distinct indices guarantee a non-zero denominator")
                })
        })
        .collect()
}

impl<C: TecdsaCurve> Interp<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Build an interpolator for degree-`degree` polynomials evaluated on
    /// `indices` (1-based, distinct, sorted ascending).
    ///
    /// # Panics
    /// Panics if `indices.len() <= degree` or if `indices` has duplicates.
    #[must_use]
    pub fn new(indices: &[u16], degree: usize) -> Self {
        assert!(
            indices.len() > degree,
            "need at least degree + 1 points to interpolate"
        );
        let base = &indices[..=degree];
        let coeffs_at_zero = coefficients_at::<C>(base, &C::Scalar::ZERO);
        let checks = indices
            .iter()
            .enumerate()
            .skip(degree + 1)
            .map(|(pos, &idx)| {
                let x = C::Scalar::from(u64::from(idx));
                (pos, coefficients_at::<C>(base, &x))
            })
            .collect();
        Self {
            len: indices.len(),
            degree,
            coeffs_at_zero,
            checks,
        }
    }

    /// Polynomial degree this interpolator reconstructs.
    #[must_use]
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Reconstruct `f(0)` from `values[i] = f(indices[i])`.
    ///
    /// Returns `None` if the values are not consistent with a polynomial of
    /// degree at most [`Self::degree`].
    ///
    /// # Panics
    /// Panics if `values.len()` differs from the number of indices.
    #[must_use]
    pub fn scalar(&self, values: &[C::Scalar]) -> Option<C::Scalar> {
        assert_eq!(values.len(), self.len, "value/index length mismatch");
        let base = &values[..=self.degree];
        for (pos, coeffs) in &self.checks {
            let expected = dot_scalar::<C>(coeffs, base);
            if expected != values[*pos] {
                return None;
            }
        }
        Some(dot_scalar::<C>(&self.coeffs_at_zero, base))
    }

    /// Reconstruct `f(0)` "in the exponent" from `values[i] = g^{f(indices[i])}`.
    ///
    /// Returns `None` if the values are not consistent with a polynomial of
    /// degree at most [`Self::degree`].
    ///
    /// # Panics
    /// Panics if `values.len()` differs from the number of indices.
    #[must_use]
    pub fn point(&self, values: &[C::ProjectivePoint]) -> Option<C::ProjectivePoint> {
        assert_eq!(values.len(), self.len, "value/index length mismatch");
        let base = &values[..=self.degree];
        for (pos, coeffs) in &self.checks {
            let expected = dot_point::<C>(coeffs, base);
            if expected != values[*pos] {
                return None;
            }
        }
        Some(dot_point::<C>(&self.coeffs_at_zero, base))
    }
}

fn dot_scalar<C>(coeffs: &[C::Scalar], values: &[C::Scalar]) -> C::Scalar
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
{
    coeffs
        .iter()
        .zip(values.iter())
        .fold(C::Scalar::ZERO, |acc, (c, v)| acc + *c * *v)
}

fn dot_point<C>(coeffs: &[C::Scalar], values: &[C::ProjectivePoint]) -> C::ProjectivePoint
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
{
    coeffs
        .iter()
        .zip(values.iter())
        .fold(C::ProjectivePoint::identity(), |acc, (c, v)| acc + *v * *c)
}

#[cfg(test)]
mod tests {
    use k256::{ProjectivePoint, Scalar, Secp256k1};
    use rand::rngs::OsRng;

    use super::*;

    fn random_scalar() -> Scalar {
        <Secp256k1 as TecdsaCurve>::random_scalar(&mut OsRng)
    }

    /// Evaluate a polynomial given by its coefficients at `x`.
    fn eval(coeffs: &[Scalar], x: u16) -> Scalar {
        let x = Scalar::from(u64::from(x));
        coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
    }

    #[test]
    fn reconstructs_the_constant_term() {
        let indices: Vec<u16> = (1..=5).collect();
        let degree = 2usize;
        let poly: Vec<Scalar> = (0..=degree).map(|_| random_scalar()).collect();
        let values: Vec<Scalar> = indices.iter().map(|&i| eval(&poly, i)).collect();

        let interp = Interp::<Secp256k1>::new(&indices, degree);
        assert_eq!(interp.scalar(&values), Some(poly[0]));

        let points: Vec<ProjectivePoint> = values
            .iter()
            .map(|v| ProjectivePoint::GENERATOR * v)
            .collect();
        assert_eq!(
            interp.point(&points),
            Some(ProjectivePoint::GENERATOR * poly[0])
        );
    }

    #[test]
    fn detects_inconsistent_shares() {
        let indices: Vec<u16> = (1..=5).collect();
        let degree = 2usize;
        let poly: Vec<Scalar> = (0..=degree).map(|_| random_scalar()).collect();
        let mut values: Vec<Scalar> = indices.iter().map(|&i| eval(&poly, i)).collect();
        values[4] += Scalar::ONE;

        let interp = Interp::<Secp256k1>::new(&indices, degree);
        assert!(interp.scalar(&values).is_none());
    }

    #[test]
    fn exactly_determined_shares_are_always_consistent() {
        // degree 2t = 4 over n = 2t + 1 = 5 points: no redundancy, no check.
        let indices: Vec<u16> = (1..=5).collect();
        let interp = Interp::<Secp256k1>::new(&indices, 4);
        let values: Vec<Scalar> = (0..5).map(|_| random_scalar()).collect();
        assert!(interp.scalar(&values).is_some());
    }
}
