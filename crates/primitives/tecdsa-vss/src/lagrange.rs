use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;

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
                    acc * xj
                        * (xj - xi)
                            .invert()
                            .expect("distinct indices guarantee non-zero denominator")
                })
        })
        .collect()
}
