#![allow(non_snake_case)]

use elliptic_curve::{
    group::Curve as CurveGroup, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

pub struct SignKeys<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub w_i: C::Scalar,
    pub g_w_i: C::ProjectivePoint,
    pub k_i: C::Scalar,
    pub gamma_i: C::Scalar,
    pub g_gamma_i: C::ProjectivePoint,
}

impl<C: TecdsaCurve> Zeroize for SignKeys<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.w_i.zeroize();
        self.k_i.zeroize();
        self.gamma_i.zeroize();
    }
}

impl<C: TecdsaCurve> SignKeys<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn create(
        secret_share: &C::Scalar,
        lagrange_coeff: &C::Scalar,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let w_i = *lagrange_coeff * secret_share;
        let g_w_i = C::generator() * w_i;
        let k_i = C::random_scalar(rng);
        let gamma_i = C::random_scalar(rng);
        let g_gamma_i = C::generator() * gamma_i;

        Self {
            w_i,
            g_w_i,
            k_i,
            gamma_i,
            g_gamma_i,
        }
    }

    pub fn compute_delta_i(&self, alpha_vec: &[C::Scalar], beta_vec: &[C::Scalar]) -> C::Scalar {
        let ki_gamma_i = self.k_i * self.gamma_i;
        let sum: C::Scalar = alpha_vec.iter().chain(beta_vec.iter()).copied().sum();
        ki_gamma_i + sum
    }

    pub fn compute_sigma_i(&self, mu_vec: &[C::Scalar], nu_vec: &[C::Scalar]) -> C::Scalar {
        let ki_w_i = self.k_i * self.w_i;
        let sum: C::Scalar = mu_vec.iter().chain(nu_vec.iter()).copied().sum();
        ki_w_i + sum
    }

    pub fn reconstruct_delta_inv(delta_vec: &[C::Scalar]) -> tecdsa_core::Result<C::Scalar> {
        let delta: C::Scalar = delta_vec.iter().copied().sum();
        delta.invert().into_option().ok_or_else(|| {
            tecdsa_core::TecdsaError::Other("delta sum is zero, cannot invert".into())
        })
    }

    pub fn compute_R(
        delta_inv: &C::Scalar,
        g_gamma_vec: &[C::ProjectivePoint],
    ) -> (C::ProjectivePoint, C::Scalar) {
        let gamma_sum: C::ProjectivePoint = g_gamma_vec.iter().copied().sum();
        let R = gamma_sum * delta_inv;
        let r = C::xcoord_mod_q(&R.to_affine());
        (R, r)
    }

    pub fn compute_s_i(
        &self,
        message: &C::Scalar,
        r: &C::Scalar,
        sigma_i: &C::Scalar,
    ) -> C::Scalar {
        Self::compute_s_i_static(message, &self.k_i, r, sigma_i)
    }

    pub fn compute_s_i_static(
        message: &C::Scalar,
        k_i: &C::Scalar,
        r: &C::Scalar,
        sigma_i: &C::Scalar,
    ) -> C::Scalar {
        *message * *k_i + *r * *sigma_i
    }
}
