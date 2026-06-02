// SPDX-License-Identifier: MIT OR Apache-2.0
//! Ephemeral per-signing-session key material for GG18.
//!
//! `SignKeys` holds the party's private ephemeral values (k_i, gamma_i, w_i)
//! and provides methods for computing MtA shares, delta, sigma, and partial
//! signatures.

#![allow(non_snake_case)]

use elliptic_curve::{
    group::Curve as CurveGroup, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

/// Ephemeral signing key material for one party.
///
/// Created at the start of a signing session by combining the party's key
/// share with the Lagrange coefficient for the signing subset.
pub struct SignKeys<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Lagrange-adjusted secret share: $w_i = \lambda_i \cdot x_i$.
    pub w_i: C::Scalar,
    /// Public key for $w_i$: $g_{w_i} = w_i \cdot G$.
    pub g_w_i: C::ProjectivePoint,
    /// Ephemeral nonce: $k_i \xleftarrow{\$} \mathbb{Z}_q$.
    pub k_i: C::Scalar,
    /// Ephemeral share: $\gamma_i \xleftarrow{\$} \mathbb{Z}_q$.
    pub gamma_i: C::Scalar,
    /// Public nonce share: $g_{\gamma_i} = \gamma_i \cdot G$.
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
    /// Create ephemeral signing keys for this party.
    ///
    /// # Parameters
    /// - `secret_share`: the party's secret share $x_i$
    /// - `lagrange_coeff`: the Lagrange coefficient $\lambda_i$ for this party
    ///   in the signing subset
    /// - `rng`: cryptographic RNG
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

    /// Compute $\delta_i = k_i \gamma_i + \sum \alpha_{ij} + \sum \beta_{ij}$.
    ///
    /// `alpha_vec` and `beta_vec` are the MtA shares from the (k_i, gamma_j) protocol.
    pub fn compute_delta_i(&self, alpha_vec: &[C::Scalar], beta_vec: &[C::Scalar]) -> C::Scalar {
        let ki_gamma_i = self.k_i * self.gamma_i;
        let sum: C::Scalar = alpha_vec.iter().chain(beta_vec.iter()).copied().sum();
        ki_gamma_i + sum
    }

    /// Compute $\sigma_i = k_i w_i + \sum \mu_{ij} + \sum \nu_{ij}$.
    ///
    /// `mu_vec` and `nu_vec` are the MtA shares from the (k_i, w_j) protocol.
    pub fn compute_sigma_i(&self, mu_vec: &[C::Scalar], nu_vec: &[C::Scalar]) -> C::Scalar {
        let ki_w_i = self.k_i * self.w_i;
        let sum: C::Scalar = mu_vec.iter().chain(nu_vec.iter()).copied().sum();
        ki_w_i + sum
    }

    /// Compute $\delta^{-1} = (\sum \delta_i)^{-1}$.
    ///
    /// # Errors
    /// Returns an error if the sum of deltas is zero (should not happen with honest parties).
    pub fn reconstruct_delta_inv(delta_vec: &[C::Scalar]) -> tecdsa_core::Result<C::Scalar> {
        let delta: C::Scalar = delta_vec.iter().copied().sum();
        delta.invert().into_option().ok_or_else(|| {
            tecdsa_core::TecdsaError::Other("delta sum is zero, cannot invert".into())
        })
    }

    /// Compute $R = \delta^{-1} \cdot \sum g_{\gamma_i}$ and extract
    /// $r = x\text{-coord}(R) \bmod q$.
    ///
    /// Returns `(R, r)`.
    pub fn compute_R(
        delta_inv: &C::Scalar,
        g_gamma_vec: &[C::ProjectivePoint],
    ) -> (C::ProjectivePoint, C::Scalar) {
        let gamma_sum: C::ProjectivePoint = g_gamma_vec.iter().copied().sum();
        let R = gamma_sum * delta_inv;
        let r = C::xcoord_mod_q(&R.to_affine());
        (R, r)
    }

    /// Compute the partial signature: $s_i = m \cdot k_i + r \cdot \sigma_i$.
    pub fn compute_s_i(
        &self,
        message: &C::Scalar,
        r: &C::Scalar,
        sigma_i: &C::Scalar,
    ) -> C::Scalar {
        Self::compute_s_i_static(message, &self.k_i, r, sigma_i)
    }

    /// Static version of `compute_s_i` that does not require a `SignKeys` instance.
    ///
    /// Used by the online signing phase which only has individual values
    /// from the presignature.
    pub fn compute_s_i_static(
        message: &C::Scalar,
        k_i: &C::Scalar,
        r: &C::Scalar,
        sigma_i: &C::Scalar,
    ) -> C::Scalar {
        *message * *k_i + *r * *sigma_i
    }
}
