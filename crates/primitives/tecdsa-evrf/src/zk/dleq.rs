// SPDX-License-Identifier: MIT OR Apache-2.0
//! Chaum-Pedersen DLEQ proof for eVRF.
//!
//! Proves `log_G(PK) = log_H(Y) = sk` without revealing `sk`, where
//! `H = hash_to_curve(input)` and `Y = sk * H`.

use elliptic_curve::{
    group::Curve as _, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_curve::{conv, TecdsaCurve};

use crate::{hash_to_curve, EvrfCurve, EvrfOutput, EvrfPublicKey, EvrfSecretKey};

/// Chaum-Pedersen DLEQ proof that `log_G(PK) = log_H(Y) = sk`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvrfProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub challenge: C::Scalar,
    pub response: C::Scalar,
}

impl<C: EvrfCurve> EvrfProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Produce a DLEQ proof for a VRF evaluation.
    pub fn prove(
        sk: &EvrfSecretKey<C>,
        input: &[u8],
        output: &EvrfOutput<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let h_affine: C::AffinePoint = hash_to_curve::<C>(input);
        Self::prove_with_h(sk, &h_affine, output, rng)
    }

    /// Produce a DLEQ proof with a pre-computed hash point.
    pub(crate) fn prove_with_h(
        sk: &EvrfSecretKey<C>,
        h_affine: &C::AffinePoint,
        output: &EvrfOutput<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let h_proj: C::ProjectivePoint = (*h_affine).into();

        let pk_affine = (C::generator() * *sk.scalar()).to_affine();

        let r = C::random_scalar(rng);
        let a_affine = (C::generator() * r).to_affine();
        let b_affine = (h_proj * r).to_affine();

        let e = dleq_challenge::<C>(&pk_affine, h_affine, &output.point, &a_affine, &b_affine);
        let s = r - e * *sk.scalar();

        Self {
            challenge: e,
            response: s,
        }
    }

    /// Verify the DLEQ proof.
    #[must_use]
    pub fn verify(&self, pk: &EvrfPublicKey<C>, input: &[u8], output: &EvrfOutput<C>) -> bool {
        use elliptic_curve::subtle::ConstantTimeEq;

        let h_affine: C::AffinePoint = hash_to_curve::<C>(input);
        let h_proj: C::ProjectivePoint = h_affine.into();

        let pk_proj: C::ProjectivePoint = pk.point.into();
        let y_proj: C::ProjectivePoint = output.point.into();

        let a_reconstructed =
            (C::generator() * self.response + pk_proj * self.challenge).to_affine();
        let b_reconstructed = (h_proj * self.response + y_proj * self.challenge).to_affine();

        let e_check = dleq_challenge::<C>(
            &pk.point,
            &h_affine,
            &output.point,
            &a_reconstructed,
            &b_reconstructed,
        );

        let lhs: FieldBytes<C> = self.challenge.to_repr();
        let rhs: FieldBytes<C> = e_check.to_repr();
        bool::from(<[u8]>::ct_eq(lhs.as_ref(), rhs.as_ref()))
    }
}

/// Fiat-Shamir challenge for the Chaum-Pedersen DLEQ proof.
///
/// `e = H("tecdsa-evrf-dleq-challenge:" || G || PK || H || Y || A || B)`
fn dleq_challenge<C>(
    pk: &C::AffinePoint,
    h_pt: &C::AffinePoint,
    y: &C::AffinePoint,
    a: &C::AffinePoint,
    b: &C::AffinePoint,
) -> C::Scalar
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let g_bytes = C::point_to_bytes(&C::generator().to_affine());
    let pk_bytes = C::point_to_bytes(pk);
    let h_bytes = C::point_to_bytes(h_pt);
    let y_bytes = C::point_to_bytes(y);
    let a_bytes = C::point_to_bytes(a);
    let b_bytes = C::point_to_bytes(b);

    let mut hasher = Sha256::new();
    hasher.update(b"tecdsa-evrf-dleq-challenge:");
    for part in [&g_bytes, &pk_bytes, &h_bytes, &y_bytes, &a_bytes, &b_bytes] {
        hasher.update(
            u32::try_from(part.len())
                .expect("part length fits u32")
                .to_le_bytes(),
        );
        hasher.update(part);
    }
    let hash = hasher.finalize();

    conv::bytes_to_scalar::<C>(&hash)
}
