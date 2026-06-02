// SPDX-License-Identifier: MIT OR Apache-2.0
//! Presignature type for GG18 threshold ECDSA.
//!
//! After Phases 1-4, each party holds `R`, `r`, `k_i`, and `sigma_i` —
//! everything needed for online signing (Phase 5) without the message.

#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

/// Output of the GG18 presigning protocol (Phases 1-4).
///
/// Contains all the values a party needs to participate in online signing
/// (Phase 5) once a message is known.
#[derive(Clone)]
pub struct Gg18Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The nonce point $R = (\sum g_{\gamma_i}) \cdot \delta^{-1}$.
    pub R: C::ProjectivePoint,
    /// The x-coordinate of $R$ reduced mod the group order.
    pub r: <C as CurveArithmetic>::Scalar,
    /// This party's nonce share $k_i$.
    pub k_i: <C as CurveArithmetic>::Scalar,
    /// This party's sigma share $\sigma_i = k_i w_i + \sum \mu_{ij} + \sum \nu_{ij}$.
    pub sigma_i: <C as CurveArithmetic>::Scalar,
    /// The joint ECDSA public key.
    pub public_key: C::ProjectivePoint,
    /// This party's ID.
    pub my_id: PartyId,
    /// The signing subset (PartyIds).
    pub signer_parties: Vec<PartyId>,
}

impl<C: TecdsaCurve> Zeroize for Gg18Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.sigma_i.zeroize();
    }
}
