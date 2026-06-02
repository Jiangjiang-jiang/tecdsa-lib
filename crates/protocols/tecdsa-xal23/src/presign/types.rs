// SPDX-License-Identifier: MIT OR Apache-2.0
//! Presignature type for XAL23 threshold ECDSA.

#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

/// Output of the XAL23 presigning protocol (4 rounds).
///
/// Contains all the values a party needs to participate in online signing
/// once a message hash is known.
#[derive(Clone)]
pub struct Xal23Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The nonce point R = g^{1/k}.
    pub R: C::ProjectivePoint,
    /// The x-coordinate of R reduced mod the group order.
    pub r: <C as CurveArithmetic>::Scalar,
    /// This party's nonce share k_i.
    pub k_i: <C as CurveArithmetic>::Scalar,
    /// This party's sigma share: sigma_i = k_i * w_i + sum(mu_ij + nu_ij).
    pub sigma_i: <C as CurveArithmetic>::Scalar,
    /// The joint ECDSA public key.
    pub public_key: C::ProjectivePoint,
    /// This party's ID.
    pub my_id: PartyId,
    /// The signing subset (PartyIds).
    pub signer_parties: Vec<PartyId>,
}

impl<C: TecdsaCurve> Zeroize for Xal23Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.sigma_i.zeroize();
    }
}

impl<C: TecdsaCurve> std::fmt::Debug for Xal23Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xal23Presignature")
            .field("r", &"<scalar>")
            .field("my_id", &self.my_id)
            .finish()
    }
}
