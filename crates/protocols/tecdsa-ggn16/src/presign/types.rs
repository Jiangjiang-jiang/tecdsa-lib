// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::backend::Integer;
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

use crate::key_share::Ggn16KeyShare;

/// Presignature output from GGN16 Rounds 1-5.
///
/// Contains: $\psi = (k\rho)^{-1} \bmod q$, $u = E(\rho)$, $v = E(\rho x)$,
/// $R = g^k$, $r = H'(R)$, and the key share.
#[derive(Clone)]
pub struct Ggn16Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// $\psi = (k \rho)^{-1} \bmod q$ (from threshold decryption of $w$).
    pub psi: <C as CurveArithmetic>::Scalar,
    /// $u = E(\rho)$ (aggregate ciphertext).
    pub u: Integer,
    /// $v = E(\rho x)$ (aggregate ciphertext).
    pub v: Integer,
    /// $R = g^k$ (nonce point).
    pub R: C::ProjectivePoint,
    /// $r = x\text{-coord}(R) \bmod q$.
    pub r: <C as CurveArithmetic>::Scalar,
    /// The key share (needed for online sign).
    pub key_share: Ggn16KeyShare<C>,
    /// This party's ID.
    pub my_id: PartyId,
    /// The signing subset.
    pub signer_parties: Vec<PartyId>,
}

impl<C: TecdsaCurve> Zeroize for Ggn16Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.psi.zeroize();
    }
}
