// SPDX-License-Identifier: MIT OR Apache-2.0
//! KU25 key share.

use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

/// A `(t + 1)`-out-of-`n` Shamir share of an ECDSA private key.
///
/// KU25 presignatures are **key-independent**, so a single party may hold an
/// arbitrary number of these -- one per key hosted by the key-management
/// network -- and use any of them with any presignature.
pub struct Ku25KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's 1-based Shamir evaluation point.
    pub party_index: u16,
    /// `x_j = f(party_index)` for the degree-`t` sharing polynomial `f` of the key.
    pub secret_share: C::Scalar,
    /// The ECDSA public key `y = g^{f(0)}`.
    pub public_key: C::ProjectivePoint,
    /// `g^{x_j}` for every party, in evaluation-point order.
    pub public_shares: Vec<C::ProjectivePoint>,
    /// Reconstruction threshold `t + 1`.
    pub threshold: u16,
    /// Number of parties `n`.
    pub total: u16,
}

impl<C: TecdsaCurve> Clone for Ku25KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            party_index: self.party_index,
            secret_share: self.secret_share,
            public_key: self.public_key,
            public_shares: self.public_shares.clone(),
            threshold: self.threshold,
            total: self.total,
        }
    }
}

impl<C: TecdsaCurve> Zeroize for Ku25KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        // `C::Scalar` is not guaranteed to implement `Zeroize`, but it is `Copy`
        // and `Default`; overwriting is the best we can portably do.
        self.secret_share = C::Scalar::default();
    }
}

impl<C: TecdsaCurve> Drop for Ku25KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: TecdsaCurve> core::fmt::Debug for Ku25KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ku25KeyShare")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}
