// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{group::Group, sec1::ModulusSize, FieldBytesSize};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_ot::seed_state::OtSeedState;
use tecdsa_protocol::KeyShareValidation;
use zeroize::Zeroize;

/// A party's key share from the DKLs23 relaxed DKG.
///
/// DKLs23 uses a relaxed distributed key generation protocol where each party
/// holds a Shamir secret share of the signing key. Unlike CGGMP20/GG18, no
/// Paillier keys or Ring-Pedersen parameters are needed -- the protocol uses
/// OT/VOLE-based multiplication instead.
///
/// The `ot_seeds` field stores base OT seeds established with each
/// counterparty.  When present, subsequent presigning sessions can skip
/// the expensive base OT phase and reconstruct `MulSender`/`MulReceiver`
/// directly from the persisted seeds.
#[derive(Clone)]
pub struct Dkls23KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's index (1-based).
    pub party_index: u16,
    /// Shamir secret share p(i) where p is the combined polynomial.
    pub shamir_share: C::Scalar,
    /// Joint ECDSA public key pk = sk * G.
    pub public_key: C::ProjectivePoint,
    /// Verification shares: V_j = share_j * G for all j.
    pub verification_shares: Vec<C::ProjectivePoint>,
    /// Total number of parties n.
    pub total: u16,
    /// Threshold t (t parties needed to sign).
    pub threshold: u16,
    /// Persisted base OT seeds per counterparty (keyed by counterparty index).
    ///
    /// Populated after the first presigning session completes its base OT
    /// exchange.  On subsequent sessions the presign state machine checks
    /// this map to skip base OT and reconstruct OTE sender/receiver state
    /// from the stored seeds.
    ///
    /// An empty map indicates no seeds have been cached yet (fresh key share
    /// from keygen).
    pub ot_seeds: BTreeMap<u16, OtSeedState>,
}

impl<C: TecdsaCurve> Zeroize for Dkls23KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.shamir_share.zeroize();
        for seed_state in self.ot_seeds.values_mut() {
            seed_state.zeroize();
        }
    }
}

impl<C: TecdsaCurve> Drop for Dkls23KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: TecdsaCurve> KeyShareValidation for Dkls23KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn validate(&self) -> Result<(), TecdsaError> {
        if self.threshold == 0 {
            return Err(TecdsaError::InvalidShare("threshold must be > 0".into()));
        }
        if self.threshold > self.total {
            return Err(TecdsaError::InvalidShare("threshold > total".into()));
        }
        if self.party_index >= self.total {
            return Err(TecdsaError::InvalidShare("party_index >= total".into()));
        }
        if self.verification_shares.len() != self.total as usize {
            return Err(TecdsaError::InvalidShare(
                "verification_shares.len() != total".into(),
            ));
        }
        if bool::from(self.public_key.is_identity()) {
            return Err(TecdsaError::InvalidShare(
                "public_key is the identity point".into(),
            ));
        }
        Ok(())
    }
}
