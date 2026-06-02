// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key share types for the CGGMP20 threshold ECDSA protocol.
//!
//! A full key share consists of:
//! - [`Cggmp20CoreKeyShare`]: the party's secret share, the joint public key, and all
//!   parties' public shares (produced by key generation).
//! - [`AuxInfo`]: Paillier keys and ring-Pedersen parameters (produced by the
//!   auxiliary-info protocol).
//! - [`Cggmp20KeyShare`]: the combined core + aux bundle, parameterised by a
//!   [`Cggmp20SecurityParams`].

use elliptic_curve::{group::Group, sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{DecryptionKey, EncryptionKey};
use tecdsa_pedersen_mod::PedersenModParams;
use tecdsa_protocol::KeyShareValidation;
use zeroize::Zeroize;

use crate::security_level::Cggmp20SecurityParams;

/// VSS configuration: threshold and total number of parties.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VssSetup {
    /// Reconstruction threshold `t` (minimum number of parties to sign).
    pub threshold: u16,
    /// Total number of parties `n`.
    pub total: u16,
}

/// Core key material produced by the key-generation protocol.
///
/// Contains the party's secret additive share, the joint ECDSA public key,
/// and all parties' public verification shares.
#[derive(Clone)]
pub struct Cggmp20CoreKeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's 0-based index.
    pub party_index: u16,
    /// Additive secret share `x_i` such that `sum(x_i) = x` (the signing key).
    pub secret_share: <C as CurveArithmetic>::Scalar,
    /// Joint ECDSA public key `X = x * G`.
    pub public_key: C::ProjectivePoint,
    /// Public verification shares `X_i = x_i * G` for every party.
    pub public_shares: Vec<C::ProjectivePoint>,
    /// VSS parameters (threshold and total).
    pub vss_setup: VssSetup,
}

impl<C: TecdsaCurve> Zeroize for Cggmp20CoreKeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

/// Auxiliary information produced by the aux-info protocol.
///
/// Stores this party's own Paillier decryption key and all parties'
/// encryption keys and ring-Pedersen parameters.
pub struct AuxInfo {
    /// This party's 0-based index.
    pub party_index: u16,
    /// This party's Paillier decryption key (contains `p`, `q` internally).
    pub dk: DecryptionKey,
    /// Paillier encryption keys for all parties (indexed by party index).
    pub paillier_eks: Vec<EncryptionKey>,
    /// Ring-Pedersen parameters `(N_i, s_i, t_i)` for all parties.
    pub pedersen_params: Vec<PedersenModParams>,
}

/// Combined key share: core key material plus auxiliary information.
///
/// The `L: Cggmp20SecurityParams` phantom parameter records which security-level
/// constraints were validated at construction time.
pub struct Cggmp20KeyShare<C: TecdsaCurve, L: Cggmp20SecurityParams>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Core ECDSA key material.
    pub core: Cggmp20CoreKeyShare<C>,
    /// Paillier + Pedersen auxiliary data.
    pub aux: AuxInfo,
    /// Phantom marker for the security level.
    pub _level: std::marker::PhantomData<L>,
}

impl<C: TecdsaCurve> KeyShareValidation for Cggmp20CoreKeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn validate(&self) -> Result<(), TecdsaError> {
        if self.vss_setup.threshold == 0 {
            return Err(TecdsaError::InvalidShare("threshold must be > 0".into()));
        }
        if self.vss_setup.threshold > self.vss_setup.total {
            return Err(TecdsaError::InvalidShare("threshold > total".into()));
        }
        if self.party_index >= self.vss_setup.total {
            return Err(TecdsaError::InvalidShare("party_index >= total".into()));
        }
        if self.public_shares.len() != self.vss_setup.total as usize {
            return Err(TecdsaError::InvalidShare(
                "public_shares.len() != total".into(),
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
