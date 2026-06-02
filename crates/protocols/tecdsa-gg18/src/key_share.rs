// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key share types for the GG18 threshold ECDSA protocol.

use elliptic_curve::{group::Group, sec1::ModulusSize, FieldBytesSize};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::zk::mta_range::NTildeParams;
use tecdsa_paillier::{DecryptionKey, EncryptionKey};
use tecdsa_protocol::KeyShareValidation;
use zeroize::Zeroize;

/// Feldman VSS setup parameters: threshold `t` and total number of parties `n`.
///
/// A valid `(t, n)` sharing requires `t + 1` parties to reconstruct the secret
/// and `n >= 2t + 1` for malicious security.
#[derive(Debug, Clone)]
pub struct VssSetup {
    /// The threshold parameter `t`: at least `t + 1` shares are needed to sign.
    pub threshold: u16,
    /// Total number of parties `n`.
    pub total: u16,
}

/// A single party's key share produced by the GG18 distributed key generation.
///
/// Contains the party's secret share `x_i`, the joint public key `Y`,
/// public verification shares `Y_j = x_j * G` for all parties, Paillier keys,
/// and Ring-Pedersen commitment parameters.
#[derive(Clone)]
pub struct Gg18KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's index (0-based).
    pub party_index: u16,
    /// Secret share $x_i$ of the ECDSA signing key.
    pub secret_share: C::Scalar,
    /// Joint ECDSA public key $Y = \sum_j x_j \cdot G$.
    pub public_key: C::ProjectivePoint,
    /// Public verification shares $Y_j = x_j \cdot G$ for each party.
    pub public_shares: Vec<C::ProjectivePoint>,
    /// VSS parameters (threshold, total).
    pub vss_setup: VssSetup,
    /// This party's Paillier decryption key.
    pub dk: DecryptionKey,
    /// Paillier encryption keys for all parties.
    pub paillier_eks: Vec<EncryptionKey>,
    /// Ring-Pedersen $(N', h_1, h_2)$ parameters for all parties.
    pub n_tilde_params: Vec<NTildeParams>,
}

impl<C: TecdsaCurve> Zeroize for Gg18KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

impl<C: TecdsaCurve> KeyShareValidation for Gg18KeyShare<C>
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
