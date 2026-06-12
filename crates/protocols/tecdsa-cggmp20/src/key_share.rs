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

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VssSetup {
    pub threshold: u16,
    pub total: u16,
}

#[derive(Clone)]
pub struct Cggmp20CoreKeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub party_index: u16,
    pub secret_share: <C as CurveArithmetic>::Scalar,
    pub public_key: C::ProjectivePoint,
    pub public_shares: Vec<C::ProjectivePoint>,
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

pub struct AuxInfo {
    pub party_index: u16,
    pub dk: DecryptionKey,
    pub paillier_eks: Vec<EncryptionKey>,
    pub pedersen_params: Vec<PedersenModParams>,
}

pub struct Cggmp20KeyShare<C: TecdsaCurve, L: Cggmp20SecurityParams>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub core: Cggmp20CoreKeyShare<C>,
    pub aux: AuxInfo,
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
