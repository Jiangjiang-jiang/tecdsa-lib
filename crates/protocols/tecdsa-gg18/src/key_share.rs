use elliptic_curve::{group::Group, sec1::ModulusSize, FieldBytesSize};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{zk::mta_range::NTildeParams, DecryptionKey, EncryptionKey};
use tecdsa_protocol::KeyShareValidation;
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct VssSetup {
    pub threshold: u16,
    pub total: u16,
}

#[derive(Clone)]
pub struct Gg18KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub party_index: u16,
    pub secret_share: C::Scalar,
    pub public_key: C::ProjectivePoint,
    pub public_shares: Vec<C::ProjectivePoint>,
    pub vss_setup: VssSetup,
    pub dk: DecryptionKey,
    pub paillier_eks: Vec<EncryptionKey>,
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
