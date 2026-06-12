#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{group::Group, sec1::ModulusSize, FieldBytesSize};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_ot::seed_state::OtSeedState;
use tecdsa_protocol::KeyShareValidation;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Dkls23KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub party_index: u16,
    pub shamir_share: C::Scalar,
    pub public_key: C::ProjectivePoint,
    pub verification_shares: Vec<C::ProjectivePoint>,
    pub total: u16,
    pub threshold: u16,
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
