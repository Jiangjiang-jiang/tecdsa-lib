#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    backend::Integer,
    threshold::{DecryptionShare, ThresholdSetup},
};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Ggn16KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub party_index: u16,
    pub secret_share: C::Scalar,
    pub public_key: C::ProjectivePoint,
    pub public_shares: Vec<C::ProjectivePoint>,
    pub alpha: Integer,
    pub threshold_setup: ThresholdSetup,
    pub decryption_share: DecryptionShare,
    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,
    pub threshold: u16,
    pub total: u16,
}

impl<C: TecdsaCurve> Zeroize for Ggn16KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
        self.decryption_share.zeroize();
    }
}
