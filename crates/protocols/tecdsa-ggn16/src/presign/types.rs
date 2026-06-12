#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::backend::Integer;
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

use crate::key_share::Ggn16KeyShare;

#[derive(Clone)]
pub struct Ggn16Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub psi: <C as CurveArithmetic>::Scalar,
    pub u: Integer,
    pub v: Integer,
    pub R: C::ProjectivePoint,
    pub r: <C as CurveArithmetic>::Scalar,
    pub key_share: Ggn16KeyShare<C>,
    pub my_id: PartyId,
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
