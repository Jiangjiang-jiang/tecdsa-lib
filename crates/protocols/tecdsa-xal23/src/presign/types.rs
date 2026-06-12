#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Xal23Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub R: C::ProjectivePoint,
    pub r: <C as CurveArithmetic>::Scalar,
    pub k_i: <C as CurveArithmetic>::Scalar,
    pub sigma_i: <C as CurveArithmetic>::Scalar,
    pub public_key: C::ProjectivePoint,
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
}

impl<C: TecdsaCurve> Zeroize for Xal23Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.sigma_i.zeroize();
    }
}

impl<C: TecdsaCurve> std::fmt::Debug for Xal23Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xal23Presignature")
            .field("r", &"<scalar>")
            .field("my_id", &self.my_id)
            .finish()
    }
}
