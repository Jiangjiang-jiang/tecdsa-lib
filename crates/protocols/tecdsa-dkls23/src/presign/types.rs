#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

use crate::key_share::Dkls23KeyShare;

#[derive(Clone)]
pub struct PartyRvoleData<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub chi: <C as CurveArithmetic>::Scalar,
    pub c_u: <C as CurveArithmetic>::Scalar,
    pub c_v: <C as CurveArithmetic>::Scalar,
    pub d_u: <C as CurveArithmetic>::Scalar,
    pub d_v: <C as CurveArithmetic>::Scalar,
}

impl<C: TecdsaCurve> Zeroize for PartyRvoleData<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.chi.zeroize();
        self.c_u.zeroize();
        self.c_v.zeroize();
        self.d_u.zeroize();
        self.d_v.zeroize();
    }
}

impl<C: TecdsaCurve> Drop for PartyRvoleData<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone)]
pub struct Dkls23Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub r_i: <C as CurveArithmetic>::Scalar,
    pub phi_i: <C as CurveArithmetic>::Scalar,
    pub sk_i: <C as CurveArithmetic>::Scalar,
    pub pk_i: C::ProjectivePoint,
    pub R: C::ProjectivePoint,
    pub r_x: <C as CurveArithmetic>::Scalar,
    pub rvole_data: BTreeMap<u16, PartyRvoleData<C>>,
    pub received_psi: BTreeMap<u16, <C as CurveArithmetic>::Scalar>,
    pub key_share: Dkls23KeyShare<C>,
}

impl<C: TecdsaCurve> Zeroize for Dkls23Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.r_i.zeroize();
        self.phi_i.zeroize();
        self.sk_i.zeroize();
        for data in self.rvole_data.values_mut() {
            data.zeroize();
        }
    }
}

impl<C: TecdsaCurve> Drop for Dkls23Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone)]
pub struct RvoleCorrelation<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub chi: <C as CurveArithmetic>::Scalar,
    pub c_u: <C as CurveArithmetic>::Scalar,
    pub c_v: <C as CurveArithmetic>::Scalar,
    pub d_u: <C as CurveArithmetic>::Scalar,
    pub d_v: <C as CurveArithmetic>::Scalar,
}

pub fn ideal_rvole<C: TecdsaCurve>(
    r_bob: &<C as CurveArithmetic>::Scalar,
    sk_bob: &<C as CurveArithmetic>::Scalar,
    rng: &mut impl rand_core::CryptoRngCore,
) -> RvoleCorrelation<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: elliptic_curve::PrimeField<Repr = elliptic_curve::FieldBytes<C>>,
{
    let chi = C::random_scalar(rng);
    let d_u = C::random_scalar(rng);
    let d_v = C::random_scalar(rng);
    let c_u = chi * *r_bob - d_u;
    let c_v = chi * *sk_bob - d_v;
    RvoleCorrelation {
        chi,
        c_u,
        c_v,
        d_u,
        d_v,
    }
}
