#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_ot::{
    rvole::MulDataToReceiver,
    soft_spoken::{OteDataToSender, OteInitSenderMsg},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignR1Broadcast {
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignR1P2p {
    pub ote_init_msg: OteInitSenderMsg,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignR2Broadcast {
    pub salt: [u8; 32],
    pub R_i: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignR2P2p {
    pub ote_data: OteDataToSender,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct SignR3P2p<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub mul_data: MulDataToReceiver,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub Gamma_u: C::ProjectivePoint,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub Gamma_v: C::ProjectivePoint,
    pub psi: <C as CurveArithmetic>::Scalar,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub pk_i: C::ProjectivePoint,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct SignR4Broadcast<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub u_i: <C as CurveArithmetic>::Scalar,
    pub w_i: <C as CurveArithmetic>::Scalar,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum Dkls23SignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1Broadcast(SignR1Broadcast),
    Round1P2p(SignR1P2p),
    Round2Broadcast(SignR2Broadcast),
    Round2P2p(SignR2P2p),
    Round3P2p(SignR3P2p<C>),
    Round4Broadcast(SignR4Broadcast<C>),
}
