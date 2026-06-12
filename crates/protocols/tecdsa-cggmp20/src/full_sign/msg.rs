use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_curve::TecdsaCurve;

use crate::presign::msg::PresignMsg;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgRound4<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub sigma: <C as CurveArithmetic>::Scalar,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum FullSignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Presign(PresignMsg<C>),
    Round4(MsgRound4<C>),
}
