use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgRound1 {
    pub commitment: HashCommitment,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound2Broad<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub rid: [u8; 32],
    #[serde(with = "tecdsa_curve::serde_projective::vec")]
    pub feldman_commitments: Vec<C::ProjectivePoint>,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub schnorr_commitment: C::ProjectivePoint,
    pub decommit_nonce: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgRound2Uni<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub vss_share: <C as CurveArithmetic>::Scalar,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub schnorr_proof: DlogProof<C>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum KeygenMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(MsgRound1),
    Round2Broad(MsgRound2Broad<C>),
    Round2Uni(MsgRound2Uni<C>),
    Round3(MsgRound3<C>),
}
