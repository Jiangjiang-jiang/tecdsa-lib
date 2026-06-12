use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::zk::{
    homo_elgamal::HomoElGamalProof,
    mta_range::{AliceProof, BobProofExt},
};

use crate::keygen::msg::SerInteger;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgSignRound1Broadcast {
    pub commitment: HashCommitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgSignRound1P2p {
    pub c_a: SerInteger,
    pub alice_proof: AliceProof,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgSignRound2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub c_b_gamma: SerInteger,
    pub c_b_w: SerInteger,
    pub bob_proof_gamma: BobProofExt<C>,
    pub bob_proof_w: BobProofExt<C>,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub w_j_point: C::ProjectivePoint,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgSignRound3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub delta_i: <C as CurveArithmetic>::Scalar,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub g_gamma_i: C::ProjectivePoint,
    pub decommit_nonce: [u8; 32],
    pub gamma_proof: DlogProof<C>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgPhase5aCommit {
    pub commitment: HashCommitment,
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgPhase5bDecommit<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub V_i: C::ProjectivePoint,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub A_i: C::ProjectivePoint,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub B_i: C::ProjectivePoint,
    pub decommit_nonce: [u8; 32],
    pub homo_proof: HomoElGamalProof<C>,
    pub dlog_proof: DlogProof<C>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgPhase5cCommit {
    pub commitment: HashCommitment,
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgPhase5dDecommit<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub U_i: C::ProjectivePoint,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub T_i: C::ProjectivePoint,
    pub decommit_nonce: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgPhase5eSig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub s_i: <C as CurveArithmetic>::Scalar,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum Gg18SignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1Broadcast(MsgSignRound1Broadcast),
    Round1P2p(MsgSignRound1P2p),
    Round2(MsgSignRound2<C>),
    Round3(MsgSignRound3<C>),
    Round4(MsgPhase5aCommit),
    Round5(MsgPhase5bDecommit<C>),
    Round6(MsgPhase5cCommit),
    Round7(MsgPhase5dDecommit<C>),
    Round8(MsgPhase5eSig<C>),
}
