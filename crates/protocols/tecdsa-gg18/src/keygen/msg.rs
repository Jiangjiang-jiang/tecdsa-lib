use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};

pub const PI_MOD_SECURITY: usize = 16;

#[derive(Clone, Debug)]
pub struct SerInteger(pub tecdsa_paillier::backend::Integer);

impl Serialize for SerInteger {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.0.to_bytes_msf();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerInteger {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(SerInteger(
            tecdsa_paillier::backend::Integer::from_bytes_msf(&bytes),
        ))
    }
}

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
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub y_i: C::ProjectivePoint,
    pub ek: tecdsa_paillier::EncryptionKey,
    pub n_tilde: SerInteger,
    pub h1: SerInteger,
    pub h2: SerInteger,
    #[serde(with = "tecdsa_curve::serde_projective::vec")]
    pub feldman_commitments: Vec<C::ProjectivePoint>,
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
    pub paillier_mod_proof:
        tecdsa_paillier::zk::paillier_zk::paillier_blum_modulus::NiProof<PI_MOD_SECURITY>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum Gg18KeygenMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(MsgRound1),
    Round2Broad(MsgRound2Broad<C>),
    Round2Uni(MsgRound2Uni<C>),
    Round3(MsgRound3<C>),
}
