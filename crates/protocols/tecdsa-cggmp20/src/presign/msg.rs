use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use generic_ec::curves::Secp256k1 as GE;
use serde::{Deserialize, Serialize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    zk::paillier_zk::{
        dlog_with_el_gamal_commitment as pi_elog, paillier_affine_operation_in_range as pi_aff,
        paillier_encryption_in_range_with_el_gamal as pi_enc_elg,
    },
    Ciphertext,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound1<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub big_k: Ciphertext,
    pub big_g: Ciphertext,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub big_y: C::ProjectivePoint,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub a1: C::ProjectivePoint,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub a2: C::ProjectivePoint,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub b1: C::ProjectivePoint,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub b2: C::ProjectivePoint,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub big_gamma: C::ProjectivePoint,
    pub big_d: Ciphertext,
    pub big_f: Ciphertext,
    pub hat_big_d: Ciphertext,
    pub hat_big_f: Ciphertext,
    pub psi0: pi_enc_elg::NiProof<GE>,
    pub psi1: pi_enc_elg::NiProof<GE>,
    pub tilde_psi: pi_elog::NiProof<GE>,
    pub psi: pi_aff::NiProof<GE>,
    pub hat_psi: pi_aff::NiProof<GE>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgRound3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub delta: <C as CurveArithmetic>::Scalar,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub big_delta: C::ProjectivePoint,
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub big_s: C::ProjectivePoint,
    pub psi_prime: pi_elog::NiProof<GE>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum PresignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(MsgRound1<C>),
    Round2(MsgRound2<C>),
    Round3(MsgRound3<C>),
}
