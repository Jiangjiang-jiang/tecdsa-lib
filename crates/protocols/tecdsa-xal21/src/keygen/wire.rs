use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;

use crate::keygen::interactive::{KeyGenP1Round1Msg, KeyGenP1Round3Msg, KeyGenP2Round2Msg};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR1Msg {
    pub(crate) commitment: HashCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR2Msg {
    pub(crate) q2_point_bytes: Vec<u8>,
    pub(crate) dlog_proof_json: Vec<u8>,
    pub(crate) ek: tecdsa_paillier::EncryptionKey,
    pub(crate) pi_gcd: NICorrectKeyProof,
    pub(crate) ntilde: tecdsa_paillier::zk::mta_range::NTildeParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR3Msg {
    pub(crate) q1_point_bytes: Vec<u8>,
    pub(crate) dlog_proof_json: Vec<u8>,
    pub(crate) nonce: [u8; 32],
}

pub(crate) fn encode_point<C: TecdsaCurve>(p: &C::ProjectivePoint) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
{
    p.to_bytes().as_ref().to_vec()
}

pub(crate) fn decode_point<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::ProjectivePoint, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
{
    let repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
    let repr_len = repr.as_ref().len();
    if bytes.len() != repr_len {
        return Err(TecdsaError::Other(format!(
            "invalid point length: expected {repr_len}, got {}",
            bytes.len()
        )));
    }
    let mut repr = repr;
    repr.as_mut().copy_from_slice(bytes);
    Option::from(C::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| TecdsaError::Other("invalid EC point encoding".into()))
}

pub(crate) fn encode_dlog_proof<C: TecdsaCurve>(
    proof: &DlogProof<C>,
) -> Result<Vec<u8>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    bincode::serde::encode_to_vec(proof, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize DlogProof: {e}")))
}

pub(crate) fn decode_dlog_proof<C: TecdsaCurve>(bytes: &[u8]) -> Result<DlogProof<C>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| TecdsaError::Other(format!("failed to deserialize DlogProof: {e}")))
}

pub(crate) fn encode_r1<C: TecdsaCurve>(msg: &KeyGenP1Round1Msg) -> Result<Vec<u8>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
{
    let wire = WireR1Msg {
        commitment: msg.commitment.clone(),
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Round1: {e}")))
}

pub(crate) fn decode_r1(bytes: &[u8]) -> Result<KeyGenP1Round1Msg, TecdsaError> {
    let (wire, _): (WireR1Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Round1: {e}")))?;
    Ok(KeyGenP1Round1Msg {
        commitment: wire.commitment,
    })
}

pub(crate) fn encode_r2<C: TecdsaCurve>(msg: &KeyGenP2Round2Msg<C>) -> Result<Vec<u8>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let wire = WireR2Msg {
        q2_point_bytes: encode_point::<C>(&msg.q2),
        dlog_proof_json: encode_dlog_proof::<C>(&msg.dlog_proof)?,
        ek: msg.ek.clone(),
        pi_gcd: msg.pi_gcd.clone(),
        ntilde: msg.ntilde.clone(),
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Round2: {e}")))
}

pub(crate) fn decode_r2<C: TecdsaCurve>(bytes: &[u8]) -> Result<KeyGenP2Round2Msg<C>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let (wire, _): (WireR2Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Round2: {e}")))?;
    Ok(KeyGenP2Round2Msg {
        q2: decode_point::<C>(&wire.q2_point_bytes)?,
        dlog_proof: decode_dlog_proof::<C>(&wire.dlog_proof_json)?,
        ek: wire.ek,
        pi_gcd: wire.pi_gcd,
        ntilde: wire.ntilde,
    })
}

pub(crate) fn encode_r3<C: TecdsaCurve>(msg: &KeyGenP1Round3Msg<C>) -> Result<Vec<u8>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let wire = WireR3Msg {
        q1_point_bytes: encode_point::<C>(&msg.q1),
        dlog_proof_json: encode_dlog_proof::<C>(&msg.dlog_proof)?,
        nonce: msg.nonce,
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Round3: {e}")))
}

pub(crate) fn decode_r3<C: TecdsaCurve>(bytes: &[u8]) -> Result<KeyGenP1Round3Msg<C>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let (wire, _): (WireR3Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Round3: {e}")))?;
    Ok(KeyGenP1Round3Msg {
        q1: decode_point::<C>(&wire.q1_point_bytes)?,
        dlog_proof: decode_dlog_proof::<C>(&wire.dlog_proof_json)?,
        nonce: wire.nonce,
    })
}
