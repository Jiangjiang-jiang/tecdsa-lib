use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;

use crate::keygen::interactive::{ClientStep2Msg, ServerStep1Msg, ServerStep3Msg};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireStep1Msg {
    pub(crate) commitment: HashCommitment,
    pub(crate) ek: tecdsa_paillier::EncryptionKey,
    pub(crate) correct_key_proof: NICorrectKeyProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireStep2Msg {
    pub(crate) x1_point_bytes: Vec<u8>,
    pub(crate) dlog_proof_json: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireStep3Msg {
    pub(crate) x2_point_bytes: Vec<u8>,
    pub(crate) nonce: [u8; 32],
    pub(crate) enc_x2: tecdsa_paillier::Ciphertext,
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

pub(crate) fn encode_step1(msg: &ServerStep1Msg) -> Result<Vec<u8>, TecdsaError> {
    let wire = WireStep1Msg {
        commitment: msg.commitment.clone(),
        ek: msg.ek.clone(),
        correct_key_proof: msg.correct_key_proof.clone(),
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Step1: {e}")))
}

pub(crate) fn decode_step1(bytes: &[u8]) -> Result<ServerStep1Msg, TecdsaError> {
    let (wire, _): (WireStep1Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Step1: {e}")))?;
    Ok(ServerStep1Msg {
        commitment: wire.commitment,
        ek: wire.ek,
        correct_key_proof: wire.correct_key_proof,
    })
}

pub(crate) fn encode_step2<C: TecdsaCurve>(msg: &ClientStep2Msg<C>) -> Result<Vec<u8>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let wire = WireStep2Msg {
        x1_point_bytes: encode_point::<C>(&msg.x1_point),
        dlog_proof_json: encode_dlog_proof::<C>(&msg.dlog_proof)?,
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Step2: {e}")))
}

pub(crate) fn decode_step2<C: TecdsaCurve>(bytes: &[u8]) -> Result<ClientStep2Msg<C>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let (wire, _): (WireStep2Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Step2: {e}")))?;
    Ok(ClientStep2Msg {
        x1_point: decode_point::<C>(&wire.x1_point_bytes)?,
        dlog_proof: decode_dlog_proof::<C>(&wire.dlog_proof_json)?,
    })
}

pub(crate) fn encode_step3<C: TecdsaCurve>(msg: &ServerStep3Msg<C>) -> Result<Vec<u8>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
{
    let wire = WireStep3Msg {
        x2_point_bytes: encode_point::<C>(&msg.x2_point),
        nonce: msg.nonce,
        enc_x2: msg.enc_x2.clone(),
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Step3: {e}")))
}

pub(crate) fn decode_step3<C: TecdsaCurve>(bytes: &[u8]) -> Result<ServerStep3Msg<C>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
{
    let (wire, _): (WireStep3Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Step3: {e}")))?;
    Ok(ServerStep3Msg {
        x2_point: decode_point::<C>(&wire.x2_point_bytes)?,
        nonce: wire.nonce,
        enc_x2: wire.enc_x2,
    })
}
