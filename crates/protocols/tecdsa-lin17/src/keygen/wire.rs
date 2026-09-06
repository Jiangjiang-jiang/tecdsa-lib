// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wire-safe serializable message types and conversion helpers for the Lin17
//! two-party interactive DKG.
//!
//! Points are encoded as compressed SEC1 bytes via `GroupEncoding`. Types
//! containing `C::ProjectivePoint` lack native serde impls, so we encode them
//! through manual serialization.

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::{
    backend::Integer,
    zk::{
        correct_key_ni::NICorrectKeyProof,
        pdl::{PdlProverMsg1, PdlProverMsg2, PdlVerifierMsg1, PdlVerifierMsg2},
        range_ni::RangeProofNi,
    },
};

use crate::keygen::interactive::{KeyGenP1Round1Msg, KeyGenP1Round3Msg, KeyGenP2Round2Msg};

// ---------------------------------------------------------------------------
// Wire-safe serializable message types
// ---------------------------------------------------------------------------

/// Wire-safe Round 1 message (P1 -> P2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR1Msg {
    pub(crate) commitment: HashCommitment,
}

/// Wire-safe Round 2 message (P2 -> P1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR2Msg {
    pub(crate) q2_bytes: Vec<u8>,
    pub(crate) dlog_proof_json: Vec<u8>,
}

/// Wire-safe Round 3 message (P1 -> P2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR3Msg {
    pub(crate) q1_bytes: Vec<u8>,
    pub(crate) dlog_proof_json: Vec<u8>,
    pub(crate) nonce: [u8; 32],
    pub(crate) ek: tecdsa_paillier::EncryptionKey,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub(crate) c_key: tecdsa_paillier::Ciphertext,
    pub(crate) c_key_nonce_bytes: Vec<u8>,
    pub(crate) correct_key_proof: NICorrectKeyProof,
    pub(crate) range_proof: RangeProofNi,
}

/// Wire-safe Round 4 message (P2 -> P1): PDL verifier msg1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR4Msg {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub(crate) c_tag: tecdsa_paillier::Ciphertext,
    pub(crate) c_tag_tag: HashCommitment,
}

/// Wire-safe Round 5 message (P1 -> P2): PDL prover msg1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR5Msg {
    pub(crate) q_hat_commitment: HashCommitment,
}

/// Wire-safe Round 6 message (P2 -> P1): PDL verifier msg2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR6Msg {
    pub(crate) a_bytes: Vec<u8>,
    pub(crate) b_bytes: Vec<u8>,
    pub(crate) nonce: [u8; 32],
}

/// Wire-safe Round 7 message (P1 -> P2): PDL prover msg2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireR7Msg {
    pub(crate) q_hat_bytes: Vec<u8>,
    pub(crate) nonce: [u8; 32],
}

// ---------------------------------------------------------------------------
// Point encoding helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Round encode/decode helpers
// ---------------------------------------------------------------------------

pub(crate) fn encode_r1(msg: &KeyGenP1Round1Msg) -> Result<Vec<u8>, TecdsaError> {
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
        q2_bytes: encode_point::<C>(&msg.q2),
        dlog_proof_json: encode_dlog_proof::<C>(&msg.dlog_proof)?,
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
        q2: decode_point::<C>(&wire.q2_bytes)?,
        dlog_proof: decode_dlog_proof::<C>(&wire.dlog_proof_json)?,
    })
}

pub(crate) fn encode_r3<C: TecdsaCurve>(msg: &KeyGenP1Round3Msg<C>) -> Result<Vec<u8>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let wire = WireR3Msg {
        q1_bytes: encode_point::<C>(&msg.q1),
        dlog_proof_json: encode_dlog_proof::<C>(&msg.dlog_proof)?,
        nonce: msg.nonce,
        ek: msg.ek.clone(),
        c_key: msg.c_key.clone(),
        c_key_nonce_bytes: msg.c_key_nonce.to_bytes_msf(),
        correct_key_proof: msg.correct_key_proof.clone(),
        range_proof: msg.range_proof.clone(),
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
        q1: decode_point::<C>(&wire.q1_bytes)?,
        dlog_proof: decode_dlog_proof::<C>(&wire.dlog_proof_json)?,
        nonce: wire.nonce,
        ek: wire.ek,
        c_key: wire.c_key,
        c_key_nonce: Integer::from_bytes_msf(&wire.c_key_nonce_bytes),
        correct_key_proof: wire.correct_key_proof,
        range_proof: wire.range_proof,
    })
}

pub(crate) fn encode_r4(msg: &PdlVerifierMsg1) -> Result<Vec<u8>, TecdsaError> {
    let wire = WireR4Msg {
        c_tag: msg.c_tag.clone(),
        c_tag_tag: msg.c_tag_tag.clone(),
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Round4: {e}")))
}

pub(crate) fn decode_r4(bytes: &[u8]) -> Result<PdlVerifierMsg1, TecdsaError> {
    let (wire, _): (WireR4Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Round4: {e}")))?;
    Ok(PdlVerifierMsg1 {
        c_tag: wire.c_tag,
        c_tag_tag: wire.c_tag_tag,
    })
}

pub(crate) fn encode_r5(msg: &PdlProverMsg1) -> Result<Vec<u8>, TecdsaError> {
    let wire = WireR5Msg {
        q_hat_commitment: msg.q_hat_commitment.clone(),
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Round5: {e}")))
}

pub(crate) fn decode_r5(bytes: &[u8]) -> Result<PdlProverMsg1, TecdsaError> {
    let (wire, _): (WireR5Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Round5: {e}")))?;
    Ok(PdlProverMsg1 {
        q_hat_commitment: wire.q_hat_commitment,
    })
}

pub(crate) fn encode_r6(msg: &PdlVerifierMsg2) -> Result<Vec<u8>, TecdsaError> {
    let wire = WireR6Msg {
        a_bytes: msg.a.to_bytes_msf(),
        b_bytes: msg.b.to_bytes_msf(),
        nonce: msg.nonce,
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Round6: {e}")))
}

pub(crate) fn decode_r6(bytes: &[u8]) -> Result<PdlVerifierMsg2, TecdsaError> {
    let (wire, _): (WireR6Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Round6: {e}")))?;
    Ok(PdlVerifierMsg2 {
        a: Integer::from_bytes_msf(&wire.a_bytes),
        b: Integer::from_bytes_msf(&wire.b_bytes),
        nonce: wire.nonce,
    })
}

pub(crate) fn encode_r7<C: TecdsaCurve>(msg: &PdlProverMsg2<C>) -> Result<Vec<u8>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
{
    let wire = WireR7Msg {
        q_hat_bytes: encode_point::<C>(&msg.q_hat),
        nonce: msg.nonce,
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("failed to serialize Round7: {e}")))
}

pub(crate) fn decode_r7<C: TecdsaCurve>(bytes: &[u8]) -> Result<PdlProverMsg2<C>, TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
{
    let (wire, _): (WireR7Msg, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("failed to deserialize Round7: {e}")))?;
    Ok(PdlProverMsg2 {
        q_hat: decode_point::<C>(&wire.q_hat_bytes)?,
        nonce: wire.nonce,
    })
}
