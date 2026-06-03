// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the LN18 KeyGen protocol (Protocol 5.1).
//!
//! KeyGen wraps three F_mult sub-operations (init, input, element-out) and
//! their message types into a single unified envelope.
//!
//! 5 rounds: init(2) + input(2) + element-out(1).

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tecdsa_commit::HashCommitment;
use tecdsa_curve::TecdsaCurve;

use crate::f_mult::{
    element_out::ElementOutMsg,
    init::{InitRound1Msg, InitRound2Msg},
    input::{InputRound1Msg, InputRound2Msg},
};

// ---------------------------------------------------------------------------
// Serde helpers for ProjectivePoint and Scalar fields
// ---------------------------------------------------------------------------

fn ser_point<C: TecdsaCurve, S: Serializer>(
    pt: &C::ProjectivePoint,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    FieldBytesSize<C>: ModulusSize,
{
    let bytes = pt.to_bytes();
    bytes.as_ref().serialize(serializer)
}

fn de_point<'de, C: TecdsaCurve, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<C::ProjectivePoint, D::Error>
where
    FieldBytesSize<C>: ModulusSize,
{
    tecdsa_curve::serde_projective::deserialize(deserializer)
}

fn ser_scalar<C: TecdsaCurve, S: Serializer>(
    s: &C::Scalar,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let repr = s.to_repr();
    AsRef::<[u8]>::as_ref(&repr).serialize(serializer)
}

fn de_scalar<'de, C: TecdsaCurve, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<C::Scalar, D::Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    let mut fb = FieldBytes::<C>::default();
    if bytes.len() != fb.len() {
        return Err(serde::de::Error::custom("invalid scalar byte length"));
    }
    fb.copy_from_slice(&bytes);
    Option::from(<C::Scalar as PrimeField>::from_repr(fb))
        .ok_or_else(|| serde::de::Error::custom("invalid scalar encoding"))
}

// ---------------------------------------------------------------------------
// Serializable wrappers for sub-op message contents
// ---------------------------------------------------------------------------

/// Serializable representation of `InitRound1Msg`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SerInitRound1 {
    pub from: u16,
    pub commitment: HashCommitment,
}

/// Serializable representation of `InitRound2Msg<C>`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct SerInitRound2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: u16,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub p_i: C::ProjectivePoint,
    // DlogProof fields
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub proof_commitment: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub proof_response: C::Scalar,
    pub nonce: [u8; 32],
}

/// Serializable representation of `InputRound1Msg` (commitment only).
#[derive(Clone, Serialize, Deserialize)]
pub struct SerInputRound1 {
    pub from: u16,
    pub commitment: HashCommitment,
}

/// Serializable representation of `InputRound2Msg<C>` (decommitment with ciphertext + proof).
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct SerInputRound2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: u16,
    // EgexpCiphertext fields
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub ct_a: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub ct_b: C::ProjectivePoint,
    // EgexpProof fields
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub proof_commit_x: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub proof_commit_y: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub proof_z1: C::Scalar,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub proof_z2: C::Scalar,
    /// Opening nonce for the Round-1 hash commitment.
    pub nonce: [u8; 32],
}

/// Serializable representation of `ElementOutMsg<C>`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct SerElementOut<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: u16,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub a_i_point: C::ProjectivePoint,
    // DdhProof fields
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub proof_g_r: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub proof_a_r: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub proof_z: C::Scalar,
}

// ---------------------------------------------------------------------------
// Unified keygen message envelope
// ---------------------------------------------------------------------------

/// Unified envelope for all LN18 KeyGen messages.
///
/// Wraps the message types from each F_mult sub-operation (init, input,
/// element-out) into a single enum used as both `Inbound` and `Outbound`
/// for the `StateMachine` trait.
///
/// 5 rounds: init(2) + input(2) + element-out(1).
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
#[allow(clippy::large_enum_variant)]
pub enum Ln18KeygenMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Init sub-protocol Round 1: hash commitment.
    InitRound1(SerInitRound1),
    /// Init sub-protocol Round 2: decommitment with DLog proof.
    InitRound2(SerInitRound2<C>),
    /// Input sub-protocol Round 1: hash commitment.
    InputRound1(SerInputRound1),
    /// Input sub-protocol Round 2: decommitment with EGexp ciphertext + proof.
    InputRound2(SerInputRound2<C>),
    /// Element-out sub-protocol Round 1: revealed point + DDH proof.
    ElementOut(SerElementOut<C>),
}

// ---------------------------------------------------------------------------
// Conversions: sub-op message <-> serializable wrapper
// ---------------------------------------------------------------------------

impl SerInitRound1 {
    #[must_use]
    pub fn from_msg(msg: &InitRound1Msg) -> Self {
        Self {
            from: msg.from.0,
            commitment: msg.commitment.clone(),
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> InitRound1Msg {
        InitRound1Msg {
            from: tecdsa_protocol::PartyId(self.from),
            commitment: self.commitment.clone(),
        }
    }
}

impl<C: TecdsaCurve> SerInitRound2<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn from_msg(msg: &InitRound2Msg<C>) -> Self {
        Self {
            from: msg.from.0,
            p_i: msg.p_i,
            proof_commitment: msg.proof.commitment,
            proof_response: msg.proof.response,
            nonce: msg.nonce,
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> InitRound2Msg<C> {
        use tecdsa_curve::zk::dlog::DlogProof;
        InitRound2Msg {
            from: tecdsa_protocol::PartyId(self.from),
            p_i: self.p_i,
            proof: DlogProof {
                commitment: self.proof_commitment,
                response: self.proof_response,
            },
            nonce: self.nonce,
        }
    }
}

impl SerInputRound1 {
    #[must_use]
    pub fn from_msg(msg: &InputRound1Msg) -> Self {
        Self {
            from: msg.from.0,
            commitment: msg.commitment.clone(),
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> InputRound1Msg {
        InputRound1Msg {
            from: tecdsa_protocol::PartyId(self.from),
            commitment: self.commitment.clone(),
        }
    }
}

impl<C: TecdsaCurve> SerInputRound2<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn from_msg(msg: &InputRound2Msg<C>) -> Self {
        Self {
            from: msg.from.0,
            ct_a: msg.ciphertext.a,
            ct_b: msg.ciphertext.b,
            proof_commit_x: msg.proof.commit_x,
            proof_commit_y: msg.proof.commit_y,
            proof_z1: msg.proof.z1,
            proof_z2: msg.proof.z2,
            nonce: msg.nonce,
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> InputRound2Msg<C> {
        use tecdsa_curve::{elgamal_exp::EgexpCiphertext, zk::egexp::EgexpProof};
        InputRound2Msg {
            from: tecdsa_protocol::PartyId(self.from),
            ciphertext: EgexpCiphertext {
                a: self.ct_a,
                b: self.ct_b,
            },
            proof: EgexpProof {
                commit_x: self.proof_commit_x,
                commit_y: self.proof_commit_y,
                z1: self.proof_z1,
                z2: self.proof_z2,
            },
            nonce: self.nonce,
        }
    }
}

impl<C: TecdsaCurve> SerElementOut<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn from_msg(msg: &ElementOutMsg<C>) -> Self {
        Self {
            from: msg.from.0,
            a_i_point: msg.a_i_point,
            proof_g_r: msg.proof.g_r,
            proof_a_r: msg.proof.a_r,
            proof_z: msg.proof.z,
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> ElementOutMsg<C> {
        use tecdsa_curve::zk::ddh::DdhProof;
        ElementOutMsg {
            from: tecdsa_protocol::PartyId(self.from),
            a_i_point: self.a_i_point,
            proof: DdhProof {
                g_r: self.proof_g_r,
                a_r: self.proof_a_r,
                z: self.proof_z,
            },
        }
    }
}

/// Extract the round number from a message variant (for error reporting).
pub(crate) fn msg_round<C: TecdsaCurve>(msg: &Ln18KeygenMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        Ln18KeygenMsg::InitRound1(_) => 1,
        Ln18KeygenMsg::InitRound2(_) => 2,
        Ln18KeygenMsg::InputRound1(_) => 3,
        Ln18KeygenMsg::InputRound2(_) => 4,
        Ln18KeygenMsg::ElementOut(_) => 5,
    }
}
