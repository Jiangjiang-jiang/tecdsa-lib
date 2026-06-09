// SPDX-License-Identifier: MIT OR Apache-2.0
//! LN18 sign message types for the real StateMachine implementations.
//!
//! Provides serializable message envelopes for the 2-round offline phase
//! (input(k) || input(rho)) and the 6-round online phase (element-out +
//! interleaved mult1/mult2).

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tecdsa_commit::HashCommitment;
use tecdsa_curve::TecdsaCurve;

use crate::f_mult::{
    element_out::ElementOutMsg,
    input::{InputRound1Msg, InputRound2Msg},
    mult::{MultRound1Msg, MultRound2Msg, MultRound3Msg, MultRound4Msg, MultRound5Msg},
};

// ---------------------------------------------------------------------------
// Serde helpers (reused from keygen/msg.rs pattern)
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
// Serializable wrappers for sub-protocol messages
// ---------------------------------------------------------------------------

/// Serializable representation of `InputRound1Msg` (commitment only).
#[derive(Clone, Serialize, Deserialize)]
pub struct SerInputRound1 {
    pub from: u16,
    pub commitment: HashCommitment,
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

/// Serializable representation of `InputRound2Msg<C>`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct SerInputRound2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: u16,
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
    pub nonce: [u8; 32],
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

/// Serializable wrapper for `MultRound1Msg<C>`: $(E_i, F_i)$ + R_prod proof.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct SerMultRound1<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: u16,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub e_i: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub f_i: C::ProjectivePoint,
    // ProdProof fields: x, y_commit, w (3 points), z1, z2 (2 scalars), + nested DdhProof (2 points + 1 scalar)
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub prod_x: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub prod_y_commit: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub prod_w: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub prod_z1: C::Scalar,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub prod_z2: C::Scalar,
    // Nested DdhProof in ProdProof
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub prod_ddh_g_r: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub prod_ddh_a_r: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub prod_ddh_z: C::Scalar,
}

impl<C: TecdsaCurve> SerMultRound1<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn from_msg(msg: &MultRound1Msg<C>) -> Self {
        Self {
            from: msg.from.0,
            e_i: msg.e_i,
            f_i: msg.f_i,
            prod_x: msg.prod_proof.x,
            prod_y_commit: msg.prod_proof.y_commit,
            prod_w: msg.prod_proof.w,
            prod_z1: msg.prod_proof.z1,
            prod_z2: msg.prod_proof.z2,
            prod_ddh_g_r: msg.prod_proof.ddh_proof.g_r,
            prod_ddh_a_r: msg.prod_proof.ddh_proof.a_r,
            prod_ddh_z: msg.prod_proof.ddh_proof.z,
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> MultRound1Msg<C> {
        use tecdsa_curve::zk::{ddh::DdhProof, prod::ProdProof};
        MultRound1Msg {
            from: tecdsa_protocol::PartyId(self.from),
            e_i: self.e_i,
            f_i: self.f_i,
            prod_proof: ProdProof {
                x: self.prod_x,
                y_commit: self.prod_y_commit,
                w: self.prod_w,
                z1: self.prod_z1,
                z2: self.prod_z2,
                ddh_proof: DdhProof {
                    g_r: self.prod_ddh_g_r,
                    a_r: self.prod_ddh_a_r,
                    z: self.prod_ddh_z,
                },
            },
        }
    }
}

/// Serializable wrapper for `MultRound2Msg<C>`: $(A_i, B_i)$ + R_EG proof.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct SerMultRound2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: u16,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub a_i: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub b_i: C::ProjectivePoint,
    // EgexpProof fields
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub eg_commit_x: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub eg_commit_y: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub eg_z1: C::Scalar,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub eg_z2: C::Scalar,
}

impl<C: TecdsaCurve> SerMultRound2<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn from_msg(msg: &MultRound2Msg<C>) -> Self {
        Self {
            from: msg.from.0,
            a_i: msg.a_i,
            b_i: msg.b_i,
            eg_commit_x: msg.egexp_proof.commit_x,
            eg_commit_y: msg.egexp_proof.commit_y,
            eg_z1: msg.egexp_proof.z1,
            eg_z2: msg.egexp_proof.z2,
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> MultRound2Msg<C> {
        use tecdsa_curve::zk::egexp::EgexpProof;
        MultRound2Msg {
            from: tecdsa_protocol::PartyId(self.from),
            a_i: self.a_i,
            b_i: self.b_i,
            egexp_proof: EgexpProof {
                commit_x: self.eg_commit_x,
                commit_y: self.eg_commit_y,
                z1: self.eg_z1,
                z2: self.eg_z2,
            },
        }
    }
}

/// Serializable wrapper for `MultRound3Msg<C>`: checkDH rerandomization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct SerMultRound3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: u16,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub u_prime_i: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub v_prime_i: C::ProjectivePoint,
    // ReProof fields: x, y (2 points) + z1, z2 (2 scalars)
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub re_x: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub re_y: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub re_z1: C::Scalar,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub re_z2: C::Scalar,
}

impl<C: TecdsaCurve> SerMultRound3<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn from_msg(msg: &MultRound3Msg<C>) -> Self {
        Self {
            from: msg.from.0,
            u_prime_i: msg.u_prime_i,
            v_prime_i: msg.v_prime_i,
            re_x: msg.re_proof.x,
            re_y: msg.re_proof.y,
            re_z1: msg.re_proof.z1,
            re_z2: msg.re_proof.z2,
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> MultRound3Msg<C> {
        use tecdsa_curve::zk::rerandom::ReProof;
        MultRound3Msg {
            from: tecdsa_protocol::PartyId(self.from),
            u_prime_i: self.u_prime_i,
            v_prime_i: self.v_prime_i,
            re_proof: ReProof {
                x: self.re_x,
                y: self.re_y,
                z1: self.re_z1,
                z2: self.re_z2,
            },
        }
    }
}

/// Serializable wrapper for `MultRound4Msg<C>`: checkDH partial decryption.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct SerMultRound4<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: u16,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub w_i: C::ProjectivePoint,
    // DdhProof fields
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub ddh_g_r: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub ddh_a_r: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub ddh_z: C::Scalar,
}

impl<C: TecdsaCurve> SerMultRound4<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn from_msg(msg: &MultRound4Msg<C>) -> Self {
        Self {
            from: msg.from.0,
            w_i: msg.w_i,
            ddh_g_r: msg.ddh_proof.g_r,
            ddh_a_r: msg.ddh_proof.a_r,
            ddh_z: msg.ddh_proof.z,
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> MultRound4Msg<C> {
        use tecdsa_curve::zk::ddh::DdhProof;
        MultRound4Msg {
            from: tecdsa_protocol::PartyId(self.from),
            w_i: self.w_i,
            ddh_proof: DdhProof {
                g_r: self.ddh_g_r,
                a_r: self.ddh_a_r,
                z: self.ddh_z,
            },
        }
    }
}

/// Serializable wrapper for `MultRound5Msg<C>`: reveal c_i + R_DH proof.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct SerMultRound5<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: u16,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub c_i: C::Scalar,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub ddh_g_r: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_point::<C, _>",
        deserialize_with = "de_point::<C, _>"
    )]
    pub ddh_a_r: C::ProjectivePoint,
    #[serde(
        serialize_with = "ser_scalar::<C, _>",
        deserialize_with = "de_scalar::<C, _>"
    )]
    pub ddh_z: C::Scalar,
}

impl<C: TecdsaCurve> SerMultRound5<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn from_msg(msg: &MultRound5Msg<C>) -> Self {
        Self {
            from: msg.from.0,
            c_i: msg.c_i,
            ddh_g_r: msg.ddh_proof.g_r,
            ddh_a_r: msg.ddh_proof.a_r,
            ddh_z: msg.ddh_proof.z,
        }
    }

    #[must_use]
    pub fn to_msg(&self) -> MultRound5Msg<C> {
        use tecdsa_curve::zk::ddh::DdhProof;
        MultRound5Msg {
            from: tecdsa_protocol::PartyId(self.from),
            c_i: self.c_i,
            ddh_proof: DdhProof {
                g_r: self.ddh_g_r,
                a_r: self.ddh_a_r,
                z: self.ddh_z,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Offline sign message envelope (Rounds 1-2)
// ---------------------------------------------------------------------------

/// Message envelope for the LN18 offline signing phase (2 rounds).
///
/// Wraps parallel `input(k)` and `input(rho)` messages into a single
/// enum used by `Ln18OfflineSignMachine`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
#[allow(clippy::large_enum_variant)]
pub enum Ln18OfflineSignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Round 1: hash commitments for both input(k) and input(rho).
    Round1Input {
        k: SerInputRound1,
        rho: SerInputRound1,
    },
    /// Round 2: decommitments with ciphertexts and proofs for both inputs.
    Round2Input {
        k: SerInputRound2<C>,
        rho: SerInputRound2<C>,
    },
}

// ---------------------------------------------------------------------------
// Online sign message envelope (Rounds 3-8)
// ---------------------------------------------------------------------------

/// Message envelope for the LN18 online signing phase (6 rounds).
///
/// Wraps interleaved element-out, mult1(k,rho), and mult2(rho,alpha) messages.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
#[allow(clippy::large_enum_variant)]
pub enum Ln18OnlineSignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Round 3: element-out(k) || mult1(k,rho).R1
    Round3 {
        element_out: SerElementOut<C>,
        mult1_r1: SerMultRound1<C>,
    },
    /// Round 4: mult1.R2 || mult2(rho,alpha).R1
    Round4 {
        mult1_r2: SerMultRound2<C>,
        mult2_r1: SerMultRound1<C>,
    },
    /// Round 5: mult1.R3 || mult2.R2
    Round5 {
        mult1_r3: SerMultRound3<C>,
        mult2_r2: SerMultRound2<C>,
    },
    /// Round 6: mult1.R4 || mult2.R3
    Round6 {
        mult1_r4: SerMultRound4<C>,
        mult2_r3: SerMultRound3<C>,
    },
    /// Round 7: mult1.R5 || mult2.R4
    Round7 {
        mult1_r5: SerMultRound5<C>,
        mult2_r4: SerMultRound4<C>,
    },
    /// Round 8: mult2.R5 (mult1 finishes locally after Round 7)
    Round8 { mult2_r5: SerMultRound5<C> },
}

// ---------------------------------------------------------------------------
// Legacy placeholder types for backward compatibility
// ---------------------------------------------------------------------------

/// Placeholder message type for the legacy presign state machine.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Ln18PresignMsg {
    pub(crate) _placeholder: u8,
}

/// Placeholder message type for the legacy sign state machine.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Ln18SignMsg {
    pub(crate) _placeholder: u8,
}

/// Placeholder message type for the legacy full-sign state machine.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Ln18FullSignMsg {
    pub(crate) _placeholder: u8,
}

// ---------------------------------------------------------------------------
// Round number helpers
// ---------------------------------------------------------------------------

/// Extract the round number from an offline sign message variant.
pub(crate) fn offline_msg_round<C: TecdsaCurve>(msg: &Ln18OfflineSignMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        Ln18OfflineSignMsg::Round1Input { .. } => 1,
        Ln18OfflineSignMsg::Round2Input { .. } => 2,
    }
}

/// Extract the round number from an online sign message variant.
pub(crate) fn online_msg_round<C: TecdsaCurve>(msg: &Ln18OnlineSignMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        Ln18OnlineSignMsg::Round3 { .. } => 1,
        Ln18OnlineSignMsg::Round4 { .. } => 2,
        Ln18OnlineSignMsg::Round5 { .. } => 3,
        Ln18OnlineSignMsg::Round6 { .. } => 4,
        Ln18OnlineSignMsg::Round7 { .. } => 5,
        Ln18OnlineSignMsg::Round8 { .. } => 6,
    }
}
