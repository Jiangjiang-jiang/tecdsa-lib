// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the LN18 Feldman VSS DKG protocol.
//!
//! 3 rounds: commit + decommit/P2P + Schnorr proof.

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};

/// Round 1 broadcast: hash commitment to Feldman polynomial + Schnorr nonce.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgRound1 {
    pub commitment: HashCommitment,
}

/// Round 2 broadcast: decommitment data.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound2Broad<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Random session contribution.
    pub rid: [u8; 32],
    /// Feldman polynomial commitments `C_j = a_j * G`.
    #[serde(with = "tecdsa_curve::serde_projective::vec")]
    pub feldman_commitments: Vec<C::ProjectivePoint>,
    /// Schnorr commitment `R_i = r_i * G`.
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub schnorr_commitment: C::ProjectivePoint,
    /// Nonce used when creating the hash commitment in Round 1.
    pub decommit_nonce: [u8; 32],
}

/// Round 2 unicast: VSS share for the recipient.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgRound2Uni<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The VSS share value `f_i(j)` for the recipient party.
    pub vss_share: <C as CurveArithmetic>::Scalar,
}

/// Round 3 broadcast: Schnorr proof of secret share knowledge.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Schnorr proof that the sender knows its secret share `x_i`.
    pub schnorr_proof: DlogProof<C>,
}

/// Unified envelope for all LN18 KeyGen messages.
///
/// 3 rounds: commit + decommit/VSS-share + Schnorr proof.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum Ln18KeygenMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Round 1: hash commitment.
    Round1(MsgRound1),
    /// Round 2 broadcast: decommit (Feldman commitments + Schnorr commitment + nonce + rid).
    Round2Broad(MsgRound2Broad<C>),
    /// Round 2 unicast: P2P VSS share.
    Round2Uni(MsgRound2Uni<C>),
    /// Round 3: Schnorr proof of combined share.
    Round3(MsgRound3<C>),
}

/// Extract the round number from a message variant (for error reporting).
pub(crate) fn msg_round<C: TecdsaCurve>(msg: &Ln18KeygenMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        Ln18KeygenMsg::Round1(_) => 1,
        Ln18KeygenMsg::Round2Broad(_) | Ln18KeygenMsg::Round2Uni(_) => 2,
        Ln18KeygenMsg::Round3(_) => 3,
    }
}
