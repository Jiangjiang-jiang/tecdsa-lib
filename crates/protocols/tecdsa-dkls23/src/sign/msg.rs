// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the DKLs23 signing protocol.
//!
//! The full signing protocol runs in 4 rounds:
//! - Round 1 (Presign): broadcast nonce commitment H(salt || R_i)
//!   + P2P RVOLE init data (OteInitSenderMsg)
//! - Round 2 (Presign): broadcast decommitment (salt + R_i)
//!   + P2P RVOLE receiver phase1 data (OteDataToSender)
//! - Round 3 (Presign): P2P RVOLE sender output (MulDataToReceiver)
//!   + RVOLE consistency data (Gamma^u, Gamma^v, psi, pk_i)
//! - Round 4 (OnlineSign): broadcast partial signature (u_i, w_i)

#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_ot::rvole::MulDataToReceiver;
use tecdsa_ot::soft_spoken::{OteDataToSender, OteInitSenderMsg};

// ---------------------------------------------------------------------------
// Round 1: nonce commitment + RVOLE init (presign)
// ---------------------------------------------------------------------------

/// Round 1 broadcast: hash commitment to the nonce point R_i.
///
/// Each party commits to `H(salt || R_i_bytes)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignR1Broadcast {
    /// SHA-256 commitment: `H(salt || R_i)`.
    pub commitment: [u8; 32],
}

/// Round 1 P2P: RVOLE initialization data from party i to party j.
///
/// Contains the OTE sender init message. Each party runs `MulSender::init`
/// and sends the resulting `OteInitSenderMsg` to each counterparty, along
/// with the nonce used to derive the public gadget vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignR1P2p {
    /// OTE sender initialization message (for the RVOLE instance where
    /// the sender of this message will act as MulSender).
    pub ote_init_msg: OteInitSenderMsg,
    /// Nonce scalar bytes for the public gadget vector.
    pub nonce: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Round 2: decommitment + RVOLE receiver phase 1 (presign)
// ---------------------------------------------------------------------------

/// Round 2 broadcast: decommitment revealing the nonce point R_i.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignR2Broadcast {
    /// Random salt used in the Round 1 commitment.
    pub salt: [u8; 32],
    /// Nonce point R_i = r_i * G, serialized as compressed SEC1.
    pub R_i: Vec<u8>,
}

/// Round 2 P2P: RVOLE receiver phase 1 data from party i to party j.
///
/// Contains the OTE data that the receiver (this party) sends to the
/// sender (counterparty j) for the RVOLE instance where this party
/// is MulReceiver and j is MulSender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignR2P2p {
    /// OTE data from receiver phase 1 (for the RVOLE instance where
    /// the sender of this message is MulReceiver).
    pub ote_data: OteDataToSender,
}

// ---------------------------------------------------------------------------
// Round 3: RVOLE sender output + consistency data (presign)
// ---------------------------------------------------------------------------

/// Round 3 P2P: RVOLE sender output + consistency data from party i to party j.
///
/// Contains the MulDataToReceiver (for the RVOLE instance where this party
/// is MulSender) plus the EC consistency check elements.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct SignR3P2p<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// RVOLE sender output: MulDataToReceiver for the instance where this
    /// party acted as MulSender (input [r_i, sk_i]) and the recipient
    /// acted as MulReceiver.
    pub mul_data: MulDataToReceiver,
    /// Gamma^u_{i,j} = c^u_{i,j} * G
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub Gamma_u: C::ProjectivePoint,
    /// Gamma^v_{i,j} = c^v_{i,j} * G
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub Gamma_v: C::ProjectivePoint,
    /// psi_{i,j} = phi_i - chi_{i,j}
    pub psi: <C as CurveArithmetic>::Scalar,
    /// pk_i = sk_i * G (Lagrange-weighted key share public key)
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub pk_i: C::ProjectivePoint,
}

// ---------------------------------------------------------------------------
// Round 4: online signing (partial signature broadcast)
// ---------------------------------------------------------------------------

/// Round 4 broadcast: partial signature values (u_i, w_i).
///
/// Each party broadcasts its contribution to the ECDSA signature.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct SignR4Broadcast<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// u_i: party i's share of the nonce inversion.
    pub u_i: <C as CurveArithmetic>::Scalar,
    /// w_i: party i's share of the signature scalar.
    pub w_i: <C as CurveArithmetic>::Scalar,
}

// ---------------------------------------------------------------------------
// Unified envelope
// ---------------------------------------------------------------------------

/// Unified envelope for all DKLs23 signing messages.
///
/// Used by both the presign and online sign state machines.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum Dkls23SignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Presign Round 1: nonce commitment broadcast.
    Round1Broadcast(SignR1Broadcast),
    /// Presign Round 1: P2P RVOLE init data.
    Round1P2p(SignR1P2p),
    /// Presign Round 2: nonce decommitment broadcast.
    Round2Broadcast(SignR2Broadcast),
    /// Presign Round 2: P2P RVOLE receiver phase 1 data.
    Round2P2p(SignR2P2p),
    /// Presign Round 3: P2P RVOLE sender output + consistency data.
    Round3P2p(SignR3P2p<C>),
    /// Online Sign Round 4: partial signature broadcast.
    Round4Broadcast(SignR4Broadcast<C>),
}
