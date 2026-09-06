// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the GGN16 threshold key generation protocol.
//!
//! The protocol runs in 2 rounds:
//! - Round 1: broadcast hash commitment to y_i
//! - Round 2: broadcast decommitment (y_i, nonce), encrypted share alpha_i,
//!   and PdlSlack proof that alpha_i encrypts the discrete log of y_i

#![allow(non_snake_case)]

use elliptic_curve::CurveArithmetic;
use rug::Integer;
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;

// ---------------------------------------------------------------------------
// Round 1: hash commitment
// ---------------------------------------------------------------------------

/// Round 1 broadcast: hash commitment to the public key contribution y_i.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenRound1Msg {
    /// Hash commitment `V_i = H(nonce || y_i_bytes)`.
    pub commitment: HashCommitment,
}

// ---------------------------------------------------------------------------
// Round 2: decommitment + encrypted share + PDL-slack proof
// ---------------------------------------------------------------------------

/// Round 2 broadcast: decommitment, encrypted secret share, and ZK proof.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct KeygenRound2Msg<C: CurveArithmetic> {
    /// Serialized y_i point bytes (compressed SEC1 encoding).
    pub y_i_bytes: Vec<u8>,
    /// Decommitment nonce for the Round 1 hash commitment.
    pub nonce: [u8; 32],
    /// Paillier ciphertext alpha_i = E(x_i) under the shared key.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub alpha_i: Integer,
    /// Paillier encryption nonce for alpha_i (needed by the proof).
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub alpha_i_nonce: Integer,
    /// PdlSlack proof bytes: proves that alpha_i encrypts the discrete log
    /// of y_i.  Serialized via `PdlSlackProof::to_bytes()` /
    /// `PdlSlackProof::from_bytes()`.
    pub proof: Vec<u8>,
    /// Phantom to carry the curve type parameter.
    #[serde(skip)]
    pub _marker: std::marker::PhantomData<C>,
}

// ---------------------------------------------------------------------------
// Unified envelope
// ---------------------------------------------------------------------------

/// Unified envelope for all GGN16 keygen messages.
///
/// Uses a single type for both `Inbound` and `Outbound` so that the
/// `Orchestrator` constraint `Outbound: Into<Inbound>` is trivially satisfied.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub enum Ggn16KeygenMsg<C: CurveArithmetic> {
    Round1(KeygenRound1Msg),
    Round2(KeygenRound2Msg<C>),
}
