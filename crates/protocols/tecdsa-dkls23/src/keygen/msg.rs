// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the DKLs23 key generation protocol.
//!
//! The protocol runs in 3 rounds:
//! - Round 1: broadcast hash commitment to share evaluation points X_{i,j}
//! - Round 2: broadcast decommitment (salt + X_{i,j} points + P_i^*),
//!   and P2P send Shamir share s_{i,j} to each party j
//! - Round 3: no outgoing messages -- verification + output computation

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Round 1: commitment hash
// ---------------------------------------------------------------------------

/// Round 1 broadcast: hash commitment to all share evaluation points.
///
/// Each party commits to `H(salt || X_{i,1} || ... || X_{i,n})` where
/// `X_{i,j} = p_i(j) * G` is the EC-point commitment to the Shamir share
/// that party i will send to party j.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenR1Broadcast {
    /// SHA-256 hash commitment: `H(salt || X_{i,1} || ... || X_{i,n} || P_i^*)`.
    pub commitment: [u8; 32],
}

// ---------------------------------------------------------------------------
// Round 2: decommitment + P2P shares
// ---------------------------------------------------------------------------

/// Round 2 broadcast: decommitment revealing the salt and all committed points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenR2Broadcast {
    /// Random salt used in the Round 1 commitment.
    pub salt: [u8; 32],
    /// EC point commitments X_{i,j} = p_i(j) * G for j in \[n\], serialized
    /// as compressed SEC1 encoding.
    pub point_commitments: Vec<Vec<u8>>,
    /// P_i^* = p_i(0) * G: the EC commitment to the constant term of p_i,
    /// serialized as compressed SEC1 encoding.
    pub p_i_star: Vec<u8>,
}

/// Round 2 P2P: the Shamir share s_{i,j} = p_i(j) sent from party i to party j.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenR2P2p {
    /// Shamir share s_{i,j} serialized as the scalar's canonical byte repr.
    pub share: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Unified envelope
// ---------------------------------------------------------------------------

/// Unified envelope for all DKLs23 keygen messages.
///
/// Uses a single type for both `Inbound` and `Outbound` so that the
/// `Orchestrator` constraint `Outbound: Into<Inbound>` is trivially satisfied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Dkls23KeygenMsg {
    /// Round 1: broadcast commitment hash.
    Round1Broadcast(KeygenR1Broadcast),
    /// Round 2: broadcast decommitment (salt + points).
    Round2Broadcast(KeygenR2Broadcast),
    /// Round 2: P2P Shamir share for the recipient.
    Round2P2p(KeygenR2P2p),
}
