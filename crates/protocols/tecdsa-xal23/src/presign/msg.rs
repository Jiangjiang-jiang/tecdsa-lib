// SPDX-License-Identifier: MIT OR Apache-2.0
//! Presign message types for XAL23 (4-round StateMachine).
//!
//! Each round uses a dedicated variant carrying a bincode-encoded payload.
//! The payloads contain JL MtA ciphertexts and ZK proofs serialized via serde.

#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};
use tecdsa_joye_libert::mta::{JlMtaReceiverMsg, JlMtaSenderMsg};

/// Messages exchanged during the XAL23 4-round presigning protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Xal23PresignMsg {
    /// Round 1 broadcast: commitment to Gamma_i (SHA-256 hash, 32 bytes).
    R1Broadcast(R1BroadcastPayload),
    /// Round 1 P2P: MtA sender_encrypt outputs for one peer.
    R1P2p(R1P2pPayload),
    /// Round 2 broadcast: decommitment (Gamma_i point + nonce).
    R2Broadcast(R2BroadcastPayload),
    /// Round 2 P2P: MtA receiver_compute outputs for one peer.
    R2P2p(R2P2pPayload),
    /// Round 3 broadcast: delta_i scalar.
    R3Broadcast(R3BroadcastPayload),
}

/// Round 1 broadcast payload: commitment hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1BroadcastPayload {
    /// SHA-256 commitment: `H(compressed Gamma_i bytes)`.
    pub commitment: [u8; 32],
}

/// Round 1 P2P payload: MtA sender ciphertexts for gamma and w.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1P2pPayload {
    /// MtA sender message for gamma_i (ciphertext + ZkJlEncProof).
    pub gamma_sender_msg: JlMtaSenderMsg,
    /// MtA sender message for w_i (ciphertext + ZkJlEncProof).
    pub w_sender_msg: JlMtaSenderMsg,
}

/// Round 2 broadcast payload: decommitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2BroadcastPayload {
    /// Compressed Gamma_i point bytes.
    pub gamma_point_bytes: Vec<u8>,
}

/// Round 2 P2P payload: MtA receiver messages for one peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2P2pPayload {
    /// MtA receiver message for gamma MtA (affine ciphertext + ZkJlAffProof).
    pub gamma_receiver_msg: JlMtaReceiverMsg,
    /// MtA receiver message for w MtA (affine ciphertext + ZkJlAffProof).
    pub w_receiver_msg: JlMtaReceiverMsg,
}

/// Round 3 broadcast payload: delta_i scalar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R3BroadcastPayload {
    /// delta_i as big-endian 32-byte scalar encoding.
    pub delta_i_bytes: Vec<u8>,
}
