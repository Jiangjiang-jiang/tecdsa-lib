// SPDX-License-Identifier: MIT OR Apache-2.0
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_paillier::{backend::Integer, threshold::PartialDecryption};

/// All message types for the GGN16 signing protocol (Rounds 1-6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ggn16SignMsg {
    /// Round 1: commit to $(u_i, v_i)$.
    Round1(SignRound1Msg),
    /// Round 2: decommit + $\Pi_{1,i}$ proof.
    Round2(SignRound2Msg),
    /// Round 3: commit to $(r_i, w_i)$.
    Round3(SignRound3Msg),
    /// Round 4: decommit + $\Pi_{2,i}$ proof.
    Round4(SignRound4Msg),
    /// Round 5: partial decryption of $w$.
    Round5(SignRound5Msg),
    /// Round 6: partial decryption of $\sigma$.
    Round6(SignRound6Msg),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound1Msg {
    pub commitment: HashCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound2Msg {
    pub u_i: Integer,
    pub v_i: Integer,
    pub nonce: [u8; 32],
    /// Serialized Pi_{1,i} (HomoMultProof).
    ///
    /// Stored as `Vec<u8>` because `HomoMultProof` does not implement serde.
    /// Use `HomoMultProof::to_bytes()` / `HomoMultProof::from_bytes()` to
    /// serialize and deserialize.
    pub homo_mult_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound3Msg {
    pub commitment: HashCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound4Msg {
    pub r_i_bytes: Vec<u8>,
    pub w_i: Integer,
    pub nonce: [u8; 32],
    /// Serialized Pi_{2,i} (NonceConsistProof).
    ///
    /// Stored as `Vec<u8>` because `NonceConsistProof<C>` has complex generics
    /// and does not implement serde. Use `NonceConsistProof::to_bytes()` /
    /// `NonceConsistProof::from_bytes()` to serialize and deserialize.
    pub nonce_consist_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound5Msg {
    pub partial_w: PartialDecryption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound6Msg {
    pub partial_sigma: PartialDecryption,
}
