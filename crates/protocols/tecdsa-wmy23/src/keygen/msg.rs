// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 keygen message types.

use serde::{Deserialize, Serialize};

/// Messages exchanged during WMY23 key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wmy23KeygenMsg {
    /// Round 1 broadcast: hash commitment (32 bytes).
    Round1(Vec<u8>),
    /// Round 2 broadcast: decommit (Pedersen commitments, CL pk, R_Key proof,
    /// CL ciphertext, R_Enc-PC proof).
    Round2(Vec<u8>),
    /// Round 2 P2P: Pedersen VSS share pair (value || randomness, 64 bytes).
    Round3(Vec<u8>),
    /// Round 3 broadcast: DRG.Comb + RevealExp output (combined PC, combined
    /// ciphertext, R_Enc-PC proof, X_i, Y_i, R_PC-DL proof).
    Round4(Vec<u8>),
}
