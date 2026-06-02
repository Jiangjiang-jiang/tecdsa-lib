// SPDX-License-Identifier: GPL-3.0-or-later
//! LLZ25 interactive DKG message types.

use serde::{Deserialize, Serialize};

/// Messages exchanged during the LLZ25 3-round interactive DKG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Llz25KeygenMsg {
    /// Round 1: 32-byte hash commitment.
    Round1(Vec<u8>),
    /// Round 2 broadcast: decommitment data (nonce, VSS commitments, DlogProof).
    Round2Bcast(Vec<u8>),
    /// Round 2 P2P: VSS share for the recipient (32 bytes scalar).
    Round2Share(Vec<u8>),
    /// Round 3: NIM-encoded share (pe_x components, R_CL_DL_EC proof).
    Round3(Vec<u8>),
}
