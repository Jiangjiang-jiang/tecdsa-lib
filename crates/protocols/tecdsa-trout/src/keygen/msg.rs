// SPDX-License-Identifier: GPL-3.0-or-later
//! Trout interactive DKG message types.

use serde::{Deserialize, Serialize};

/// Messages exchanged during the Trout 3-round interactive DKG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TroutKeygenMsg {
    /// Round 1: 32-byte hash commitment.
    Round1(Vec<u8>),
    /// Round 2 broadcast: decommitment data (nonce, eVRF pk, VSS commitments,
    /// CL contribution QFI, `DlogProof`).
    Round2Bcast(Vec<u8>),
    /// Round 2 P2P: VSS share for the recipient (32 bytes scalar).
    Round2Share(Vec<u8>),
    /// Round 3: encrypted share (`X_i`, `C_tilde_i`, `R_CL_EC` proof).
    Round3(Vec<u8>),
}
