// SPDX-License-Identifier: MIT OR Apache-2.0
//! XAL23 interactive DKG message types.

use serde::{Deserialize, Serialize};

/// Messages exchanged during the XAL23 2-round interactive DKG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Xal23KeygenMsg {
    /// Round 1: 32-byte hash commitment.
    Round1(Vec<u8>),
    /// Round 2 broadcast: decommitment data (nonce, JL public key,
    /// VSS commitments, DlogProof).
    Round2Bcast(Vec<u8>),
    /// Round 2 P2P: VSS share for the recipient (32 bytes scalar).
    Round2Share(Vec<u8>),
}
