// SPDX-License-Identifier: GPL-3.0-or-later
//! TX25 keygen message types.

use serde::{Deserialize, Serialize};

/// Messages exchanged during TX25 key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Tx25KeygenMsg {
    /// Round 1: CL key pair + R_key proof.
    Round1(Vec<u8>),
    /// Round 2: PVSS share distribution + R_Sh proof.
    Round2(Vec<u8>),
    /// Round 3: Public share X_i + R_Dec_DL proof.
    Round3(Vec<u8>),
}
