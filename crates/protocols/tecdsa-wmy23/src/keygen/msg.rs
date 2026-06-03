// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 keygen message types.

use serde::{Deserialize, Serialize};

/// Messages exchanged during WMY23 key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wmy23KeygenMsg {
    /// Round 1: hash commitment.
    Round1(Vec<u8>),
    /// Round 2: decommitment + CL public key + VSS coefficients.
    Round2(Vec<u8>),
    /// Round 3: P2P VSS shares + CL key proof.
    Round3(Vec<u8>),
    /// Round 4: complaints / confirmation.
    Round4(Vec<u8>),
}
