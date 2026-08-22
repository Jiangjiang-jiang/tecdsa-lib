// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wire messages for KU25 key generation.

use serde::{Deserialize, Serialize};

/// Keygen wire message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ku25KeygenMsg {
    /// Round 1 (broadcast): `X_j = g^{x_j}`, SEC1-compressed.
    Round1(Vec<u8>),
}
