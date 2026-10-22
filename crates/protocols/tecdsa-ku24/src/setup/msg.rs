// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wire messages for the PRSS setup phase.

use serde::{Deserialize, Serialize};

use crate::prss::{SubsetMask, KEY_LEN};

/// A single replicated PRF key, tagged with the subset it belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Bitmask of the subset `A` (bit `i - 1` set iff party `i` is a member).
    pub subset: SubsetMask,
    /// The key `k_A`.
    pub key: [u8; KEY_LEN],
}

/// Setup wire message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ku24SetupMsg {
    /// Round 1 (point-to-point): the keys this party deals to the recipient.
    ///
    /// Sent over the private channel; there is no broadcast and no
    /// commit/complain round (Section 5).
    Keys(Vec<KeyEntry>),
}
