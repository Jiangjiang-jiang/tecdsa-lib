// SPDX-License-Identifier: MIT OR Apache-2.0
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PartyId(pub u16);

impl std::fmt::Display for PartyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    pub id: PartyId,
    pub index: u16,
    pub total: u16,
    /// Reconstruction/signing threshold `t` (number of parties needed to sign).
    /// Maximum tolerated corruptions is `t - 1`.
    pub threshold: u16,
}
