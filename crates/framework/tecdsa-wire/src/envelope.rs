// SPDX-License-Identifier: MIT OR Apache-2.0
use serde::{Deserialize, Serialize};

pub const PREAMBLE: &[u8; 4] = b"MPCE";
pub const WIRE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub session_id: [u8; 32],
    pub protocol_id: u16,
    pub round: u16,
    pub from: u16,
    pub to: u16,
}
