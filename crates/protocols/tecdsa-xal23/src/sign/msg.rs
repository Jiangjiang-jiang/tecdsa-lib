// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sign message types for XAL23.

#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};

/// Messages exchanged during the XAL23 online signing round.
///
/// The signing phase is a single round: each party broadcasts its partial
/// signature scalar `s_i`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Xal23SignMsg {
    /// A party's partial signature scalar (big-endian byte encoding of `s_i`).
    PartialSig(Vec<u8>),
}
