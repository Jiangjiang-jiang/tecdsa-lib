// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wire messages for KU24 online signing.

use serde::{Deserialize, Serialize};

/// Sign wire message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ku24SignMsg {
    /// Round 1: `(r_i, s_j)`, the pair the paper sends to the coordinator.
    ///
    /// `r` is echoed so that a mismatch (two parties using different
    /// presignatures) is detected rather than silently producing garbage.
    Round1 {
        /// `r_i` of the presignature being consumed.
        r: Vec<u8>,
        /// This party's degree-`2t` share `s_j`.
        s: Vec<u8>,
    },
}
