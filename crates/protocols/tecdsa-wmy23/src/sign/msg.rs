// SPDX-License-Identifier: GPL-3.0-or-later
//! WMY23 online signing message types.

use serde::{Deserialize, Serialize};

/// Messages exchanged during WMY23 online signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wmy23SignMsg {
    /// Round 5: partial signature broadcast.
    Round5(Vec<u8>),
}
