// SPDX-License-Identifier: MIT OR Apache-2.0
//! Presign message types for XAL23.
//!
//! The simulation-mode `Xal23PresignMachine` does not exchange messages, so
//! this type exists solely to satisfy the `StateMachine` associated type bounds.
//! When a proper multi-round presign is implemented, this enum will be expanded
//! with per-round variants (commitments, `MtA` ciphertexts, delta broadcasts,
//! etc.).

#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};

/// Messages for the XAL23 presign `StateMachine`.
///
/// Currently a unit enum because the simulation-mode machine does not
/// exchange messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Xal23PresignMsg {
    /// Placeholder variant. The simulation-mode presign machine does not
    /// send or receive messages.
    _Placeholder,
}
