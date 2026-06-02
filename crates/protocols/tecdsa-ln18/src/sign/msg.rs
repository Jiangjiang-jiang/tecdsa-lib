// SPDX-License-Identifier: MIT OR Apache-2.0
//! LN18 sign message types for the StateMachine wrappers.

/// Placeholder message type for the presign state machine.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Ln18PresignMsg {
    pub(crate) _placeholder: u8,
}

/// Placeholder message type for the online sign state machine.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Ln18OnlineSignMsg {
    pub(crate) _placeholder: u8,
}

/// Placeholder message type for the sign state machine.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Ln18SignMsg {
    pub(crate) _placeholder: u8,
}

/// Placeholder message type for the full-sign state machine.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Ln18FullSignMsg {
    pub(crate) _placeholder: u8,
}
