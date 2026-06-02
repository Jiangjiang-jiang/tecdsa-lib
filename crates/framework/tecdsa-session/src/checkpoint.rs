// SPDX-License-Identifier: MIT OR Apache-2.0
use serde::{Deserialize, Serialize};
use tecdsa_protocol::StateMachine;

/// Marker trait for state machines that support checkpointing.
/// Protocol implementors opt in by implementing this.
pub trait Checkpointable: StateMachine {
    type Snapshot: Serialize + for<'de> Deserialize<'de>;
    fn snapshot(&self) -> Self::Snapshot;
    fn restore(snapshot: Self::Snapshot) -> Self;
}

#[derive(Serialize, Deserialize)]
pub struct SessionCheckpoint<S> {
    pub session_id: [u8; 32],
    pub my_id: u16,
    pub current_round: u16,
    pub protocol_id: u16,
    pub machine_snapshot: S,
    pub message_log_hash: [u8; 32],
}
