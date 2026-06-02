// SPDX-License-Identifier: MIT OR Apache-2.0
#![doc = "Transport trait and in-memory adapter for the tecdsa threshold ECDSA library."]

pub mod in_memory;
pub mod netsim;

pub use in_memory::{InMemoryNetwork, NetworkMetrics, NetworkPartyMetrics};
use tecdsa_protocol::PartyId;

/// Transport abstraction for threshold ECDSA protocols.
///
/// Protocols are transport-agnostic; they call `send`/`broadcast`/`receive`
/// and do not care whether the underlying channel is in-memory, TCP, or WebSocket.
pub trait Transport {
    /// Send `data` from `from` to `to`.
    fn send(&mut self, from: PartyId, to: PartyId, data: Vec<u8>);

    /// Broadcast `data` from `from` to all other parties.
    fn broadcast(&mut self, from: PartyId, data: Vec<u8>);

    /// Drain all pending messages addressed to `party`, returning `(sender, payload)` pairs.
    fn receive(&mut self, party: PartyId) -> Vec<(PartyId, Vec<u8>)>;
}
