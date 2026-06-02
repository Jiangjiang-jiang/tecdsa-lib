// SPDX-License-Identifier: MIT OR Apache-2.0
//! Async transport trait for production network backends.
//!
//! Wallet vendors implement [`AsyncTransport`] for their infrastructure
//! (gRPC, WebSocket, MQ, etc.) and plug it into [`AsyncSession`](crate::AsyncSession).

use std::time::Duration;
use tecdsa_protocol::PartyId;

/// Async transport trait for production network backends.
///
/// This is the async counterpart of [`Transport`](tecdsa_transport::Transport).
/// Unlike the synchronous trait, `receive` takes an explicit `timeout` and
/// returns `Result` to surface network errors.
#[async_trait::async_trait]
pub trait AsyncTransport: Send {
    /// Error type surfaced by the transport layer.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Send `data` from `from` to a specific party `to`.
    async fn send(&mut self, from: PartyId, to: PartyId, data: Vec<u8>) -> Result<(), Self::Error>;

    /// Broadcast `data` from `from` to all other parties.
    async fn broadcast(&mut self, from: PartyId, data: Vec<u8>) -> Result<(), Self::Error>;

    /// Receive all pending messages addressed to `party`, waiting up to `timeout`.
    ///
    /// Returns `(sender, payload)` pairs.  Implementations should return as
    /// soon as enough messages are available (or the timeout expires with
    /// whatever has arrived so far).
    async fn receive(
        &mut self,
        party: PartyId,
        timeout: Duration,
    ) -> Result<Vec<(PartyId, Vec<u8>)>, Self::Error>;
}
