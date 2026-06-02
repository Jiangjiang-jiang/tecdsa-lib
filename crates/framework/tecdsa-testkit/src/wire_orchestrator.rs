// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wire-aware multi-party orchestrator for integration testing.
//!
//! [`WireOrchestrator`] is similar to [`crate::Orchestrator`] but routes every
//! message through the full wire encode/decode path (via
//! [`run_multi_party_sync`]).  This verifies that protocol messages survive
//! serialization round-trips, catching any `serde` or `bincode` regressions
//! that the direct-delivery `Orchestrator` would miss.
//!
//! Key difference from `Orchestrator`: `WireOrchestrator` does **not** require
//! `Outbound: Into<Inbound>`.  The wire serialization handles the type
//! round-trip instead.

use tecdsa_protocol::{PartyId, StateMachine};
use tecdsa_session::{run_multi_party_sync, SessionRunConfig};
use tecdsa_transport::{InMemoryNetwork, NetworkMetrics};

/// Orchestrator that routes all messages through wire encode/decode.
///
/// Wraps [`run_multi_party_sync`] with a simple builder API matching
/// [`crate::Orchestrator`].
pub struct WireOrchestrator<M: StateMachine> {
    machines: Vec<(PartyId, M)>,
    max_rounds: u16,
}

impl<M> WireOrchestrator<M>
where
    M: StateMachine,
    M::Outbound: serde::Serialize + Clone,
    M::Inbound: serde::de::DeserializeOwned + Clone,
{
    /// Create a new wire orchestrator.
    ///
    /// * `machines`   -- `(PartyId, StateMachine)` pairs, one per party.
    /// * `max_rounds` -- hard cap on outer-loop iterations (fail-safe).
    #[must_use]
    pub fn new(machines: Vec<(PartyId, M)>, max_rounds: u16) -> Self {
        Self {
            machines,
            max_rounds,
        }
    }

    /// Drive all machines to completion through the wire encode/decode path.
    ///
    /// Returns a [`WireOrchestratorResult`] that dereferences to
    /// `Vec<Result<M::Output>>` for API compatibility with
    /// [`crate::OrchestratorResult`].
    #[must_use]
    pub fn run(self) -> WireOrchestratorResult<M::Output> {
        let party_ids: Vec<tecdsa_protocol::PartyId> =
            self.machines.iter().map(|(pid, _)| *pid).collect();
        let mut network = InMemoryNetwork::from_party_ids(&party_ids);
        let session_id = [0u8; 32]; // deterministic for testing
        let config = SessionRunConfig {
            max_rounds: self.max_rounds,
            ..SessionRunConfig::default()
        };

        let results = run_multi_party_sync(
            self.machines,
            &mut network,
            session_id,
            config,
            self.max_rounds,
        );

        // Convert Vec<Result<M::Output, SessionError>> to Vec<tecdsa_core::Result<M::Output>>
        let outputs = results
            .into_iter()
            .map(|r| r.map_err(|e| tecdsa_core::TecdsaError::Other(e.to_string())))
            .collect();

        let metrics = network.metrics().clone();

        WireOrchestratorResult { outputs, metrics }
    }
}

/// Result of a [`WireOrchestrator`] run.
///
/// Dereferences to `Vec<Result<O>>` and implements `IntoIterator` for
/// compatibility with [`crate::OrchestratorResult`].
///
/// Also carries [`NetworkMetrics`] with per-party bytes/messages counts.
pub struct WireOrchestratorResult<O> {
    /// Per-party protocol outputs.
    pub outputs: Vec<tecdsa_core::Result<O>>,
    /// Communication metrics collected during the run.
    pub metrics: NetworkMetrics,
}

impl<O> std::ops::Deref for WireOrchestratorResult<O> {
    type Target = Vec<tecdsa_core::Result<O>>;
    fn deref(&self) -> &Self::Target {
        &self.outputs
    }
}

impl<O> IntoIterator for WireOrchestratorResult<O> {
    type Item = tecdsa_core::Result<O>;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.outputs.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toy_dkg::ToyDkgMachine;

    fn make_machines(n: u16) -> Vec<(PartyId, ToyDkgMachine)> {
        (0..n)
            .map(|i| (PartyId(i), ToyDkgMachine::new(PartyId(i), n)))
            .collect()
    }

    #[test]
    fn wire_orchestrator_toy_dkg_3_parties() {
        let results = WireOrchestrator::new(make_machines(3), 10).run();
        // All three parties must succeed.
        for (i, res) in results.iter().enumerate() {
            assert!(
                res.is_ok(),
                "party {i} failed via WireOrchestrator: {:?}",
                res.as_ref().err()
            );
        }
        // All parties must agree on the same combined key.
        let first = results[0].as_ref().unwrap();
        for (i, res) in results.iter().enumerate().skip(1) {
            assert_eq!(
                first,
                res.as_ref().unwrap(),
                "party {i} disagrees with party 0 via WireOrchestrator"
            );
        }
    }

    #[test]
    fn wire_orchestrator_matches_direct_orchestrator() {
        use crate::Orchestrator;
        let n = 3u16;

        let wire_results = WireOrchestrator::new(make_machines(n), 10).run();
        let orch_results = Orchestrator::new(make_machines(n), 10)
            .run()
            .expect("orchestrator must succeed");

        for (i, (wr, or)) in wire_results.iter().zip(orch_results.iter()).enumerate() {
            assert_eq!(
                wr.as_ref().unwrap(),
                or.as_ref().unwrap(),
                "party {i}: WireOrchestrator output differs from Orchestrator output"
            );
        }
    }
}
