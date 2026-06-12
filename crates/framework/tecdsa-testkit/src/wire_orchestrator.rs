use tecdsa_protocol::{PartyId, StateMachine};
use tecdsa_session::{run_multi_party_sync, SessionRunConfig};
use tecdsa_transport::{InMemoryNetwork, NetworkMetrics};

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
    #[must_use]
    pub fn new(machines: Vec<(PartyId, M)>, max_rounds: u16) -> Self {
        Self {
            machines,
            max_rounds,
        }
    }

    #[must_use]
    pub fn run(self) -> WireOrchestratorResult<M::Output> {
        let party_ids: Vec<tecdsa_protocol::PartyId> =
            self.machines.iter().map(|(pid, _)| *pid).collect();
        let mut network = InMemoryNetwork::from_party_ids(&party_ids);
        let session_id = [0u8; 32];
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

        let outputs = results
            .into_iter()
            .map(|r| r.map_err(|e| tecdsa_core::TecdsaError::Other(e.to_string())))
            .collect();

        let metrics = network.metrics().clone();

        WireOrchestratorResult { outputs, metrics }
    }
}

pub struct WireOrchestratorResult<O> {
    pub outputs: Vec<tecdsa_core::Result<O>>,
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
        for (i, res) in results.iter().enumerate() {
            assert!(
                res.is_ok(),
                "party {i} failed via WireOrchestrator: {:?}",
                res.as_ref().err()
            );
        }
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
