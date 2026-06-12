use tecdsa_protocol::{state_machine::Recipient, PartyId, StateMachine};
use tecdsa_transport::Transport;

use crate::{
    config::SessionRunConfig, error::SessionError, metrics::SessionMetrics, runner::SessionRunner,
};

pub struct SyncSession<M, T>
where
    M: StateMachine,
    M::Outbound: serde::Serialize,
    M::Inbound: serde::de::DeserializeOwned,
    T: Transport,
{
    runner: SessionRunner<M>,
    transport: T,
    my_id: PartyId,
}

impl<M, T> SyncSession<M, T>
where
    M: StateMachine,
    M::Outbound: serde::Serialize,
    M::Inbound: serde::de::DeserializeOwned,
    T: Transport,
{
    pub fn new(
        machine: M,
        transport: T,
        my_id: PartyId,
        parties: Vec<PartyId>,
        session_id: [u8; 32],
        config: SessionRunConfig,
    ) -> Self {
        let runner = SessionRunner::new(machine, session_id, my_id, parties, config);
        Self {
            runner,
            transport,
            my_id,
        }
    }

    pub fn run(mut self) -> Result<M::Output, SessionError> {
        loop {
            let encoded = self.runner.step_encode()?;
            for (recipient, bytes) in encoded {
                match recipient {
                    Recipient::Party(to) => {
                        self.transport.send(self.my_id, to, bytes);
                    }
                    Recipient::Broadcast => {
                        self.transport.broadcast(self.my_id, bytes);
                    }
                }
            }

            if self.runner.is_done() {
                return self.runner.finish();
            }
            if self.runner.current_round() >= self.runner.config.max_rounds {
                return Err(SessionError::MaxRoundsExceeded(
                    self.runner.config.max_rounds,
                ));
            }

            let raw = self.transport.receive(self.my_id);
            self.runner.step_decode(&raw)?;
        }
    }

    pub fn metrics(&self) -> &SessionMetrics {
        &self.runner.metrics
    }
}

pub fn run_multi_party_sync<M>(
    machines: Vec<(PartyId, M)>,
    network: &mut tecdsa_transport::InMemoryNetwork,
    session_id: [u8; 32],
    config: SessionRunConfig,
    max_rounds: u16,
) -> Vec<Result<M::Output, SessionError>>
where
    M: StateMachine,
    M::Outbound: serde::Serialize + Clone,
    M::Inbound: serde::de::DeserializeOwned + Clone,
{
    use tecdsa_transport::Transport;

    let all_parties: Vec<PartyId> = machines.iter().map(|(pid, _)| *pid).collect();
    let n = machines.len();

    let mut runners: Vec<Option<SessionRunner<M>>> = machines
        .into_iter()
        .map(|(pid, m)| {
            Some(SessionRunner::new(
                m,
                session_id,
                pid,
                all_parties.clone(),
                SessionRunConfig {
                    max_rounds: config.max_rounds,
                    round_timeout: config.round_timeout,
                    retry_policy: crate::config::RetryPolicy {
                        max_retries: config.retry_policy.max_retries,
                        base_delay: config.retry_policy.base_delay,
                    },
                    checkpoint_dir: None,
                    protocol_id: config.protocol_id,
                },
            ))
        })
        .collect();

    let mut results: Vec<Option<Result<M::Output, SessionError>>> = (0..n).map(|_| None).collect();

    for _round in 0..max_rounds {
        if results.iter().all(|r| r.is_some()) {
            break;
        }

        for i in 0..n {
            if results[i].is_some() {
                continue;
            }
            let runner = runners[i].as_mut().unwrap();
            match runner.step_encode() {
                Ok(encoded) => {
                    let my_id = all_parties[i];
                    for (recipient, bytes) in encoded {
                        match recipient {
                            Recipient::Party(to) => {
                                network.send(my_id, to, bytes);
                            }
                            Recipient::Broadcast => {
                                network.broadcast(my_id, bytes);
                            }
                        }
                    }
                }
                Err(e) => {
                    results[i] = Some(Err(e));
                }
            }
        }

        for i in 0..n {
            if results[i].is_some() {
                continue;
            }
            let runner = runners[i].as_mut().unwrap();
            if runner.is_done() {
                let r = runners[i].take().unwrap();
                results[i] = Some(r.finish());
                continue;
            }
            let my_id = all_parties[i];
            let raw = network.receive(my_id);
            if let Err(e) = runner.step_decode(&raw) {
                results[i] = Some(Err(e));
            }
        }

        for i in 0..n {
            if results[i].is_some() {
                continue;
            }
            let runner = runners[i].as_ref().unwrap();
            if runner.is_done() {
                let runner = runners[i].as_mut().unwrap();
                match runner.step_encode() {
                    Ok(encoded) => {
                        let my_id = all_parties[i];
                        for (recipient, bytes) in encoded {
                            match recipient {
                                Recipient::Party(to) => {
                                    network.send(my_id, to, bytes);
                                }
                                Recipient::Broadcast => {
                                    network.broadcast(my_id, bytes);
                                }
                            }
                        }
                        let r = runners[i].take().unwrap();
                        results[i] = Some(r.finish());
                    }
                    Err(e) => {
                        results[i] = Some(Err(e));
                    }
                }
            }
        }
    }

    for i in 0..n {
        if results[i].is_none() {
            results[i] = Some(Err(SessionError::MaxRoundsExceeded(max_rounds)));
        }
    }

    results.into_iter().map(|r| r.unwrap()).collect()
}
