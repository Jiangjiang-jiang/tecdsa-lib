use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use tecdsa_protocol::{Outgoing, PartyId, Recipient, StateMachine};

#[derive(Debug, Clone, Default)]
pub struct CommStats {
    pub bytes_sent: usize,
    pub messages_sent: usize,
    pub bytes_received: usize,
    pub messages_received: usize,
    pub bytes_per_round: BTreeMap<u16, usize>,
}

#[derive(Debug, Clone, Default)]
pub struct PartyTiming {
    pub init: Duration,
    pub drain_outgoing: Duration,
    pub handle: Duration,
    pub finish: Duration,
}

impl PartyTiming {
    #[must_use]
    pub fn total_active(&self) -> Duration {
        self.init + self.drain_outgoing + self.handle + self.finish
    }

    #[must_use]
    pub fn rounds_active(&self) -> Duration {
        self.drain_outgoing + self.handle + self.finish
    }
}

#[must_use]
pub fn wire_size<T: serde::Serialize>(value: &T) -> usize {
    let cfg = bincode::config::standard()
        .with_big_endian()
        .with_fixed_int_encoding();
    bincode::serde::encode_to_vec(value, cfg)
        .map(|v| v.len())
        .unwrap_or(0)
}

pub struct Orchestrator<M>
where
    M: StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    pub machines: Vec<(PartyId, M)>,
    max_rounds: u16,
    stats: BTreeMap<PartyId, CommStats>,
    collect_stats: bool,
    timings: BTreeMap<PartyId, PartyTiming>,
    collect_timing: bool,
}

impl<M> Orchestrator<M>
where
    M: StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    #[must_use]
    pub fn new(machines: Vec<(PartyId, M)>, max_rounds: u16) -> Self {
        let stats = machines
            .iter()
            .map(|(pid, _)| (*pid, CommStats::default()))
            .collect();
        Self {
            machines,
            max_rounds,
            stats,
            collect_stats: false,
            timings: BTreeMap::new(),
            collect_timing: false,
        }
    }

    #[must_use]
    pub fn with_stats(mut self, collect: bool) -> Self {
        self.collect_stats = collect;
        self
    }

    #[must_use]
    pub fn with_timing(mut self, collect: bool) -> Self {
        self.collect_timing = collect;
        self
    }

    pub fn run(mut self) -> tecdsa_core::Result<OrchestratorResult<M::Output>> {
        let bincode_config = bincode::config::standard()
            .with_big_endian()
            .with_fixed_int_encoding();

        let machine_index: Vec<usize> = {
            let max_id = self
                .machines
                .iter()
                .map(|(pid, _)| pid.0 as usize)
                .max()
                .unwrap_or(0);
            let mut idx = vec![usize::MAX; max_id + 1];
            for (i, (pid, _)) in self.machines.iter().enumerate() {
                idx[pid.0 as usize] = i;
            }
            idx
        };

        for round in 0..self.max_rounds {
            let all_done = self.machines.iter().all(|(_, m)| m.is_done());
            if all_done {
                break;
            }

            let mut pending: Vec<(PartyId, Outgoing<M::Outbound>)> = Vec::new();
            for (pid, machine) in &mut self.machines {
                let t0 = if self.collect_timing {
                    Some(Instant::now())
                } else {
                    None
                };
                let msgs: Vec<_> = machine.drain_outgoing();
                if let Some(t0) = t0 {
                    self.timings.entry(*pid).or_default().drain_outgoing += t0.elapsed();
                }
                for msg in msgs {
                    pending.push((*pid, msg));
                }
            }

            for (from, outgoing) in &pending {
                let msg_bytes = if self.collect_stats {
                    bincode::serde::encode_to_vec(&outgoing.msg, bincode_config)
                        .map(|v| v.len())
                        .map_err(|e| {
                            tecdsa_core::TecdsaError::Serialization(format!("stats encode: {e}"))
                        })?
                } else {
                    0
                };

                match outgoing.to {
                    Recipient::Party(to) => {
                        if self.collect_stats {
                            if let Some(s) = self.stats.get_mut(from) {
                                s.bytes_sent += msg_bytes;
                                s.messages_sent += 1;
                                *s.bytes_per_round.entry(round).or_default() += msg_bytes;
                            }
                            if let Some(s) = self.stats.get_mut(&to) {
                                s.bytes_received += msg_bytes;
                                s.messages_received += 1;
                            }
                        }
                        let idx = machine_index
                            .get(to.0 as usize)
                            .copied()
                            .unwrap_or(usize::MAX);
                        if let Some((_, machine)) = self.machines.get_mut(idx) {
                            let inbound: M::Inbound = outgoing.msg.clone().into();
                            let t0 = if self.collect_timing {
                                Some(Instant::now())
                            } else {
                                None
                            };
                            machine.handle(*from, inbound)?;
                            if let Some(t0) = t0 {
                                self.timings.entry(to).or_default().handle += t0.elapsed();
                            }
                        }
                    }
                    Recipient::Broadcast => {
                        let n_recipients = self.machines.len() - 1;
                        if self.collect_stats {
                            if let Some(s) = self.stats.get_mut(from) {
                                s.bytes_sent += msg_bytes * n_recipients;
                                s.messages_sent += n_recipients;
                                *s.bytes_per_round.entry(round).or_default() +=
                                    msg_bytes * n_recipients;
                            }
                        }
                        for (pid, machine) in &mut self.machines {
                            if pid != from {
                                if self.collect_stats {
                                    if let Some(s) = self.stats.get_mut(pid) {
                                        s.bytes_received += msg_bytes;
                                        s.messages_received += 1;
                                    }
                                }
                                let inbound: M::Inbound = outgoing.msg.clone().into();
                                let t0 = if self.collect_timing {
                                    Some(Instant::now())
                                } else {
                                    None
                                };
                                machine.handle(*from, inbound)?;
                                if let Some(t0) = t0 {
                                    self.timings.entry(*pid).or_default().handle += t0.elapsed();
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut timings = std::mem::take(&mut self.timings);
        let collect_timing = self.collect_timing;
        let outputs = self
            .machines
            .into_iter()
            .map(|(pid, m)| {
                let t0 = if collect_timing {
                    Some(Instant::now())
                } else {
                    None
                };
                let result = m.finish();
                if let Some(t0) = t0 {
                    timings.entry(pid).or_default().finish += t0.elapsed();
                }
                result
            })
            .collect();
        Ok(OrchestratorResult {
            outputs,
            stats: self.stats,
            timings,
        })
    }

    #[must_use]
    pub fn comm_stats(&self) -> &BTreeMap<PartyId, CommStats> {
        &self.stats
    }
}

pub struct OrchestratorResult<O> {
    pub outputs: Vec<tecdsa_core::Result<O>>,
    pub stats: BTreeMap<PartyId, CommStats>,
    pub timings: BTreeMap<PartyId, PartyTiming>,
}

impl<O> std::ops::Deref for OrchestratorResult<O> {
    type Target = Vec<tecdsa_core::Result<O>>;
    fn deref(&self) -> &Self::Target {
        &self.outputs
    }
}

impl<O> IntoIterator for OrchestratorResult<O> {
    type Item = tecdsa_core::Result<O>;
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.outputs.into_iter()
    }
}

impl<O> OrchestratorResult<O> {
    #[must_use]
    pub fn comm_stats(&self) -> &BTreeMap<PartyId, CommStats> {
        &self.stats
    }

    #[must_use]
    pub fn total_bytes_sent(&self) -> usize {
        self.stats.values().map(|s| s.bytes_sent).sum()
    }

    #[must_use]
    pub fn avg_bytes_per_party(&self) -> usize {
        let n = self.stats.len();
        if n == 0 {
            return 0;
        }
        self.total_bytes_sent() / n
    }

    #[must_use]
    pub fn party_timing(&self, pid: PartyId) -> Option<&PartyTiming> {
        self.timings.get(&pid)
    }
}
