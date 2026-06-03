// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic multi-party orchestrator for protocol state machines.
//!
//! The [`Orchestrator`] drives a set of [`StateMachine`] instances through
//! rounds without any network layer — messages are delivered by directly
//! calling [`StateMachine::handle`] on each recipient machine.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use tecdsa_protocol::{Outgoing, PartyId, Recipient, StateMachine};

/// Per-party communication statistics collected during a protocol run.
#[derive(Debug, Clone, Default)]
pub struct CommStats {
    /// Total bytes sent (serialized message payload via bincode).
    pub bytes_sent: usize,
    /// Total number of messages sent.
    pub messages_sent: usize,
    /// Total bytes received.
    pub bytes_received: usize,
    /// Total number of messages received.
    pub messages_received: usize,
    /// Bytes sent per round (round index -> bytes).
    pub bytes_per_round: BTreeMap<u16, usize>,
}

/// Per-party timing measurements collected during a protocol run.
#[derive(Debug, Clone, Default)]
pub struct PartyTiming {
    /// Time spent constructing the machine (set externally via helper).
    pub init: Duration,
    /// Time spent in [`StateMachine::drain_outgoing`].
    pub drain_outgoing: Duration,
    /// Time spent in [`StateMachine::handle`].
    pub handle: Duration,
    /// Time spent in [`StateMachine::finish`].
    pub finish: Duration,
}

impl PartyTiming {
    /// Total active computation time (init + drain + handle + finish).
    #[must_use]
    pub fn total_active(&self) -> Duration {
        self.init + self.drain_outgoing + self.handle + self.finish
    }
}

/// Drives a set of [`StateMachine`]s through rounds deterministically.
///
/// All message routing is synchronous and in-process.  Use this for unit
/// tests and KAT runners where determinism and simplicity matter.
///
/// After [`run`](Orchestrator::run), call [`comm_stats`](Orchestrator::comm_stats)
/// to retrieve per-party communication measurements.
pub struct Orchestrator<M>
where
    M: StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    /// The party-ID / state-machine pairs managed by this orchestrator.
    pub machines: Vec<(PartyId, M)>,
    max_rounds: u16,
    /// Per-party communication statistics.
    stats: BTreeMap<PartyId, CommStats>,
    /// When `false` (the default), skip the `bincode::encode_to_vec` call
    /// that serializes every message just to count bytes. Set to `true`
    /// via [`with_stats`](Orchestrator::with_stats) when communication
    /// measurements are needed.
    collect_stats: bool,
    /// Per-party timing measurements.
    timings: BTreeMap<PartyId, PartyTiming>,
    /// When `true`, instrument `drain_outgoing`, `handle`, and `finish`
    /// calls with [`Instant`] timers.
    collect_timing: bool,
}

impl<M> Orchestrator<M>
where
    M: StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    /// Create a new orchestrator wrapping `machines`, stopping after at most
    /// `max_rounds` rounds even if some machines have not finished.
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

    /// Enable or disable per-message serialization for communication stats.
    ///
    /// When `collect` is `true`, every outgoing message is serialized via
    /// `bincode::encode_to_vec` to measure its byte size. When `false`
    /// (the default), the serialization is skipped and all byte counts
    /// remain zero.
    #[must_use]
    pub fn with_stats(mut self, collect: bool) -> Self {
        self.collect_stats = collect;
        self
    }

    /// Enable or disable per-party timing instrumentation.
    ///
    /// When `collect` is `true`, every `drain_outgoing`, `handle`, and
    /// `finish` call is bracketed with [`Instant::now`] / [`Instant::elapsed`]
    /// and the durations are accumulated per party.
    #[must_use]
    pub fn with_timing(mut self, collect: bool) -> Self {
        self.collect_timing = collect;
        self
    }

    /// Run all machines to completion (or until `max_rounds` is exhausted).
    ///
    /// Returns an [`OrchestratorResult`] containing both protocol outputs
    /// and per-party communication statistics.  The result dereferences to
    /// `Vec<Result<Output>>` for backward compatibility.
    pub fn run(mut self) -> tecdsa_core::Result<OrchestratorResult<M::Output>> {
        let bincode_config = bincode::config::standard()
            .with_big_endian()
            .with_fixed_int_encoding();

        for round in 0..self.max_rounds {
            let all_done = self.machines.iter().all(|(_, m)| m.is_done());
            if all_done {
                break;
            }

            // Collect all outgoing messages from every machine in this round.
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

            // Route each message to its intended recipient(s).
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
                        if let Some((_, machine)) = self.machines.iter_mut().find(|(p, _)| *p == to)
                        {
                            let t0 = if self.collect_timing {
                                Some(Instant::now())
                            } else {
                                None
                            };
                            machine.handle(*from, outgoing.msg.clone().into())?;
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
                                let t0 = if self.collect_timing {
                                    Some(Instant::now())
                                } else {
                                    None
                                };
                                machine.handle(*from, outgoing.msg.clone().into())?;
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

    /// Returns the per-party communication statistics (only meaningful after `run`).
    #[must_use]
    pub fn comm_stats(&self) -> &BTreeMap<PartyId, CommStats> {
        &self.stats
    }
}

/// Result of an orchestrator run, containing both protocol outputs and
/// communication statistics.
pub struct OrchestratorResult<O> {
    /// Protocol outputs, one per party.
    pub outputs: Vec<tecdsa_core::Result<O>>,
    /// Per-party communication statistics.
    pub stats: BTreeMap<PartyId, CommStats>,
    /// Per-party timing measurements.
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
    /// Per-party communication statistics.
    #[must_use]
    pub fn comm_stats(&self) -> &BTreeMap<PartyId, CommStats> {
        &self.stats
    }

    /// Total bytes sent across all parties.
    #[must_use]
    pub fn total_bytes_sent(&self) -> usize {
        self.stats.values().map(|s| s.bytes_sent).sum()
    }

    /// Average bytes sent per party.
    #[must_use]
    pub fn avg_bytes_per_party(&self) -> usize {
        let n = self.stats.len();
        if n == 0 {
            return 0;
        }
        self.total_bytes_sent() / n
    }

    /// Per-party timing for the given party, if timing was collected.
    #[must_use]
    pub fn party_timing(&self, pid: PartyId) -> Option<&PartyTiming> {
        self.timings.get(&pid)
    }
}
