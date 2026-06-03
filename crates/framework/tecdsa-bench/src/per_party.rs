// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-party timing helpers for Criterion benchmarks.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use tecdsa_protocol::PartyId;
use tecdsa_testkit::{Orchestrator, PartyTiming};

/// Run a protocol from builder closures, timing machine construction (init)
/// as well as protocol rounds (drain/handle/finish).
///
/// Each builder is called once to construct a machine; its execution time is
/// recorded as `PartyTiming::init`.
pub fn run_timed_with_init<M, F>(
    builders: Vec<(PartyId, F)>,
    max_rounds: u16,
) -> (
    Vec<tecdsa_core::Result<M::Output>>,
    BTreeMap<PartyId, PartyTiming>,
)
where
    M: tecdsa_protocol::StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
    F: FnOnce() -> M,
{
    let mut init_timings: BTreeMap<PartyId, Duration> = BTreeMap::new();
    let machines: Vec<(PartyId, M)> = builders
        .into_iter()
        .map(|(pid, builder)| {
            let t0 = Instant::now();
            let machine = builder();
            init_timings.insert(pid, t0.elapsed());
            (pid, machine)
        })
        .collect();

    let result = Orchestrator::new(machines, max_rounds)
        .with_timing(true)
        .run()
        .expect("orchestrator must succeed");

    let mut timings = result.timings.clone();
    for (pid, init_dur) in init_timings {
        timings.entry(pid).or_default().init = init_dur;
    }

    (result.outputs, timings)
}

/// Run a protocol with pre-constructed machines (init time NOT measured).
///
/// **Not for main-table benchmarks** — use [`run_timed_with_init`] instead.
/// This variant is for supplementary/test scenarios where machine construction
/// cost is intentionally excluded (e.g., measuring only protocol round overhead).
pub fn run_timed_without_init<M>(
    machines: Vec<(PartyId, M)>,
    max_rounds: u16,
) -> (
    Vec<tecdsa_core::Result<M::Output>>,
    BTreeMap<PartyId, PartyTiming>,
)
where
    M: tecdsa_protocol::StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    let result = Orchestrator::new(machines, max_rounds)
        .with_timing(true)
        .run()
        .expect("orchestrator must succeed");
    let timings = result.timings.clone();
    (result.outputs, timings)
}

/// Extract the total active compute time for a specific party.
pub fn party_active_time(timings: &BTreeMap<PartyId, PartyTiming>, pid: PartyId) -> Duration {
    timings
        .get(&pid)
        .map(|t| t.total_active())
        .unwrap_or_default()
}
