// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-party timing helpers for Criterion benchmarks.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use criterion::{measurement::WallTime, BenchmarkGroup, SamplingMode};
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

/// Collapse a per-party [`PartyTiming`] map into per-party total active time.
#[must_use]
pub fn active_map(timings: BTreeMap<PartyId, PartyTiming>) -> BTreeMap<PartyId, Duration> {
    timings
        .into_iter()
        .map(|(pid, t)| (pid, t.total_active()))
        .collect()
}

/// Run one protocol from builder closures (timing init) and return each
/// party's total active time. See [`run_timed_with_init`].
pub fn active_with_init<M, F>(
    builders: Vec<(PartyId, F)>,
    max_rounds: u16,
) -> BTreeMap<PartyId, Duration>
where
    M: tecdsa_protocol::StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
    F: FnOnce() -> M,
{
    active_map(run_timed_with_init(builders, max_rounds).1)
}

/// Run one protocol from pre-constructed machines (init NOT timed) and return
/// each party's total active time. See [`run_timed_without_init`].
pub fn active_without_init<M>(
    machines: Vec<(PartyId, M)>,
    max_rounds: u16,
) -> BTreeMap<PartyId, Duration>
where
    M: tecdsa_protocol::StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    active_map(run_timed_without_init(machines, max_rounds).1)
}

/// Execute `run_once` `samples + 1` times, returning the per-party timing map
/// from every run.
///
/// **All real protocol work happens here, once.** The extra `+ 1` run absorbs
/// the warm-up invocation Criterion performs before measurement, so that every
/// measured sample maps to a distinct pre-recorded run (see
/// [`bench_party_replay`]).
pub fn precompute_runs(
    samples: usize,
    mut run_once: impl FnMut() -> BTreeMap<PartyId, Duration>,
) -> Vec<BTreeMap<PartyId, Duration>> {
    (0..samples + 1).map(|_| run_once()).collect()
}

/// Configure a Criterion group so each per-party benchmark bottoms out at one
/// iteration per sample with no warm-up/measurement spin.
///
/// This is required by the replay pattern: the protocol is executed up front
/// (see [`precompute_runs`]) and the per-party benchmarks merely replay the
/// recorded timings, so Criterion must not attempt to amortise/scale them.
pub fn configure_replay_group(group: &mut BenchmarkGroup<'_, WallTime>, samples: usize) {
    group
        .sample_size(samples)
        .sampling_mode(SamplingMode::Flat)
        .warm_up_time(Duration::from_nanos(1))
        .measurement_time(Duration::from_nanos(1));
}

/// Register a per-party benchmark that replays a party's pre-recorded active
/// times from `runs` (produced by [`precompute_runs`]).
///
/// The closure performs negligible work, but the [`Duration`] it returns to
/// Criterion is the real measured per-party active time, so Criterion computes
/// its statistics over genuine measurements. A cursor walks `runs` (wrapping
/// with `%`) so each sample maps to a distinct execution and the same physical
/// run is shared across every party's benchmark.
pub fn bench_party_replay(
    group: &mut BenchmarkGroup<'_, WallTime>,
    id: impl Into<String>,
    runs: &[BTreeMap<PartyId, Duration>],
    pid: PartyId,
) {
    let mut next = 0usize;
    group.bench_function(id.into(), |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += runs[next % runs.len()]
                    .get(&pid)
                    .copied()
                    .unwrap_or_default();
                next += 1;
            }
            total
        });
    });
}
