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

/// Execute `run_once` enough times to gather `target_samples` pooled per-party
/// timings, returning the per-party timing map from every run.
///
/// **All real protocol work happens here.** A single execution already yields
/// one timing *per participating party*, and per-party times are near-symmetric,
/// so [`bench_party_replay`] pools all parties across all runs into one sample
/// set. We therefore run only as many executions as needed to reach
/// `target_samples` pooled timings (`ceil(target_samples / parties)`), capped at
/// `target_samples` executions — for large quorums this is a single run, which
/// is the dominant wall-clock win over the previous "one full run per sample".
///
/// `TECDSA_BENCH_RUNS` (see [`config::bench_runs_override`](crate::config::bench_runs_override))
/// forces an exact execution count, overriding the adaptive choice — set it to
/// `1` for fast smoke runs that execute each protocol/phase exactly once.
pub fn precompute_runs(
    target_samples: usize,
    mut run_once: impl FnMut() -> BTreeMap<PartyId, Duration>,
) -> Vec<BTreeMap<PartyId, Duration>> {
    if let Some(forced) = crate::config::bench_runs_override() {
        return (0..forced).map(|_| run_once()).collect();
    }
    let mut out = Vec::new();
    let first = run_once();
    let parties = first.len().max(1);
    out.push(first);
    while out.len() < target_samples && out.len() * parties < target_samples {
        out.push(run_once());
    }
    out
}

/// Like [`precompute_runs`], but for a two-phase pipeline (e.g. presign then
/// online-sign) where the second phase consumes the first phase's outputs.
///
/// `run_once` performs **both** phases in a single execution and returns their
/// per-party active-time maps as `(phase_a, phase_b)`. This lets the first phase
/// be timed once and its outputs reused by the second phase, instead of running
/// the first phase again (untimed) just to feed the second — halving the heavy
/// presign work in the sign sweeps. Returns the two pooled run-vectors (same
/// length), each replayed independently by [`bench_party_replay`].
///
/// Adaptive/`TECDSA_BENCH_RUNS` semantics match [`precompute_runs`] (sized by the
/// first phase's party count).
#[allow(clippy::type_complexity)]
pub fn precompute_runs_2(
    target_samples: usize,
    mut run_once: impl FnMut() -> (BTreeMap<PartyId, Duration>, BTreeMap<PartyId, Duration>),
) -> (
    Vec<BTreeMap<PartyId, Duration>>,
    Vec<BTreeMap<PartyId, Duration>>,
) {
    let forced = crate::config::bench_runs_override();
    let mut a = Vec::new();
    let mut b = Vec::new();
    let (fa, fb) = run_once();
    let parties = fa.len().max(1);
    a.push(fa);
    b.push(fb);
    let enough = |len: usize| match forced {
        Some(r) => len >= r,
        None => len >= target_samples || len * parties >= target_samples,
    };
    while !enough(a.len()) {
        let (na, nb) = run_once();
        a.push(na);
        b.push(nb);
    }
    (a, b)
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

/// Register a benchmark that replays pre-recorded active times from `runs`
/// (produced by [`precompute_runs`]).
///
/// Every party's active time from every run is pooled into one sample set. The
/// closure performs negligible work, but each [`Duration`] it returns to
/// Criterion is a real measured per-party active time, so Criterion computes its
/// statistics over `runs * parties` genuine measurements. A cursor walks the
/// pool (wrapping with `%`) so a small number of real executions still yields a
/// full sample set. Pooling relies on the suite's near-symmetry assumption (it
/// already reports a single representative party).
///
/// `_pid` is retained for call-site compatibility; the representative-party label
/// is encoded by the caller in `id`. Pooling no longer selects a single party.
pub fn bench_party_replay(
    group: &mut BenchmarkGroup<'_, WallTime>,
    id: impl Into<String>,
    runs: &[BTreeMap<PartyId, Duration>],
    _pid: PartyId,
) {
    let pool: Vec<Duration> = runs.iter().flat_map(|m| m.values().copied()).collect();
    let pool = if pool.is_empty() {
        vec![Duration::ZERO]
    } else {
        pool
    };
    let mut next = 0usize;
    group.bench_function(id.into(), |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += pool[next % pool.len()];
                next += 1;
            }
            total
        });
    });
}
