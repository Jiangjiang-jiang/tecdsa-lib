// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-party timing helpers for Criterion benchmarks.

use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use criterion::{measurement::WallTime, BenchmarkGroup, SamplingMode};
use tecdsa_protocol::PartyId;
use tecdsa_testkit::{CommStats, Orchestrator, PartyTiming};

/// Global collector for per-party online communication (bytes), keyed by a
/// `<proto>/n{n}_t{t}` string. Populated by [`run_online_comm`] /
/// [`record_online_comm`] and flushed by [`write_online_comm`]. Used by the
/// one-shot `protocol_once` binary (single-threaded), so a plain `Mutex<Vec>`
/// suffices.
static ONLINE_COMM: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

thread_local! {
    /// When set (by `protocol_once`'s `time_once` around a presign/offline-sign
    /// phase), the timed-run helpers [`run_timed_with_init`] /
    /// [`run_timed_without_init`] additionally collect communication stats and
    /// record the representative party's `bytes_sent` under this key. It is never
    /// set by the criterion benches, so their timed runs are unaffected (no
    /// serialization overhead, no recording).
    static COMM_KEY: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Set (or clear with `None`) the per-phase comm key used by the timed-run
/// helpers. Used by `protocol_once` to attribute offline (presign) communication.
pub fn set_comm_key(key: Option<String>) {
    COMM_KEY.with(|k| *k.borrow_mut() = key);
}

fn comm_key_is_set() -> bool {
    COMM_KEY.with(|k| k.borrow().is_some())
}

fn record_keyed_comm(stats: &BTreeMap<PartyId, CommStats>) {
    COMM_KEY.with(|k| {
        if let Some(key) = k.borrow().as_ref() {
            let bytes = stats.values().next().map(|c| c.bytes_sent).unwrap_or(0);
            ONLINE_COMM.lock().unwrap().push((key.clone(), bytes));
        }
    });
}

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

    let collect_comm = comm_key_is_set();
    let orch = Orchestrator::new(machines, max_rounds).with_timing(true);
    let orch = if collect_comm {
        orch.with_stats(true)
    } else {
        orch
    };
    let result = orch.run().expect("orchestrator must succeed");
    if collect_comm {
        record_keyed_comm(&result.stats);
    }

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
    let collect_comm = comm_key_is_set();
    let orch = Orchestrator::new(machines, max_rounds).with_timing(true);
    let orch = if collect_comm {
        orch.with_stats(true)
    } else {
        orch
    };
    let result = orch.run().expect("orchestrator must succeed");
    if collect_comm {
        record_keyed_comm(&result.stats);
    }
    let timings = result.timings.clone();
    (result.outputs, timings)
}

/// Like [`run_timed_without_init`] but also enables communication stats and
/// records the representative (party-1) `bytes_sent` under `comm_key` for later
/// [`write_online_comm`]. Returns `(outputs, timings)` so callers are unchanged.
///
/// Enabling stats does NOT perturb the per-party active timing: message
/// serialization happens in the orchestrator's routing loop, outside the
/// `drain_outgoing`/`handle`/`finish` timing brackets (only wall-clock grows).
/// `bytes_sent` follows the orchestrator convention (a broadcast counts the
/// payload once per recipient), i.e. one signer's total online egress.
pub fn run_online_comm<M>(
    comm_key: impl Into<String>,
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
        .with_stats(true)
        .run()
        .expect("orchestrator must succeed");
    let bytes = result
        .stats
        .values()
        .next()
        .map(|c| c.bytes_sent)
        .unwrap_or(0);
    ONLINE_COMM.lock().unwrap().push((comm_key.into(), bytes));
    (result.outputs, result.timings.clone())
}

/// Builder-based counterpart of [`run_online_comm`] (mirrors
/// [`run_timed_with_init`]): constructs machines from `builders` (timing init),
/// runs them with communication stats, and records party-1 `bytes_sent` under
/// `comm_key`. Returns `(outputs, timings)`.
pub fn run_online_comm_with_init<M, F>(
    comm_key: impl Into<String>,
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
        .with_stats(true)
        .run()
        .expect("orchestrator must succeed");
    let mut timings = result.timings.clone();
    for (pid, init_dur) in init_timings {
        timings.entry(pid).or_default().init = init_dur;
    }
    let bytes = result
        .stats
        .values()
        .next()
        .map(|c| c.bytes_sent)
        .unwrap_or(0);
    ONLINE_COMM.lock().unwrap().push((comm_key.into(), bytes));
    (result.outputs, timings)
}

/// Record an externally-computed per-party online communication figure (bytes),
/// for protocols whose online phase sends no orchestrator-routed messages (e.g.
/// CGGMP20, where each signer broadcasts one partial-signature scalar).
pub fn record_online_comm(comm_key: impl Into<String>, bytes_sent: usize) {
    ONLINE_COMM
        .lock()
        .unwrap()
        .push((comm_key.into(), bytes_sent));
}

/// Flush all recorded online-communication rows to `path` as `<key>\t<bytes>`
/// TSV (one line per measurement).
pub fn write_online_comm(path: &str) {
    let rows = ONLINE_COMM.lock().unwrap();
    let mut s = String::new();
    for (k, b) in rows.iter() {
        s.push_str(&format!("{k}\t{b}\n"));
    }
    std::fs::write(path, s).expect("write online comm file");
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

/// Like [`active_map`], but per-party ROUNDS-ONLY active time
/// ([`PartyTiming::rounds_active`]): drain + handle + finish, EXCLUDING machine
/// construction (`init`). Use to measure interactive round cost when the
/// constructor is accounted for separately (e.g. CGGMP20 aux-info vs setup).
#[must_use]
pub fn active_map_rounds_only(
    timings: BTreeMap<PartyId, PartyTiming>,
) -> BTreeMap<PartyId, Duration> {
    timings
        .into_iter()
        .map(|(pid, t)| (pid, t.rounds_active()))
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

/// Break the degeneracy of a zero-variance sample pool so Criterion can analyze
/// it without panicking.
///
/// Criterion's bootstrap analysis divides by the sample standard deviation; a
/// constant pool (std-dev = 0) yields `NaN` and trips an internal assertion
/// (`slice.len() > 1 && !is_nan`). A constant pool arises when a party does no
/// work in a phase (e.g. ABC24's client has no offline round, so its `presign`
/// series is all-zero) or under a single-execution smoke run
/// (`TECDSA_BENCH_RUNS=1`).
///
/// When every entry is identical (value `v`), we replace the pool with the two
/// distinct values `v+1ns` and `v+2ns`. Replayed across Criterion's samples this
/// gives a non-zero variance (avoiding the NaN) while keeping every sample
/// strictly positive — Criterion separately errors on any iteration that
/// measures exactly zero time, which is what a no-work party (`v = 0`) would
/// otherwise produce. The ~1.5ns mean shift is far below the millisecond-scale
/// display resolution, so the reported figure is unchanged in practice. Pools
/// that already have any spread are left untouched.
fn desingularize(pool: &mut Vec<Duration>) {
    if pool.iter().all(|&d| d == pool[0]) {
        let v = pool[0];
        pool.clear();
        pool.push(v + Duration::from_nanos(1));
        pool.push(v + Duration::from_nanos(2));
    }
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
    let mut pool: Vec<Duration> = runs.iter().flat_map(|m| m.values().copied()).collect();
    if pool.is_empty() {
        pool.push(Duration::ZERO);
    }
    desingularize(&mut pool);
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

/// Replay a SINGLE party's pre-recorded active times, with NO cross-party
/// pooling. Use for asymmetric protocols (e.g. two-party, where party1 and
/// party2 perform different work) so each party is reported on its own.
///
/// Unlike [`bench_party_replay`] (which pools all parties into one
/// representative "average per-party" sample set), this pools only the
/// durations recorded for `pid`. An empty series (e.g. a party that does no
/// work in this phase) replays as zero.
pub fn bench_party_replay_single(
    group: &mut BenchmarkGroup<'_, WallTime>,
    id: impl Into<String>,
    runs: &[BTreeMap<PartyId, Duration>],
    pid: PartyId,
) {
    let mut pool: Vec<Duration> = runs.iter().filter_map(|m| m.get(&pid).copied()).collect();
    if pool.is_empty() {
        pool.push(Duration::ZERO);
    }
    desingularize(&mut pool);
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
