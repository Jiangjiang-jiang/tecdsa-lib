use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use criterion::{measurement::WallTime, BenchmarkGroup, SamplingMode};
use tecdsa_protocol::PartyId;
use tecdsa_testkit::{CommStats, Orchestrator, PartyTiming};

static ONLINE_COMM: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

thread_local! {
    static COMM_KEY: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

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
    let orch = if collect_comm { orch.with_stats(true) } else { orch };
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
    let orch = if collect_comm { orch.with_stats(true) } else { orch };
    let result = orch.run().expect("orchestrator must succeed");
    if collect_comm {
        record_keyed_comm(&result.stats);
    }
    let timings = result.timings.clone();
    (result.outputs, timings)
}

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
    let bytes = result.stats.values().next().map(|c| c.bytes_sent).unwrap_or(0);
    ONLINE_COMM.lock().unwrap().push((comm_key.into(), bytes));
    (result.outputs, result.timings.clone())
}

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
    let bytes = result.stats.values().next().map(|c| c.bytes_sent).unwrap_or(0);
    ONLINE_COMM.lock().unwrap().push((comm_key.into(), bytes));
    (result.outputs, timings)
}

pub fn record_online_comm(comm_key: impl Into<String>, bytes_sent: usize) {
    ONLINE_COMM.lock().unwrap().push((comm_key.into(), bytes_sent));
}

pub fn write_online_comm(path: &str) {
    let rows = ONLINE_COMM.lock().unwrap();
    let mut s = String::new();
    for (k, b) in rows.iter() {
        s.push_str(&format!("{k}\t{b}\n"));
    }
    std::fs::write(path, s).expect("write online comm file");
}

pub fn party_active_time(timings: &BTreeMap<PartyId, PartyTiming>, pid: PartyId) -> Duration {
    timings
        .get(&pid)
        .map(|t| t.total_active())
        .unwrap_or_default()
}

#[must_use]
pub fn active_map(timings: BTreeMap<PartyId, PartyTiming>) -> BTreeMap<PartyId, Duration> {
    timings
        .into_iter()
        .map(|(pid, t)| (pid, t.total_active()))
        .collect()
}

#[must_use]
pub fn active_map_rounds_only(
    timings: BTreeMap<PartyId, PartyTiming>,
) -> BTreeMap<PartyId, Duration> {
    timings
        .into_iter()
        .map(|(pid, t)| (pid, t.rounds_active()))
        .collect()
}

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

pub fn configure_replay_group(group: &mut BenchmarkGroup<'_, WallTime>, samples: usize) {
    group
        .sample_size(samples)
        .sampling_mode(SamplingMode::Flat)
        .warm_up_time(Duration::from_nanos(1))
        .measurement_time(Duration::from_nanos(1));
}

fn desingularize(pool: &mut Vec<Duration>) {
    if pool.iter().all(|&d| d == pool[0]) {
        let v = pool[0];
        pool.clear();
        pool.push(v + Duration::from_nanos(1));
        pool.push(v + Duration::from_nanos(2));
    }
}

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
