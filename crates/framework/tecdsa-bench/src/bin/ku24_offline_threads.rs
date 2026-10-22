// SPDX-License-Identifier: MIT OR Apache-2.0
//! Thread-count sweep for KU24 batch presigning.
//!
//! Matches the honest-majority configurations `scripts/build_hm_table.py`
//! reports -- (n, t) = (3,2), (5,3), (7,4), (11,6) -- at a fixed batch size m,
//! and measures the same quantity as the multiparty bench's
//! `presign/ku24/n{n}_t{t}_m{m}/party1` series: the mean per-party *active*
//! time (machine construction + every `drain_outgoing` / `handle` / `finish`),
//! divided by m, i.e. per presignature. Construction is included because that
//! is where all of the `F_rss` derivation happens.
//!
//! The one-time, key-independent PRSS setup runs untimed, once per
//! configuration. Each timed cell then runs inside a dedicated rayon pool, so
//! one process sweeps the whole grid. Every rep uses a fresh session id, as a
//! real deployment must.
//!
//!   cargo run --profile bench -p tecdsa-bench --features parallel \
//!       --bin ku24_offline_threads -- [m] [reps]
//!
//! Use `--profile bench`, not `--release`. The workspace's release profile
//! keeps `overflow-checks = true` while the bench profile turns them off, and
//! the checked build is ~5-15% slower here, so a `--release` run is not
//! comparable with the criterion numbers the tables are built from. The
//! speedup ratios are unaffected, since every row shares one build.

use std::time::Duration;

use tecdsa_bench::per_party;
use tecdsa_ku24::{presign::Ku24PresignMachine, prss::PrssKeys, setup::Ku24SetupMachine};
use tecdsa_protocol::PartyId;
use tecdsa_testkit::Orchestrator;

type C = k256::Secp256k1;

const CONFIGS: [(u16, u16); 4] = [(3, 2), (5, 3), (7, 4), (11, 6)];
const THREAD_COUNTS: [usize; 7] = [1, 2, 4, 8, 12, 16, 24];

fn setup(n: u16, t: u16) -> Vec<PrssKeys<C>> {
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    let machines: Vec<_> = parties
        .iter()
        .map(|&pid| {
            (
                pid,
                Ku24SetupMachine::<C>::new(pid, parties.clone(), t).expect("ku24 setup"),
            )
        })
        .collect();
    Orchestrator::new(machines, 4)
        .run()
        .expect("setup orchestration")
        .into_iter()
        .map(|r| r.expect("setup output"))
        .collect()
}

/// Mean per-party active time of one batch, divided by the batch size.
fn per_presignature(n: u16, prss: &[PrssKeys<C>], m: usize, session: [u8; 32]) -> Duration {
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    let builders: Vec<_> = parties
        .iter()
        .zip(prss)
        .map(|(&pid, keys)| {
            let parties = parties.clone();
            (pid, move || {
                Ku24PresignMachine::new_with_session(pid, parties, keys, m, &session)
                    .expect("ku24 presign")
            })
        })
        .collect();
    let per_party = per_party::active_with_init(builders, 8);
    let mean = per_party.values().sum::<Duration>() / u32::from(n);
    mean / u32::try_from(m).expect("batch size fits in u32")
}

fn main() {
    let mut args = std::env::args().skip(1);
    let m: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(128);
    let reps: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);

    let prss: Vec<Vec<PrssKeys<C>>> = CONFIGS.iter().map(|&(n, t)| setup(n, t)).collect();

    println!(
        "KU24 batch presigning, per-party active time per presignature, m={m}, mean of {reps}"
    );
    print!("{:>8}", "threads");
    for (n, t) in CONFIGS {
        print!("{:>12}", format!("({n},{t})"));
    }
    println!();

    let mut session_ctr = 0u64;
    let mut baseline = [0f64; CONFIGS.len()];
    for (row, threads) in THREAD_COUNTS.into_iter().enumerate() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("thread pool");
        print!("{threads:>8}");
        let mut speedups = Vec::new();
        for (col, &(n, _)) in CONFIGS.iter().enumerate() {
            let ms = pool.install(|| {
                let total: Duration = (0..reps)
                    .map(|_| {
                        session_ctr += 1;
                        let mut session = [0u8; 32];
                        session[..8].copy_from_slice(&session_ctr.to_be_bytes());
                        per_presignature(n, &prss[col], m, session)
                    })
                    .sum();
                total.as_secs_f64() * 1e3 / reps as f64
            });
            if row == 0 {
                baseline[col] = ms;
            }
            speedups.push(baseline[col] / ms);
            print!("{ms:>12.4}");
        }
        print!("   |");
        for s in speedups {
            print!("{s:>7.2}x");
        }
        println!();
    }
    println!("(ms per presignature; the right-hand block is speedup vs the 1-thread row)");
}
