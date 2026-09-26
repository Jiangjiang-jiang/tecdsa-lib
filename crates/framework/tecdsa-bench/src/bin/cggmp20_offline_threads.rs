// SPDX-License-Identifier: MIT OR Apache-2.0
//! Thread-count sweep for CGGMP20 offline signing (presigning).
//!
//! Matches the configuration `scripts/build_sign_table.py` reports in the
//! Offline column: `presign/cggmp20/n20_t{t}/party1` for t in {2,3,7,11,20},
//! i.e. the mean per-party *active* time (init + rounds + finish) at n = 20.
//!
//! The one-time setup (key shares, Paillier keys, Ring-Pedersen parameters) is
//! built directly rather than by running DKG and aux-info, since presigning is
//! indifferent to how that material was produced. Each timed configuration then
//! runs inside a dedicated rayon pool, so one process can sweep the whole grid.
//!
//!   cargo run --release -p tecdsa-bench --features parallel \
//!       --bin cggmp20_offline_threads -- [n] [reps]

use std::time::{Duration, Instant};

use tecdsa_cggmp20::{
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    presign::Cggmp20PresignMachine,
    security_level::{Cggmp20SecurityParams, SecurityLevel128},
    trusted_dealer,
};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::DecryptionKey;
use tecdsa_pedersen_mod::PedersenModParams;
use tecdsa_protocol::{PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine};

type C = k256::Secp256k1;

const T_VALUES: [u16; 5] = [2, 3, 7, 11, 20];
const THREAD_COUNTS: [usize; 7] = [1, 2, 4, 8, 12, 16, 24];

fn make_signer_configs(signers: &[u16], n: u16, t: u16) -> Vec<SessionConfig> {
    let session_id = SessionId([1u8; 32]);
    let parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
    signers
        .iter()
        .map(|&i| SessionConfig {
            session_id: session_id.clone(),
            local_party: PartyInfo {
                id: PartyId(i),
                index: i,
                total: n,
                threshold: t,
            },
            parties: parties.clone(),
        })
        .collect()
}

/// Mean per-party active time of one presigning run: machine construction plus
/// every `drain_outgoing` / `handle` / `finish` call, matching what
/// `per_party::bench_party_replay` pools for the `presign/...` series.
fn presign_active_time(
    signers: &[u16],
    n: u16,
    t: u16,
    core_shares: &[Cggmp20CoreKeyShare<C>],
    aux_infos: &[AuxInfo],
) -> Duration {
    let configs = make_signer_configs(signers, n, t);
    let mut active = vec![Duration::ZERO; signers.len()];

    let mut machines: Vec<(PartyId, Cggmp20PresignMachine<C>)> = signers
        .iter()
        .enumerate()
        .map(|(idx, &s)| {
            let p0 = (s - 1) as usize;
            let mut rng = tecdsa_core::Csprng::new();
            let t0 = Instant::now();
            let m = Cggmp20PresignMachine::<C>::with_security::<SecurityLevel128>(
                &configs[idx],
                &core_shares[p0],
                &aux_infos[p0],
                signers,
                &mut rng,
            );
            active[idx] += t0.elapsed();
            (PartyId(s), m)
        })
        .collect();

    for _round in 0..10 {
        if machines.iter().all(|(_, m)| m.is_done()) {
            break;
        }
        let mut pending = Vec::new();
        for (i, (pid, machine)) in machines.iter_mut().enumerate() {
            let t0 = Instant::now();
            let msgs: Vec<_> = machine.drain_outgoing();
            active[i] += t0.elapsed();
            for msg in msgs {
                pending.push((*pid, msg));
            }
        }
        for (from, outgoing) in pending {
            match outgoing.to {
                Recipient::Party(to) => {
                    if let Some((i, (_, machine))) =
                        machines.iter_mut().enumerate().find(|(_, (p, _))| *p == to)
                    {
                        let inbound = outgoing.msg;
                        let t0 = Instant::now();
                        machine.handle(from, inbound).expect("handle");
                        active[i] += t0.elapsed();
                    }
                }
                Recipient::Broadcast => {
                    for (i, (pid, machine)) in machines.iter_mut().enumerate() {
                        if *pid != from {
                            let inbound = outgoing.msg.clone();
                            let t0 = Instant::now();
                            machine.handle(from, inbound).expect("handle");
                            active[i] += t0.elapsed();
                        }
                    }
                }
            }
        }
    }

    for (i, (_, m)) in machines.into_iter().enumerate() {
        let t0 = Instant::now();
        m.finish().expect("presign must succeed");
        active[i] += t0.elapsed();
    }

    active.iter().sum::<Duration>() / u32::try_from(active.len()).expect("signer count fits u32")
}

fn main() {
    let mut args = std::env::args().skip(1);
    let n: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(20);
    let reps: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);

    // ---- one-time setup ----
    let t0 = Instant::now();
    let mut rng = tecdsa_core::Csprng::new();
    let secret = C::random_scalar(&mut rng);
    // One t-of-n share set per threshold, as `shares_by_t` does in the bench.
    let shares_by_t: Vec<(u16, Vec<Cggmp20CoreKeyShare<C>>)> = T_VALUES
        .iter()
        .map(|&t| (t, trusted_dealer::deal::<C>(&secret, t, n, &mut rng)))
        .collect();

    let bits = SecurityLevel128::RSA_PRIME_BITS;
    let keys: Vec<(DecryptionKey, PedersenModParams)> =
        tecdsa_bigint::par::map_indexed(n as usize, |_| {
            let mut rng = tecdsa_core::Csprng::new();
            let (p, q) = tecdsa_bigint::par::gen_two_primes(&mut rng, bits);
            let dk = DecryptionKey::from_primes(p, q).expect("valid paillier key");
            let (params, _) = PedersenModParams::generate(u64::from(bits), &mut rng);
            (dk, params)
        });
    let paillier_eks: Vec<_> = keys
        .iter()
        .map(|(dk, _)| dk.encryption_key().clone())
        .collect();
    let pedersen_params: Vec<_> = keys.iter().map(|(_, p)| p.clone()).collect();
    let aux_infos: Vec<AuxInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, (dk, _))| AuxInfo {
            party_index: u16::try_from(i).expect("party index fits u16"),
            dk: dk.clone(),
            paillier_eks: paillier_eks.clone(),
            pedersen_params: pedersen_params.clone(),
        })
        .collect();
    eprintln!(
        "setup for n={n} done in {:.1} s",
        t0.elapsed().as_secs_f64()
    );

    // ---- sweep ----
    println!("CGGMP20 offline signing (presign), per-party active time, n={n}, mean of {reps}");
    print!("{:>8}", "threads");
    for t in T_VALUES {
        print!("{:>12}", format!("t={t}"));
    }
    println!();

    let mut baseline = [0f64; T_VALUES.len()];
    for (row, threads) in THREAD_COUNTS.into_iter().enumerate() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("thread pool");
        print!("{threads:>8}");
        let mut speedups = Vec::new();
        for (col, &(t, ref core_shares)) in shares_by_t.iter().enumerate() {
            let signers: Vec<u16> = (1..=t).collect();
            let ms = pool.install(|| {
                let total: Duration = (0..reps)
                    .map(|_| presign_active_time(&signers, n, t, core_shares, &aux_infos))
                    .sum();
                total.as_secs_f64() * 1e3 / reps as f64
            });
            if row == 0 {
                baseline[col] = ms;
            }
            speedups.push(baseline[col] / ms);
            print!("{ms:>12.1}");
        }
        print!("   |");
        for s in speedups {
            print!("{:>7.2}x", s);
        }
        println!();
    }
    println!("(ms; the right-hand block is speedup vs the 1-thread row)");
}
