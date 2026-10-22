// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase-by-phase wall-clock profile of CGGMP20 at the production security level.
//!
//! Run with:
//!   cargo run --release --example cggmp20_profile -p tecdsa-cggmp20

use std::time::Instant;

use tecdsa_cggmp20::{
    aux_info::AuxInfoMachine,
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    keygen::Cggmp20KeygenMachine,
    presign::Cggmp20PresignMachine,
    security_level::SecurityLevel128,
};
use tecdsa_core::Csprng;
use tecdsa_protocol::{PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine};

type C = k256::Secp256k1;

fn make_session_configs(n: u16, t: u16) -> Vec<SessionConfig> {
    let session_id = SessionId([0u8; 32]);
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    (1..=n)
        .map(|i| SessionConfig {
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

/// Drive machines to completion, charging each party's compute time separately.
fn run_protocol<M: StateMachine>(machines: &mut [(PartyId, M)], max_rounds: u16) -> Vec<f64>
where
    M::Outbound: Clone + Into<M::Inbound>,
{
    let mut per_party = vec![0f64; machines.len()];
    for _round in 0..max_rounds {
        if machines.iter().all(|(_, m)| m.is_done()) {
            break;
        }
        let mut pending = Vec::new();
        for (i, (pid, machine)) in machines.iter_mut().enumerate() {
            let t0 = Instant::now();
            let msgs: Vec<_> = machine.drain_outgoing();
            per_party[i] += t0.elapsed().as_secs_f64();
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
                        let inbound = outgoing.msg.into();
                        let t0 = Instant::now();
                        machine.handle(from, inbound).expect("handle");
                        per_party[i] += t0.elapsed().as_secs_f64();
                    }
                }
                Recipient::Broadcast => {
                    for (i, (pid, machine)) in machines.iter_mut().enumerate() {
                        if *pid != from {
                            let inbound = outgoing.msg.clone().into();
                            let t0 = Instant::now();
                            machine.handle(from, inbound).expect("handle");
                            per_party[i] += t0.elapsed().as_secs_f64();
                        }
                    }
                }
            }
        }
    }
    per_party
}

fn main() {
    let mut args = std::env::args().skip(1);
    let n: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(3);
    let t: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(2);
    // Presigning is cheap relative to the one-time setup, so it can be repeated
    // to average out noise without paying for aux-info again.
    let presign_reps: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let signers: Vec<u16> = (1..=t).collect();
    let signers = &signers[..];

    println!(
        "n={n} t={t}  mode: {}",
        if cfg!(feature = "parallel") {
            format!("parallel, {} threads", tecdsa_bigint::par::num_threads())
        } else {
            "sequential".to_string()
        }
    );

    // ---- keygen ----
    let configs = make_session_configs(n, t);
    let mut rng = Csprng::new();
    let t0 = Instant::now();
    let mut machines: Vec<(PartyId, Cggmp20KeygenMachine<C>)> = configs
        .iter()
        .map(|cfg| {
            (
                cfg.local_party.id,
                Cggmp20KeygenMachine::<C>::new(cfg, &mut rng),
            )
        })
        .collect();
    let keygen_init = t0.elapsed().as_secs_f64() / f64::from(n);
    let keygen_rounds = run_protocol(&mut machines, 10);
    let t0 = Instant::now();
    let core_shares: Vec<Cggmp20CoreKeyShare<C>> = machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("keygen"))
        .collect();
    let keygen_finish = t0.elapsed().as_secs_f64() / f64::from(n);
    println!(
        "keygen        init {:>8.1} ms   rounds {:>8.1} ms   finish {:>8.1} ms  (per party)",
        keygen_init * 1e3,
        keygen_rounds[0] * 1e3,
        keygen_finish * 1e3
    );

    // ---- aux info ----
    let configs = make_session_configs(n, t);
    let t0 = Instant::now();
    let mut machines: Vec<(PartyId, AuxInfoMachine<SecurityLevel128>)> = configs
        .iter()
        .map(|cfg| {
            (
                cfg.local_party.id,
                AuxInfoMachine::<SecurityLevel128>::new(cfg, &mut rng),
            )
        })
        .collect();
    let aux_init = t0.elapsed().as_secs_f64() / f64::from(n);
    let aux_rounds = run_protocol(&mut machines, 10);
    let t0 = Instant::now();
    let aux_infos: Vec<AuxInfo> = machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("aux"))
        .collect();
    let aux_finish = t0.elapsed().as_secs_f64() / f64::from(n);
    println!(
        "aux_info      init {:>8.1} ms   rounds {:>8.1} ms   finish {:>8.1} ms  (per party)",
        aux_init * 1e3,
        aux_rounds[0] * 1e3,
        aux_finish * 1e3
    );

    // ---- presign (the offline signing phase) ----
    let signer_configs = make_signer_configs(signers, n, t);
    let mut samples: Vec<(f64, f64, f64)> = Vec::with_capacity(presign_reps);
    for _ in 0..presign_reps {
        let t0 = Instant::now();
        let mut machines: Vec<(PartyId, Cggmp20PresignMachine<C>)> = signers
            .iter()
            .enumerate()
            .map(|(idx, &s)| {
                let p0 = (s - 1) as usize;
                (
                    PartyId(s),
                    Cggmp20PresignMachine::<C>::with_security::<SecurityLevel128>(
                        &signer_configs[idx],
                        &core_shares[p0],
                        &aux_infos[p0],
                        signers,
                        &mut rng,
                    ),
                )
            })
            .collect();
        let pre_init = t0.elapsed().as_secs_f64() / signers.len() as f64;
        let pre_rounds = run_protocol(&mut machines, 10);
        let t0 = Instant::now();
        let _presigs: Vec<_> = machines
            .into_iter()
            .map(|(_, m)| m.finish().expect("presign"))
            .collect();
        let pre_finish = t0.elapsed().as_secs_f64() / signers.len() as f64;
        samples.push((pre_init, pre_rounds[0], pre_finish));
    }
    let reps = samples.len() as f64;
    let mean_init = samples.iter().map(|s| s.0).sum::<f64>() / reps;
    let mean_rounds = samples.iter().map(|s| s.1).sum::<f64>() / reps;
    let mean_finish = samples.iter().map(|s| s.2).sum::<f64>() / reps;
    println!(
        "presign       init {:>8.1} ms   rounds {:>8.1} ms   finish {:>8.1} ms   TOTAL {:>8.1} ms  (per party, mean of {presign_reps})",
        mean_init * 1e3,
        mean_rounds * 1e3,
        mean_finish * 1e3,
        (mean_init + mean_rounds + mean_finish) * 1e3
    );
}
