// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(clippy::similar_names, clippy::many_single_char_names)]

//! TX25 benchmark with paper-exact parameters (128-bit CL security).
//!
//! Paper: Tang & Xue, S&P 2025, Table 4, n=5, t=1.
//! Paper environment: MacBook Pro M1 Pro, macOS Monterey 12.3, 16GB RAM.
//! Paper CL params: CL-HSM_q, 256-bit Z_q, 1827-bit Delta_K.

use std::time::Instant;

use tecdsa_class_group::cl::ClSetup;
use tecdsa_protocol::{Outgoing, PartyId, Recipient, StateMachine};
use tecdsa_tx25::{
    keygen::Tx25KeygenMachine,
    presign::{Tx25PresignMachine, Tx25Presignature},
    sign::{Tx25OnlineSignMachine, Tx25OnlineSignMsg},
    Tx25KeyShare,
};

fn run_protocol<M>(machines: Vec<(PartyId, M)>, max_rounds: u16) -> Vec<M::Output>
where
    M: StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    let orchestrator = tecdsa_testkit::Orchestrator::new(machines, max_rounds);
    orchestrator
        .run()
        .expect("orchestrator must succeed")
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.unwrap_or_else(|e| panic!("party {i} failed: {e}")))
        .collect()
}

fn run_single_round(machines: &mut [(PartyId, Tx25OnlineSignMachine)]) {
    let mut pending: Vec<(PartyId, Outgoing<Tx25OnlineSignMsg>)> = Vec::new();
    for (pid, machine) in machines.iter_mut() {
        for msg in machine.drain_outgoing() {
            pending.push((*pid, msg));
        }
    }
    for (from, outgoing) in pending {
        match outgoing.to {
            Recipient::Party(to) => {
                if let Some((_, machine)) = machines.iter_mut().find(|(p, _)| *p == to) {
                    machine.handle(from, outgoing.msg).expect("handle");
                }
            }
            Recipient::Broadcast => {
                for (pid, machine) in machines.iter_mut() {
                    if *pid != from {
                        machine.handle(from, outgoing.msg.clone()).expect("handle");
                    }
                }
            }
        }
    }
}

#[test]
fn bench_tx25_n5_128bit() {
    let n = 5u16;
    let t = 1u16;
    let seed = "128001";
    let party_ids: Vec<PartyId> = (1..=n).map(PartyId).collect();

    println!("\n=== TX25 Benchmark (n={n}, t={t}, 128-bit CL security) ===");
    println!("Paper: Tang & Xue, S&P 2025, Table 4");
    println!("Paper env: MacBook Pro M1 Pro, macOS 12.3\n");

    // --- KeyGen ---
    let t0 = Instant::now();
    let keygen_machines: Vec<(PartyId, Tx25KeygenMachine)> = party_ids
        .iter()
        .map(|&pid| {
            let m = Tx25KeygenMachine::new(pid, party_ids.clone(), t, seed, true).expect("keygen");
            (pid, m)
        })
        .collect();
    let key_shares: Vec<Tx25KeyShare> = run_protocol(keygen_machines, 10);
    let keygen_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let pk = key_shares[0].public_key;
    for ks in &key_shares[1..] {
        assert_eq!(pk, ks.public_key);
    }

    // --- Presign (Offline) ---
    let t1 = Instant::now();
    let presign_machines: Vec<(PartyId, Tx25PresignMachine)> = party_ids
        .iter()
        .enumerate()
        .map(|(i, &pid)| {
            let setup = ClSetup::new_secp256k1_128bit(seed).expect("setup");
            let m = Tx25PresignMachine::new(pid, party_ids.clone(), &key_shares[i], setup)
                .expect("presign");
            (pid, m)
        })
        .collect();
    let presignatures: Vec<Tx25Presignature> = run_protocol(presign_machines, 10);
    let presign_ms = t1.elapsed().as_secs_f64() * 1000.0;

    for ps in &presignatures[1..] {
        assert_eq!(presignatures[0].r_point, ps.r_point);
    }

    // --- Online Sign ---
    let message = b"TX25 benchmark message";

    let t2 = Instant::now();
    let mut sign_machines: Vec<(PartyId, Tx25OnlineSignMachine)> = party_ids
        .iter()
        .enumerate()
        .map(|(i, &pid)| {
            let m = Tx25OnlineSignMachine::new(
                pid,
                party_ids.clone(),
                presignatures[i].clone(),
                message,
                pk,
            )
            .expect("sign");
            (pid, m)
        })
        .collect();
    run_single_round(&mut sign_machines);
    let online_ms = t2.elapsed().as_secs_f64() * 1000.0;

    for (pid, m) in &sign_machines {
        assert!(m.is_done(), "party {pid} not done");
    }
    let sigs: Vec<_> = sign_machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("finish"))
        .collect::<Vec<_>>();
    for s in &sigs[1..] {
        assert_eq!(sigs[0].r, s.r);
        assert_eq!(sigs[0].s, s.s);
    }

    // --- Report ---
    let n_f = n as f64;
    println!("| Phase   | Total (ms) | Per-party (ms) | Paper per-party (ms) | Ratio  |");
    println!("|---------|------------|----------------|----------------------|--------|");
    println!(
        "| KeyGen  | {:>10.0} | {:>14.0} | N/A                  | -      |",
        keygen_ms,
        keygen_ms / n_f
    );
    println!(
        "| Offline | {:>10.0} | {:>14.0} | 1224                 | {:.1}x  |",
        presign_ms,
        presign_ms / n_f,
        (presign_ms / n_f) / 1224.0
    );
    println!(
        "| Online  | {:>10.2} | {:>14.2} | 1.18                 | {:.1}x  |",
        online_ms,
        online_ms / n_f,
        (online_ms / n_f) / 1.18
    );
    println!();
    println!("Signature: PASS");
}
