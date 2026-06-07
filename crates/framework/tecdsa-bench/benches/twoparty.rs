// SPDX-License-Identifier: MIT OR Apache-2.0
//! Two-party protocol benchmark suite for threshold ECDSA protocols.
//!
//! Benchmarks four two-party protocols:
//! - **Lin17**: 4-round sign, Paillier multiplicative sharing
//! - **KGG24**: 3-round sign + proactive refresh, Paillier additive sharing
//! - **XAL21**: 2-round offline + 1-round online, generic over MtA (default: Paillier)
//! - **ABC24**: 2-round sign, Paillier OLE, additive sharing
//!
//! DKG is measured via the interactive `KeygenMachine` StateMachine with
//! per-party timing through the Orchestrator. Sign phases use per-party
//! round functions timed individually.

use std::{collections::BTreeMap, time::Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::ops::Reduce;
use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_bench::per_party;
use tecdsa_protocol::{DataToSign, PartyId};

type C = Secp256k1;

/// Number of Criterion samples per party benchmark. Also the number of real
/// protocol executions per phase (plus one warm-up run). A single execution
/// produces every party's timing, which is then replayed per party.
const SAMPLES: usize = 10;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a DataToSign from raw bytes by SHA-256 hashing and reducing mod q.
fn make_data_to_sign(msg: &[u8]) -> DataToSign<C> {
    let hash_bytes: [u8; 32] = Sha256::digest(msg).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    DataToSign::from_digest(scalar)
}

/// Two-party role specs: (role_index, my_id, peer_id).
fn two_party_specs() -> [(u16, PartyId, PartyId); 2] {
    let p1 = PartyId(1);
    let p2 = PartyId(2);
    [(1, p1, p2), (2, p2, p1)]
}

// ===========================================================================
// Lin17
// ===========================================================================

fn lin17_benchmarks(c: &mut Criterion) {
    use tecdsa_lin17::{
        keygen::{Lin17KeygenMachine, TwoPartyRole},
        sign,
    };

    let mut group = c.benchmark_group("twoparty/lin17");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let specs = two_party_specs();

    // --- DKG: one execution per sample, every party reported separately ---
    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Lin17KeygenMachine::<C>::new(role, my_id, peer_id, &mut rng)
                        .expect("keygen machine init")
                })
            })
            .collect();
        per_party::active_with_init(builders, 10)
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay(
            &mut group,
            format!("dkg/lin17/n2_t2/party{party_idx}"),
            &dkg_runs,
            PartyId(party_idx),
        );
    }

    // --- Sign: one execution per sample, both parties timed via round functions ---
    // Untimed setup: generate key shares via trusted dealer
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_lin17::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let sign_runs = per_party::precompute_runs(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        // P1 Round 1
        let t0 = Instant::now();
        let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
        let p1_r1 = t0.elapsed();

        // P2 Round 2
        let t0 = Instant::now();
        let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
        let p2_r2 = t0.elapsed();

        // P1 Round 3
        let t0 = Instant::now();
        sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
        let p1_r3 = t0.elapsed();

        // P2 Round 4
        let t0 = Instant::now();
        let p2_r4_msg = sign::party2_round4::<C>(
            &p2_key,
            &p2_state,
            &p1_r1_msg,
            &p1_decommit,
            &message,
            &mut rng,
        )
        .expect("round4");
        let p2_r4 = t0.elapsed();

        // P1 Finalize
        let t0 = Instant::now();
        sign::party1_finalize::<C>(&p1_key, &p1_state, &p2_state.r2, &p2_r4_msg, &message)
            .expect("finalize");
        let p1_fin = t0.elapsed();

        BTreeMap::from([
            (PartyId(1), p1_r1 + p1_r3 + p1_fin),
            (PartyId(2), p2_r2 + p2_r4),
        ])
    });
    per_party::bench_party_replay(
        &mut group,
        "full_sign/lin17/n2_t2/party1",
        &sign_runs,
        PartyId(1),
    );
    per_party::bench_party_replay(
        &mut group,
        "full_sign/lin17/n2_t2/party2",
        &sign_runs,
        PartyId(2),
    );

    group.finish();
}

// ===========================================================================
// KGG24
// ===========================================================================

fn kgg24_benchmarks(c: &mut Criterion) {
    use tecdsa_kgg24::{
        keygen::{Kgg24KeygenMachine, TwoPartyRole},
        sign,
    };

    let mut group = c.benchmark_group("twoparty/kgg24");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let specs = two_party_specs();

    // --- DKG: one execution per sample, every party reported separately ---
    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Kgg24KeygenMachine::<C>::new(role, my_id, peer_id, &mut rng)
                        .expect("keygen machine init")
                })
            })
            .collect();
        per_party::active_with_init(builders, 10)
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay(
            &mut group,
            format!("dkg/kgg24/n2_t2/party{party_idx}"),
            &dkg_runs,
            PartyId(party_idx),
        );
    }

    // --- Sign: one execution per sample, both parties timed via round functions ---
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_kgg24::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let sign_runs = per_party::precompute_runs(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        // P1 Round 1
        let t0 = Instant::now();
        let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
        let p1_r1 = t0.elapsed();

        // P2 Round 2
        let t0 = Instant::now();
        let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
        let p2_r2 = t0.elapsed();

        // P1 Round 3
        let t0 = Instant::now();
        sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
        let p1_r3 = t0.elapsed();

        // P2 compute partial sig
        let t0 = Instant::now();
        let p2_partial = sign::party2_compute_partial_sig::<C>(
            &p2_key,
            &p2_state,
            &p1_r1_msg,
            &p1_decommit,
            &message,
            &mut rng,
        )
        .expect("partial_sig");
        let p2_partial_dur = t0.elapsed();

        // P1 Finalize
        let t0 = Instant::now();
        sign::party1_finalize::<C>(
            &p1_key,
            &p1_state,
            &p2_state.r2,
            &p2_partial,
            &message,
            &mut rng,
        )
        .expect("finalize");
        let p1_fin = t0.elapsed();

        BTreeMap::from([
            (PartyId(1), p1_r1 + p1_r3 + p1_fin),
            (PartyId(2), p2_r2 + p2_partial_dur),
        ])
    });
    per_party::bench_party_replay(
        &mut group,
        "full_sign/kgg24/n2_t2/party1",
        &sign_runs,
        PartyId(1),
    );
    per_party::bench_party_replay(
        &mut group,
        "full_sign/kgg24/n2_t2/party2",
        &sign_runs,
        PartyId(2),
    );

    group.finish();
}

// ===========================================================================
// XAL21
// ===========================================================================

fn xal21_benchmarks(c: &mut Criterion) {
    use tecdsa_xal21::{
        keygen::{TwoPartyRole, Xal21KeygenMachine},
        offline_sign, online_sign,
    };

    let mut group = c.benchmark_group("twoparty/xal21");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let specs = two_party_specs();

    // --- DKG: one execution per sample, every party reported separately ---
    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Xal21KeygenMachine::<C>::new(role, my_id, peer_id, &mut rng)
                        .expect("keygen machine init")
                })
            })
            .collect();
        per_party::active_with_init(builders, 10)
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay(
            &mut group,
            format!("dkg/xal21/n2_t2/party{party_idx}"),
            &dkg_runs,
            PartyId(party_idx),
        );
    }
    group.finish();

    // --- Offline/Online sign: local single-op benchmarks ---
    // XAL21's offline_sign simulates both parties sequentially via step
    // functions (step1_p2, step2_p2/p1, step3_p2/p1). The step functions
    // are generic over M: MtA with complex intermediate state types,
    // making per-party round-level timing impractical without a dedicated
    // test harness. Report combined total; per-party separation requires
    // future SignMachine implementation. These are kept in a separate group
    // so they use normal Criterion timing (the replay group sets
    // measurement_time to ~0).
    let mut sign_group = c.benchmark_group("twoparty/xal21_sign");
    sign_group.sample_size(10);

    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_xal21::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    sign_group.bench_function("presign/xal21/n2_t2/combined", |b| {
        b.iter(|| {
            let mut rng = rand_core::OsRng;
            offline_sign::offline_sign::<C>(&p1_key, &p2_key, &mut rng).expect("offline_sign");
        });
    });

    // --- Online Sign: per-party timing ---
    // P2 computes partial signature, P1 combines and verifies.
    // Generate fresh presignature for online sign benchmarks (untimed setup).
    let (p1_presig, p2_presig) =
        offline_sign::offline_sign::<C>(&p1_key, &p2_key, &mut rng).expect("offline_sign");

    // Party 2: compute s2
    sign_group.bench_function("online_sign/xal21/n2_t2/party2", |b| {
        b.iter(|| {
            online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2");
        });
    });

    // Party 1: combine and verify
    {
        let p2_msg = online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2");
        sign_group.bench_function("online_sign/xal21/n2_t2/party1", |b| {
            b.iter(|| {
                online_sign::party1_compute_signature::<C>(&p1_key, &p1_presig, &p2_msg, &message)
                    .expect("sig");
            });
        });
    }

    sign_group.finish();
}

// ===========================================================================
// ABC24
// ===========================================================================

fn abc24_benchmarks(c: &mut Criterion) {
    use tecdsa_abc24::{
        keygen::{Abc24KeygenMachine, TwoPartyRole},
        sign,
    };

    let mut group = c.benchmark_group("twoparty/abc24");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let specs = two_party_specs();

    // --- DKG: one execution per sample, every party reported separately ---
    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Abc24KeygenMachine::<C>::new(role, my_id, peer_id, &mut rng)
                        .expect("keygen machine init")
                })
            })
            .collect();
        per_party::active_with_init(builders, 10)
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay(
            &mut group,
            format!("dkg/abc24/n2_t2/party{party_idx}"),
            &dkg_runs,
            PartyId(party_idx),
        );
    }

    // --- Sign: one execution per sample, both parties timed via round functions ---
    // ABC24 uses server (P1) / client (P2) terminology.
    let mut rng = rand_core::OsRng;
    let (server_key, client_key) = tecdsa_abc24::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let sign_runs = per_party::precompute_runs(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        // Server (P1) Round 1
        let t0 = Instant::now();
        let (server_msg, server_state) = sign::server_round1::<C>(&server_key, &mut rng);
        let p1_r1 = t0.elapsed();

        // Client (P2) Round 2
        let t0 = Instant::now();
        let client_msg = sign::client_round2::<C>(&client_key, &server_msg, &message, &mut rng)
            .expect("client_round2");
        let p2_r2 = t0.elapsed();

        // Server (P1) Finalize
        let t0 = Instant::now();
        sign::server_finalize::<C>(&server_key, &server_state, &client_msg, &message)
            .expect("server_finalize");
        let p1_fin = t0.elapsed();

        BTreeMap::from([(PartyId(1), p1_r1 + p1_fin), (PartyId(2), p2_r2)])
    });
    per_party::bench_party_replay(
        &mut group,
        "full_sign/abc24/n2_t2/party1",
        &sign_runs,
        PartyId(1),
    );
    per_party::bench_party_replay(
        &mut group,
        "full_sign/abc24/n2_t2/party2",
        &sign_runs,
        PartyId(2),
    );

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion groups and main
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    lin17_benchmarks,
    kgg24_benchmarks,
    xal21_benchmarks,
    abc24_benchmarks
);
criterion_main!(benches);
