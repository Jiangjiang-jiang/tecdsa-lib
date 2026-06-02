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

use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::ops::Reduce;
use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_bench::per_party;
use tecdsa_protocol::{DataToSign, PartyId};

type C = Secp256k1;

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
    use tecdsa_lin17::keygen::{Lin17KeygenMachine, TwoPartyRole};
    use tecdsa_lin17::sign;

    let mut group = c.benchmark_group("lin17");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    let specs = two_party_specs();

    // --- DKG: per-party active time ---
    for party_idx in 1..=2u16 {
        let pid = PartyId(party_idx);
        group.bench_function(format!("dkg/lin17/n2_t1/party{party_idx}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
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
                    let (_, timings) = per_party::run_timed_with_init(builders, 10);
                    total += per_party::party_active_time(&timings, pid);
                }
                total
            });
        });
    }

    // --- Sign: per-party timing via round functions ---
    // Untimed setup: generate key shares via trusted dealer
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_lin17::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    // Party 1 active time: round1 + round3 + finalize
    group.bench_function("full_sign/lin17/n2_t1/party1", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut rng = rand_core::OsRng;

                // P1 Round 1
                let t0 = Instant::now();
                let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
                total += t0.elapsed();

                // P2 Round 2 (untimed for party 1)
                let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);

                // P1 Round 3
                let t0 = Instant::now();
                sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
                total += t0.elapsed();

                // P2 Round 4 (untimed for party 1)
                let p2_r4_msg = sign::party2_round4::<C>(
                    &p2_key,
                    &p2_state,
                    &p1_r1_msg,
                    &p1_decommit,
                    &message,
                    &mut rng,
                )
                .expect("round4");

                // P1 Finalize
                let t0 = Instant::now();
                sign::party1_finalize::<C>(&p1_key, &p1_state, &p2_state.r2, &p2_r4_msg, &message)
                    .expect("finalize");
                total += t0.elapsed();
            }
            total
        });
    });

    // Party 2 active time: round2 + round4
    group.bench_function("full_sign/lin17/n2_t1/party2", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut rng = rand_core::OsRng;

                // P1 Round 1 (untimed for party 2)
                let (p1_r1_msg, _p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);

                // P2 Round 2
                let t0 = Instant::now();
                let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
                total += t0.elapsed();

                // P1 Round 3 (untimed for party 2)
                sign::party1_round3::<C>(&p2_r2_msg).expect("round3");

                // P2 Round 4
                let t0 = Instant::now();
                let _p2_r4_msg = sign::party2_round4::<C>(
                    &p2_key,
                    &p2_state,
                    &p1_r1_msg,
                    &p1_decommit,
                    &message,
                    &mut rng,
                )
                .expect("round4");
                total += t0.elapsed();
            }
            total
        });
    });

    group.finish();
}

// ===========================================================================
// KGG24
// ===========================================================================

fn kgg24_benchmarks(c: &mut Criterion) {
    use tecdsa_kgg24::keygen::{Kgg24KeygenMachine, TwoPartyRole};
    use tecdsa_kgg24::sign;

    let mut group = c.benchmark_group("kgg24");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    let specs = two_party_specs();

    // --- DKG: per-party active time ---
    for party_idx in 1..=2u16 {
        let pid = PartyId(party_idx);
        group.bench_function(format!("dkg/kgg24/n2_t1/party{party_idx}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
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
                    let (_, timings) = per_party::run_timed_with_init(builders, 10);
                    total += per_party::party_active_time(&timings, pid);
                }
                total
            });
        });
    }

    // --- Sign: per-party timing via round functions ---
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_kgg24::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    // Party 1 active time: round1 + round3 + finalize
    group.bench_function("full_sign/kgg24/n2_t1/party1", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut rng = rand_core::OsRng;

                // P1 Round 1
                let t0 = Instant::now();
                let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
                total += t0.elapsed();

                // P2 Round 2 (untimed)
                let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);

                // P1 Round 3
                let t0 = Instant::now();
                sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
                total += t0.elapsed();

                // P2 compute partial sig (untimed)
                let p2_partial = sign::party2_compute_partial_sig::<C>(
                    &p2_key,
                    &p2_state,
                    &p1_r1_msg,
                    &p1_decommit,
                    &message,
                    &mut rng,
                )
                .expect("partial_sig");

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
                total += t0.elapsed();
            }
            total
        });
    });

    // Party 2 active time: round2 + compute_partial_sig
    group.bench_function("full_sign/kgg24/n2_t1/party2", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut rng = rand_core::OsRng;

                // P1 Round 1 (untimed)
                let (p1_r1_msg, _p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);

                // P2 Round 2
                let t0 = Instant::now();
                let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
                total += t0.elapsed();

                // P1 Round 3 (untimed)
                sign::party1_round3::<C>(&p2_r2_msg).expect("round3");

                // P2 compute partial sig
                let t0 = Instant::now();
                let _p2_partial = sign::party2_compute_partial_sig::<C>(
                    &p2_key,
                    &p2_state,
                    &p1_r1_msg,
                    &p1_decommit,
                    &message,
                    &mut rng,
                )
                .expect("partial_sig");
                total += t0.elapsed();
            }
            total
        });
    });

    group.finish();
}

// ===========================================================================
// XAL21
// ===========================================================================

fn xal21_benchmarks(c: &mut Criterion) {
    use tecdsa_xal21::keygen::{TwoPartyRole, Xal21KeygenMachine};
    use tecdsa_xal21::offline_sign;
    use tecdsa_xal21::online_sign;

    let mut group = c.benchmark_group("xal21");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    let specs = two_party_specs();

    // --- DKG: per-party active time ---
    for party_idx in 1..=2u16 {
        let pid = PartyId(party_idx);
        group.bench_function(format!("dkg/xal21/n2_t1/party{party_idx}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
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
                    let (_, timings) = per_party::run_timed_with_init(builders, 10);
                    total += per_party::party_active_time(&timings, pid);
                }
                total
            });
        });
    }

    // --- Offline Sign (presign): combined total ---
    // XAL21's offline_sign simulates both parties sequentially via step
    // functions (step1_p2, step2_p2/p1, step3_p2/p1). The step functions
    // are generic over M: MtA with complex intermediate state types,
    // making per-party round-level timing impractical without a dedicated
    // test harness. Report combined total; per-party separation requires
    // future SignMachine implementation.
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_xal21::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    group.bench_function("presign/xal21/n2_t1/combined", |b| {
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
    group.bench_function("online_sign/xal21/n2_t1/party2", |b| {
        b.iter(|| {
            online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2");
        });
    });

    // Party 1: combine and verify
    {
        let p2_msg = online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2");
        group.bench_function("online_sign/xal21/n2_t1/party1", |b| {
            b.iter(|| {
                online_sign::party1_compute_signature::<C>(&p1_key, &p1_presig, &p2_msg, &message)
                    .expect("sig");
            });
        });
    }

    group.finish();
}

// ===========================================================================
// ABC24
// ===========================================================================

fn abc24_benchmarks(c: &mut Criterion) {
    use tecdsa_abc24::keygen::{Abc24KeygenMachine, TwoPartyRole};
    use tecdsa_abc24::sign;

    let mut group = c.benchmark_group("abc24");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    let specs = two_party_specs();

    // --- DKG: per-party active time ---
    for party_idx in 1..=2u16 {
        let pid = PartyId(party_idx);
        group.bench_function(format!("dkg/abc24/n2_t1/party{party_idx}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
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
                    let (_, timings) = per_party::run_timed_with_init(builders, 10);
                    total += per_party::party_active_time(&timings, pid);
                }
                total
            });
        });
    }

    // --- Sign: per-party timing via round functions ---
    // ABC24 uses server (P1) / client (P2) terminology.
    let mut rng = rand_core::OsRng;
    let (server_key, client_key) = tecdsa_abc24::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    // Server (Party 1) active time: server_round1 + server_finalize
    group.bench_function("full_sign/abc24/n2_t1/party1", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut rng = rand_core::OsRng;

                // Server Round 1
                let t0 = Instant::now();
                let (server_msg, server_state) = sign::server_round1::<C>(&server_key, &mut rng);
                total += t0.elapsed();

                // Client Round 2 (untimed for server)
                let client_msg =
                    sign::client_round2::<C>(&client_key, &server_msg, &message, &mut rng)
                        .expect("client_round2");

                // Server Finalize
                let t0 = Instant::now();
                sign::server_finalize::<C>(&server_key, &server_state, &client_msg, &message)
                    .expect("server_finalize");
                total += t0.elapsed();
            }
            total
        });
    });

    // Client (Party 2) active time: client_round2
    group.bench_function("full_sign/abc24/n2_t1/party2", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut rng = rand_core::OsRng;

                // Server Round 1 (untimed for client)
                let (server_msg, _server_state) = sign::server_round1::<C>(&server_key, &mut rng);

                // Client Round 2
                let t0 = Instant::now();
                sign::client_round2::<C>(&client_key, &server_msg, &message, &mut rng)
                    .expect("client_round2");
                total += t0.elapsed();
            }
            total
        });
    });

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
