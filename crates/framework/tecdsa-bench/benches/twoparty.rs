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
//!
//! Each protocol's one-time, per-party key material (Paillier keypair; XAL21
//! also the Ring-Pedersen `N~` parameters) is benchmarked separately as
//! `setup/<proto>` and reported in seconds. The same material is injected into
//! the DKG run *untimed* (via each machine's `new_with_setup` constructor), so
//! the `dkg/...` figures measure only the interactive key-generation rounds and
//! exclude the (multi-second) safe-prime generation. This mirrors the
//! `setup/<proto>` split used by the multi-party suite (e.g. GG18, TX25).

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

    let specs = two_party_specs();

    // --- Setup: P1's one-time Paillier keypair (the dominant DKG setup cost).
    // Measured here with real timing and excluded from the DKG rounds below so
    // the two figures are reported separately. ---
    {
        let mut setup_group = c.benchmark_group("twoparty/lin17");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/lin17", |b| {
            b.iter(|| {
                tecdsa_paillier::DecryptionKey::generate(&mut tecdsa_core::Csprng::new())
                    .expect("Paillier keygen failed")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("twoparty/lin17");
    per_party::configure_replay_group(&mut group, SAMPLES);

    // --- DKG: one execution per sample, every party reported separately ---
    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        // Untimed one-time setup: P1's Paillier key, generated outside the timed
        // builder so the DKG rounds exclude it (measured by `setup/lin17`).
        let mut p1_dk = Some(
            tecdsa_paillier::DecryptionKey::generate(&mut tecdsa_core::Csprng::new())
                .expect("Paillier keygen failed"),
        );
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
                // Only P1 consumes the precomputed Paillier key.
                let precomputed_dk = if role == TwoPartyRole::Party1 {
                    p1_dk.take()
                } else {
                    None
                };
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Lin17KeygenMachine::<C>::new_with_setup(
                        role,
                        my_id,
                        peer_id,
                        precomputed_dk,
                        &mut rng,
                    )
                    .expect("keygen machine init")
                })
            })
            .collect();
        per_party::active_with_init(builders, 10)
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay_single(
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

    // Sign split per party into offline (message-independent rounds) and online
    // (rounds that take the message). Offline: P1 round1+round3, P2 round2.
    // Online: P1 finalize, P2 round4.
    let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        // P1 Round 1 (offline)
        let t0 = Instant::now();
        let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
        let p1_r1 = t0.elapsed();

        // P2 Round 2 (offline)
        let t0 = Instant::now();
        let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
        let p2_r2 = t0.elapsed();

        // P1 Round 3 (offline)
        let t0 = Instant::now();
        sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
        let p1_r3 = t0.elapsed();

        // P2 Round 4 (online: takes the message)
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

        // P1 Finalize (online: takes the message)
        let t0 = Instant::now();
        sign::party1_finalize::<C>(&p1_key, &p1_state, &p2_state.r2, &p2_r4_msg, &message)
            .expect("finalize");
        let p1_fin = t0.elapsed();

        (
            BTreeMap::from([(PartyId(1), p1_r1 + p1_r3), (PartyId(2), p2_r2)]),
            BTreeMap::from([(PartyId(1), p1_fin), (PartyId(2), p2_r4)]),
        )
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay_single(
            &mut group,
            format!("presign/lin17/n2_t2/party{party_idx}"),
            &presign_runs,
            PartyId(party_idx),
        );
        per_party::bench_party_replay_single(
            &mut group,
            format!("online_sign/lin17/n2_t2/party{party_idx}"),
            &online_runs,
            PartyId(party_idx),
        );
    }

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

    let specs = two_party_specs();

    // --- Setup: P1's one-time Paillier keypair (the dominant DKG setup cost),
    // measured separately from the DKG rounds below. ---
    {
        let mut setup_group = c.benchmark_group("twoparty/kgg24");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/kgg24", |b| {
            b.iter(|| {
                tecdsa_paillier::DecryptionKey::generate(&mut tecdsa_core::Csprng::new())
                    .expect("Paillier keygen failed")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("twoparty/kgg24");
    per_party::configure_replay_group(&mut group, SAMPLES);

    // --- DKG: one execution per sample, every party reported separately ---
    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        // Untimed one-time setup: P1's Paillier key, generated outside the timed
        // builder so the DKG rounds exclude it (measured by `setup/kgg24`).
        let mut p1_dk = Some(
            tecdsa_paillier::DecryptionKey::generate(&mut tecdsa_core::Csprng::new())
                .expect("Paillier keygen failed"),
        );
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
                // Only P1 consumes the precomputed Paillier key.
                let precomputed_dk = if role == TwoPartyRole::Party1 {
                    p1_dk.take()
                } else {
                    None
                };
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Kgg24KeygenMachine::<C>::new_with_setup(
                        role,
                        my_id,
                        peer_id,
                        precomputed_dk,
                        &mut rng,
                    )
                    .expect("keygen machine init")
                })
            })
            .collect();
        per_party::active_with_init(builders, 10)
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay_single(
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

    // Sign split per party into offline (message-independent rounds) and online
    // (rounds that take the message). Offline: P1 round1+round3, P2 round2.
    // Online: P1 finalize, P2 compute_partial_sig.
    let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        // P1 Round 1 (offline)
        let t0 = Instant::now();
        let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
        let p1_r1 = t0.elapsed();

        // P2 Round 2 (offline)
        let t0 = Instant::now();
        let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
        let p2_r2 = t0.elapsed();

        // P1 Round 3 (offline)
        let t0 = Instant::now();
        sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
        let p1_r3 = t0.elapsed();

        // P2 compute partial sig (online: takes the message)
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

        // P1 Finalize (online: takes the message)
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

        (
            BTreeMap::from([(PartyId(1), p1_r1 + p1_r3), (PartyId(2), p2_r2)]),
            BTreeMap::from([(PartyId(1), p1_fin), (PartyId(2), p2_partial_dur)]),
        )
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay_single(
            &mut group,
            format!("presign/kgg24/n2_t2/party{party_idx}"),
            &presign_runs,
            PartyId(party_idx),
        );
        per_party::bench_party_replay_single(
            &mut group,
            format!("online_sign/kgg24/n2_t2/party{party_idx}"),
            &online_runs,
            PartyId(party_idx),
        );
    }

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

    let specs = two_party_specs();

    // --- Setup: P2's one-time MtA setup (Paillier keypair + Ring-Pedersen
    // params), the dominant DKG setup cost, measured separately from the DKG
    // rounds below. ---
    {
        let mut setup_group = c.benchmark_group("twoparty/xal21");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/xal21", |b| {
            b.iter(|| tecdsa_xal21::keygen::generate_setup(&mut tecdsa_core::Csprng::new()));
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("twoparty/xal21");
    per_party::configure_replay_group(&mut group, SAMPLES);

    // --- DKG: one execution per sample, every party reported separately ---
    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        // Untimed one-time setup: P2's MtA material (Paillier key + Ring-Pedersen
        // params), generated outside the timed builder so the DKG rounds exclude
        // it (measured by `setup/xal21`).
        let mut p2_setup = Some(tecdsa_xal21::keygen::generate_setup(
            &mut tecdsa_core::Csprng::new(),
        ));
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
                // Only P2 consumes the precomputed MtA setup.
                let precomputed_setup = if role == TwoPartyRole::Party2 {
                    p2_setup.take()
                } else {
                    None
                };
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Xal21KeygenMachine::<C>::new_with_setup(
                        role,
                        my_id,
                        peer_id,
                        precomputed_setup,
                        &mut rng,
                    )
                    .expect("keygen machine init")
                })
            })
            .collect();
        per_party::active_with_init(builders, 10)
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay_single(
            &mut group,
            format!("dkg/xal21/n2_t2/party{party_idx}"),
            &dkg_runs,
            PartyId(party_idx),
        );
    }

    // --- Sign: offline (message-independent) + online (takes the message), per
    // party, in the same replay group as DKG. Offline mirrors the per-party step
    // functions of `offline_sign_generic`:
    //   P2 = step1_commit + step2_encrypt_k2 + step2_verify + step3_decommit_R
    //   P1 = step2_compute + step3_send_nonce + step3_verify_R
    // Online: P2 = party2_compute_s2, P1 = party1_compute_signature.
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_xal21::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    // MtA setup, built from P2's key exactly as `offline_sign` does (untimed).
    let mta_setup = tecdsa_paillier::mta::PaillierMtaSetup {
        ek: p2_key.ek.clone(),
        dk: p2_key.dk.clone(),
        proof_setup: tecdsa_paillier::mta::Gg18ProofSetup {
            ntilde: p2_key.ntilde.clone(),
        },
    };

    let (presign_runs, online_runs) =
        per_party::precompute_runs_2(SAMPLES, || {
            let mut rng = rand_core::OsRng;

            // P2 step1: commit nonce (offline)
            let t0 = Instant::now();
            let (step1_msg, step1_state) = offline_sign::step1_p2_commit::<C>(&mut rng);
            let mut p2_off = t0.elapsed();

            // P2 step2a: encrypt k2 for MtA (offline)
            let t0 = Instant::now();
            let (sender_msg, sender_state) = offline_sign::step2_p2_encrypt_k2::<
                C,
                offline_sign::DefaultMtA,
            >(&mta_setup, &step1_state.k2, &mut rng)
            .expect("step2_p2_encrypt_k2");
            p2_off += t0.elapsed();

            // P1 step2b: compute re-sharing data (offline)
            let t0 = Instant::now();
            let (step2_msg, step2_state) = offline_sign::step2_p1_compute::<
                C,
                offline_sign::DefaultMtA,
            >(&p1_key, &mta_setup, &sender_msg, &mut rng)
            .expect("step2_p1_compute");
            let mut p1_off = t0.elapsed();

            // P2 step2c: verify + compute x2' (offline)
            let t0 = Instant::now();
            let x2_prime = offline_sign::step2_p2_verify::<C, offline_sign::DefaultMtA>(
                &p2_key,
                &mta_setup,
                &sender_state,
                &step1_state.k2,
                &step2_msg,
            )
            .expect("step2_p2_verify");
            p2_off += t0.elapsed();

            // P1 step3a: send nonce (offline)
            let t0 = Instant::now();
            let (step3_p1_msg, k1) = offline_sign::step3_p1_send_nonce::<C>(&mut rng);
            p1_off += t0.elapsed();

            // P2 step3b: decommit + compute R (offline)
            let t0 = Instant::now();
            let (step3_p2_decommit, p2_presig) =
                offline_sign::step3_p2_decommit_and_compute_R::<C>(
                    &step1_state,
                    &step3_p1_msg,
                    &step2_msg.r1,
                    x2_prime,
                )
                .expect("step3_p2_decommit_and_compute_R");
            p2_off += t0.elapsed();

            // P1 step3c: verify + compute R (offline)
            let t0 = Instant::now();
            let p1_presig = offline_sign::step3_p1_verify_and_compute_R::<C>(
                &step1_msg,
                &step3_p2_decommit,
                k1,
                &step2_state,
            )
            .expect("step3_p1_verify_and_compute_R");
            p1_off += t0.elapsed();

            // P2 online: compute s2 (takes the message)
            let t0 = Instant::now();
            let p2_msg = online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2");
            let p2_on = t0.elapsed();

            // P1 online: combine + verify (takes the message)
            let t0 = Instant::now();
            online_sign::party1_compute_signature::<C>(&p1_key, &p1_presig, &p2_msg, &message)
                .expect("sig");
            let p1_on = t0.elapsed();

            (
                BTreeMap::from([(PartyId(1), p1_off), (PartyId(2), p2_off)]),
                BTreeMap::from([(PartyId(1), p1_on), (PartyId(2), p2_on)]),
            )
        });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay_single(
            &mut group,
            format!("presign/xal21/n2_t2/party{party_idx}"),
            &presign_runs,
            PartyId(party_idx),
        );
        per_party::bench_party_replay_single(
            &mut group,
            format!("online_sign/xal21/n2_t2/party{party_idx}"),
            &online_runs,
            PartyId(party_idx),
        );
    }

    group.finish();
}

// ===========================================================================
// ABC24
// ===========================================================================

fn abc24_benchmarks(c: &mut Criterion) {
    use tecdsa_abc24::{
        keygen::{Abc24KeygenMachine, TwoPartyRole},
        sign,
    };

    let specs = two_party_specs();

    // --- Setup: the server's (P1) one-time Paillier keypair, part of the
    // SetupData it publishes non-interactively. Measured separately from the
    // DKG steps below. ---
    {
        let mut setup_group = c.benchmark_group("twoparty/abc24");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/abc24", |b| {
            b.iter(|| {
                tecdsa_paillier::DecryptionKey::generate(&mut tecdsa_core::Csprng::new())
                    .expect("Paillier keygen failed")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("twoparty/abc24");
    per_party::configure_replay_group(&mut group, SAMPLES);

    // --- DKG: one execution per sample, every party reported separately ---
    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        // Untimed one-time setup: the server's (P1) Paillier key, generated
        // outside the timed builder so the DKG steps exclude it (measured by
        // `setup/abc24`).
        let mut server_dk = Some(
            tecdsa_paillier::DecryptionKey::generate(&mut tecdsa_core::Csprng::new())
                .expect("Paillier keygen failed"),
        );
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
                // Only the server (P1) consumes the precomputed Paillier key.
                let precomputed_dk = if role == TwoPartyRole::Party1 {
                    server_dk.take()
                } else {
                    None
                };
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Abc24KeygenMachine::<C>::new_with_setup(
                        role,
                        my_id,
                        peer_id,
                        precomputed_dk,
                        &mut rng,
                    )
                    .expect("keygen machine init")
                })
            })
            .collect();
        per_party::active_with_init(builders, 10)
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay_single(
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

    // Sign split per party into offline (message-independent) and online (takes
    // the message). Offline: P1 = server_round1, P2 = nothing. Online: P1 =
    // server_finalize, P2 = client_round2.
    let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        // Server (P1) Round 1 (offline)
        let t0 = Instant::now();
        let (server_msg, server_state) = sign::server_round1::<C>(&server_key, &mut rng);
        let p1_off = t0.elapsed();

        // Client (P2) Round 2 (online: takes the message)
        let t0 = Instant::now();
        let client_msg = sign::client_round2::<C>(&client_key, &server_msg, &message, &mut rng)
            .expect("client_round2");
        let p2_on = t0.elapsed();

        // Server (P1) Finalize (online: takes the message)
        let t0 = Instant::now();
        sign::server_finalize::<C>(&server_key, &server_state, &client_msg, &message)
            .expect("server_finalize");
        let p1_on = t0.elapsed();

        (
            // Client (P2) does no offline work.
            BTreeMap::from([
                (PartyId(1), p1_off),
                (PartyId(2), std::time::Duration::ZERO),
            ]),
            BTreeMap::from([(PartyId(1), p1_on), (PartyId(2), p2_on)]),
        )
    });
    for party_idx in 1..=2u16 {
        per_party::bench_party_replay_single(
            &mut group,
            format!("presign/abc24/n2_t2/party{party_idx}"),
            &presign_runs,
            PartyId(party_idx),
        );
        per_party::bench_party_replay_single(
            &mut group,
            format!("online_sign/abc24/n2_t2/party{party_idx}"),
            &online_runs,
            PartyId(party_idx),
        );
    }

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
