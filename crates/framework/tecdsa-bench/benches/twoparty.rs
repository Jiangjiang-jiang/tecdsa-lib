use std::{collections::BTreeMap, time::Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::ops::Reduce;
use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_bench::per_party;
use tecdsa_protocol::{DataToSign, PartyId};

type C = Secp256k1;

const SAMPLES: usize = 10;

fn make_data_to_sign(msg: &[u8]) -> DataToSign<C> {
    let hash_bytes: [u8; 32] = Sha256::digest(msg).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    DataToSign::from_digest(scalar)
}

fn two_party_specs() -> [(u16, PartyId, PartyId); 2] {
    let p1 = PartyId(1);
    let p2 = PartyId(2);
    [(1, p1, p2), (2, p2, p1)]
}

fn lin17_benchmarks(c: &mut Criterion) {
    use tecdsa_lin17::{
        keygen::{Lin17KeygenMachine, TwoPartyRole},
        sign,
    };

    let specs = two_party_specs();

    {
        let mut setup_group = c.benchmark_group("twoparty/lin17");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/lin17", |b| {
            b.iter(|| {
                tecdsa_paillier::keygen(&mut tecdsa_core::Csprng::new())
                    .expect("Paillier keygen failed")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("twoparty/lin17");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        let mut p1_dk = Some(
            tecdsa_paillier::keygen(&mut tecdsa_core::Csprng::new())
                .expect("Paillier keygen failed"),
        );
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
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

    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_lin17::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        let t0 = Instant::now();
        let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
        let p1_r1 = t0.elapsed();

        let t0 = Instant::now();
        let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
        let p2_r2 = t0.elapsed();

        let t0 = Instant::now();
        sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
        let p1_r3 = t0.elapsed();

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

fn kgg24_benchmarks(c: &mut Criterion) {
    use tecdsa_kgg24::{
        keygen::{Kgg24KeygenMachine, TwoPartyRole},
        sign,
    };

    let specs = two_party_specs();

    {
        let mut setup_group = c.benchmark_group("twoparty/kgg24");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/kgg24", |b| {
            b.iter(|| {
                tecdsa_paillier::keygen(&mut tecdsa_core::Csprng::new())
                    .expect("Paillier keygen failed")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("twoparty/kgg24");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        let mut p1_dk = Some(
            tecdsa_paillier::keygen(&mut tecdsa_core::Csprng::new())
                .expect("Paillier keygen failed"),
        );
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
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

    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_kgg24::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        let t0 = Instant::now();
        let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
        let p1_r1 = t0.elapsed();

        let t0 = Instant::now();
        let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
        let p2_r2 = t0.elapsed();

        let t0 = Instant::now();
        sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
        let p1_r3 = t0.elapsed();

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

fn xal21_benchmarks(c: &mut Criterion) {
    use tecdsa_xal21::{
        keygen::{TwoPartyRole, Xal21KeygenMachine},
        offline_sign, online_sign,
    };

    let specs = two_party_specs();

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

    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        let mut p2_setup =
            Some(tecdsa_xal21::keygen::generate_setup(&mut tecdsa_core::Csprng::new()));
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
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

    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_xal21::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let mta_setup = tecdsa_paillier::mta::PaillierMtaSetup {
        ek: p2_key.ek.clone(),
        dk: p2_key.dk.clone(),
        proof_setup: tecdsa_paillier::mta::Gg18ProofSetup {
            ntilde: p2_key.ntilde.clone(),
        },
    };

    let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        let t0 = Instant::now();
        let (step1_msg, step1_state) = offline_sign::step1_p2_commit::<C>(&mut rng);
        let mut p2_off = t0.elapsed();

        let t0 = Instant::now();
        let (sender_msg, sender_state) =
            offline_sign::step2_p2_encrypt_k2::<C, offline_sign::DefaultMtA>(
                &mta_setup,
                &step1_state.k2,
                &mut rng,
            )
            .expect("step2_p2_encrypt_k2");
        p2_off += t0.elapsed();

        let t0 = Instant::now();
        let (step2_msg, step2_state) =
            offline_sign::step2_p1_compute::<C, offline_sign::DefaultMtA>(
                &p1_key,
                &mta_setup,
                &sender_msg,
                &mut rng,
            )
            .expect("step2_p1_compute");
        let mut p1_off = t0.elapsed();

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

        let t0 = Instant::now();
        let (step3_p1_msg, k1) = offline_sign::step3_p1_send_nonce::<C>(&mut rng);
        p1_off += t0.elapsed();

        let t0 = Instant::now();
        let (step3_p2_decommit, p2_presig) = offline_sign::step3_p2_decommit_and_compute_R::<C>(
            &step1_state,
            &step3_p1_msg,
            &step2_msg.r1,
            x2_prime,
        )
        .expect("step3_p2_decommit_and_compute_R");
        p2_off += t0.elapsed();

        let t0 = Instant::now();
        let p1_presig = offline_sign::step3_p1_verify_and_compute_R::<C>(
            &step1_msg,
            &step3_p2_decommit,
            k1,
            &step2_state,
        )
        .expect("step3_p1_verify_and_compute_R");
        p1_off += t0.elapsed();

        let t0 = Instant::now();
        let p2_msg = online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2");
        let p2_on = t0.elapsed();

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

fn abc24_benchmarks(c: &mut Criterion) {
    use tecdsa_abc24::{
        keygen::{Abc24KeygenMachine, TwoPartyRole},
        sign,
    };

    let specs = two_party_specs();

    {
        let mut setup_group = c.benchmark_group("twoparty/abc24");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/abc24", |b| {
            b.iter(|| {
                tecdsa_paillier::keygen(&mut tecdsa_core::Csprng::new())
                    .expect("Paillier keygen failed")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("twoparty/abc24");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let dkg_runs = per_party::precompute_runs(SAMPLES, || {
        let mut server_dk = Some(
            tecdsa_paillier::keygen(&mut tecdsa_core::Csprng::new())
                .expect("Paillier keygen failed"),
        );
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(_, my_id, peer_id))| {
                let role = roles[i];
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

    let mut rng = rand_core::OsRng;
    let (server_key, client_key) = tecdsa_abc24::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
        let mut rng = rand_core::OsRng;

        let t0 = Instant::now();
        let (server_msg, server_state) = sign::server_round1::<C>(&server_key, &mut rng);
        let p1_off = t0.elapsed();

        let t0 = Instant::now();
        let client_msg = sign::client_round2::<C>(&client_key, &server_msg, &message, &mut rng)
            .expect("client_round2");
        let p2_on = t0.elapsed();

        let t0 = Instant::now();
        sign::server_finalize::<C>(&server_key, &server_state, &client_msg, &message)
            .expect("server_finalize");
        let p1_on = t0.elapsed();

        (
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

criterion_group!(
    benches,
    lin17_benchmarks,
    kgg24_benchmarks,
    xal21_benchmarks,
    abc24_benchmarks
);
criterion_main!(benches);
