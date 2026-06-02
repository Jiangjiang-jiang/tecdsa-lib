// SPDX-License-Identifier: MIT OR Apache-2.0
//! Supplementary primitive benchmarks (NOT part of the main protocol table).
//!
//! Benchmarks the raw Paillier MtA cycle (sender_encrypt, receiver_compute,
//! sender_decrypt) used as a building block by Paillier-based protocols.
//!
//! These benchmarks are for primitive cost analysis, not protocol comparison.
//! The main protocol tables are in `multiparty.rs` and `twoparty.rs`.

use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::PrimeField;
use k256::Secp256k1;
use rand_core::OsRng;

// ---------------------------------------------------------------------------
// MtA benchmarks (raw Paillier MtA cycle)
// ---------------------------------------------------------------------------

fn mta_benchmarks(c: &mut Criterion) {
    use tecdsa_curve::TecdsaCurve;
    use tecdsa_paillier::mta::{PaillierMtA, PaillierMtaSetup, SimpleProofs};
    use tecdsa_protocol::MtA;

    type DefaultMtA = PaillierMtA<SimpleProofs>;

    let mut group = c.benchmark_group("mta");
    group.sample_size(10);

    // Pre-generate Paillier keys (slow).
    let dk = tecdsa_paillier::keygen(&mut OsRng).expect("Paillier keygen failed");
    let ek = dk.encryption_key().clone();

    let setup: PaillierMtaSetup<SimpleProofs> = PaillierMtaSetup {
        ek,
        dk,
        proof_setup: (),
    };

    // Generate two random scalar inputs for the MtA protocol.
    let a = Secp256k1::random_scalar(&mut OsRng);
    let b = Secp256k1::random_scalar(&mut OsRng);
    let a_bytes = a.to_repr();
    let b_bytes = b.to_repr();

    // Compute curve order q in big-endian bytes.
    let neg_one = -k256::Scalar::ONE;
    let neg_one_bytes = neg_one.to_repr();
    let q_int = tecdsa_paillier::backend::Integer::from_bytes_msf(neg_one_bytes.as_ref()) + 1u8;
    let q_bytes = q_int.to_bytes_msf();

    // Benchmark the full MtA cycle: sender_encrypt + receiver_compute + sender_decrypt
    group.bench_function("paillier_full_cycle", |bench| {
        bench.iter(|| {
            let (sender_msg, sender_state) =
                DefaultMtA::sender_encrypt(&setup, a_bytes.as_ref(), &q_bytes, &mut OsRng)
                    .expect("sender_encrypt failed");

            let (receiver_msg, _alpha) = DefaultMtA::receiver_compute(
                &setup,
                b_bytes.as_ref(),
                &q_bytes,
                &sender_msg,
                &mut OsRng,
            )
            .expect("receiver_compute failed");

            let _beta = DefaultMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
                .expect("sender_decrypt failed");
        });
    });

    // Benchmark individual MtA steps.

    // Step 1: sender_encrypt
    group.bench_function("paillier_sender_encrypt", |bench| {
        bench.iter(|| {
            DefaultMtA::sender_encrypt(&setup, a_bytes.as_ref(), &q_bytes, &mut OsRng)
                .expect("sender_encrypt failed")
        });
    });

    // Step 2: receiver_compute (requires sender_msg from step 1)
    let (sender_msg_precomputed, _sender_state_precomputed) =
        DefaultMtA::sender_encrypt(&setup, a_bytes.as_ref(), &q_bytes, &mut OsRng)
            .expect("sender_encrypt setup failed");

    group.bench_function("paillier_receiver_compute", |bench| {
        bench.iter(|| {
            DefaultMtA::receiver_compute(
                &setup,
                b_bytes.as_ref(),
                &q_bytes,
                &sender_msg_precomputed,
                &mut OsRng,
            )
            .expect("receiver_compute failed")
        });
    });

    // Step 3: sender_decrypt (requires receiver_msg from step 2)
    let (sender_msg_for_decrypt, sender_state_for_decrypt) =
        DefaultMtA::sender_encrypt(&setup, a_bytes.as_ref(), &q_bytes, &mut OsRng)
            .expect("sender_encrypt setup failed");

    let (receiver_msg_precomputed, _alpha) = DefaultMtA::receiver_compute(
        &setup,
        b_bytes.as_ref(),
        &q_bytes,
        &sender_msg_for_decrypt,
        &mut OsRng,
    )
    .expect("receiver_compute setup failed");

    group.bench_function("paillier_sender_decrypt", |bench| {
        bench.iter(|| {
            DefaultMtA::sender_decrypt(
                &setup,
                &sender_state_for_decrypt,
                &q_bytes,
                &receiver_msg_precomputed,
            )
            .expect("sender_decrypt failed")
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion groups and main
// ---------------------------------------------------------------------------

criterion_group!(benches, mta_benchmarks);
criterion_main!(benches);
