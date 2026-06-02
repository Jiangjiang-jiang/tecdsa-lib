// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the DKLs23 signing protocol.
//!
//! Tests keygen -> presign -> online_sign -> ECDSA verify end-to-end,
//! using real OT-based RVOLE for the secure multiplication.

#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, PrimeField};
use sha2::{Digest as _, Sha256};
use tecdsa_protocol::{verify_ecdsa, DataToSign, PartyId};
use tecdsa_testkit::Orchestrator;

use tecdsa_dkls23::key_share::Dkls23KeyShare;
use tecdsa_dkls23::keygen::Dkls23KeygenMachine;
use tecdsa_dkls23::presign::{Dkls23PresignMachine, PresignConfig};
use tecdsa_dkls23::sign::{Dkls23OnlineSignMachine, OnlineSignConfig};

type C = k256::Secp256k1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run keygen to produce key shares for n parties with corruption threshold t.
///
/// `corrupted_t` = max number of corrupted parties tolerated.
/// Reconstruction requires `corrupted_t + 1` parties.
fn run_keygen(n: u16, corrupted_t: u16) -> Vec<Dkls23KeyShare<C>> {
    let mut rng = rand::thread_rng();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    let reconstruction_threshold = corrupted_t + 1;

    let machines: Vec<(PartyId, Dkls23KeygenMachine<C>)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Dkls23KeygenMachine::new(
                pid,
                all_parties.clone(),
                reconstruction_threshold,
                &mut rng,
            );
            (pid, machine)
        })
        .collect();

    let results = Orchestrator::new(machines, 10)
        .run()
        .expect("orchestrator must succeed");
    results
        .into_iter()
        .map(|r| r.expect("keygen should succeed"))
        .collect()
}

/// Prepare a message digest for signing.
fn test_message_digest(msg: &[u8]) -> DataToSign<C> {
    let hash = Sha256::digest(msg);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    let scalar = <C as elliptic_curve::CurveArithmetic>::Scalar::from_repr(
        elliptic_curve::FieldBytes::<C>::from(bytes),
    )
    .expect("hash must be valid scalar");
    DataToSign::from_digest(scalar)
}

/// Run the presigning protocol for the given signing subset.
///
/// Uses real OT-based RVOLE from `tecdsa-ot::rvole` -- no ideal RVOLE.
fn run_presign(
    shares: &[Dkls23KeyShare<C>],
    signer_indices: &[u16],
) -> Vec<tecdsa_dkls23::presign::Dkls23Presignature<C>> {
    let signer_parties: Vec<PartyId> = signer_indices.iter().map(|&i| PartyId(i)).collect();

    // Build PresignConfig for each party (no pre-computed RVOLE needed)
    let mut machines: Vec<(PartyId, Dkls23PresignMachine<C>)> = Vec::new();

    for &idx in signer_indices {
        let share = shares[(idx - 1) as usize].clone();
        let pid = PartyId(idx);

        let config = PresignConfig {
            key_share: share,
            my_id: pid,
            signer_parties: signer_parties.clone(),
        };

        machines.push((pid, Dkls23PresignMachine::new(config, rand_core::OsRng)));
    }

    // Run the protocol through the orchestrator
    let results = Orchestrator::new(machines, 20)
        .run()
        .expect("orchestrator must succeed");
    results
        .into_iter()
        .map(|r| r.expect("presign should succeed"))
        .collect()
}

/// Run the online signing protocol.
fn run_online_sign(
    presignatures: Vec<tecdsa_dkls23::presign::Dkls23Presignature<C>>,
    message: DataToSign<C>,
) -> tecdsa_protocol::Signature<C> {
    let machines: Vec<(PartyId, Dkls23OnlineSignMachine<C>)> = presignatures
        .into_iter()
        .map(|presig| {
            let pid = presig.my_id;
            let config = OnlineSignConfig {
                presignature: presig,
                message,
            };
            (pid, Dkls23OnlineSignMachine::new(config))
        })
        .collect();

    let results = Orchestrator::new(machines, 10)
        .run()
        .expect("orchestrator must succeed");
    let sigs: Vec<_> = results
        .into_iter()
        .map(|r| r.expect("online sign should succeed"))
        .collect();

    // All parties should produce the same signature
    for i in 1..sigs.len() {
        assert_eq!(sigs[i].r, sigs[0].r, "all signers must agree on r");
        assert_eq!(sigs[i].s, sigs[0].s, "all signers must agree on s");
    }

    sigs.into_iter().next().unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_dkls23_full_sign_2_of_3() {
    // 1. Run keygen (3 parties, corruption threshold=1, need 2 to sign)
    let shares = run_keygen(3, 1);

    // Verify keygen produced correct shares
    let pk0_bytes = shares[0].public_key.to_bytes();
    for share in &shares {
        assert_eq!(
            share.public_key.to_bytes(),
            pk0_bytes,
            "all parties must agree on public key"
        );
    }

    // 2. Choose signing subset (parties 1, 2)
    let signer_indices = &[1u16, 2];

    // 3. Run presign (3 rounds with real RVOLE)
    let presigs = run_presign(&shares, signer_indices);
    assert_eq!(presigs.len(), 2);

    // Verify presignatures agree on R and r_x
    assert_eq!(
        presigs[0].R.to_bytes(),
        presigs[1].R.to_bytes(),
        "all parties must agree on R"
    );
    assert_eq!(
        presigs[0].r_x, presigs[1].r_x,
        "all parties must agree on r_x"
    );

    // 4. Run online sign (1 round)
    let message = test_message_digest(b"hello world");
    let sig = run_online_sign(presigs, message);

    // 5. Verify ECDSA signature
    verify_ecdsa::<C>(&sig, &shares[0].public_key, &message).expect("DKLs23 signature must verify");
}

#[test]
fn test_dkls23_full_sign_3_of_5() {
    // 1. Run keygen (5 parties, corruption threshold=2, need 3 to sign)
    let shares = run_keygen(5, 2);

    // 2. Choose signing subset (parties 1, 3, 5)
    let signer_indices = &[1u16, 3, 5];

    // 3. Run presign
    let presigs = run_presign(&shares, signer_indices);
    assert_eq!(presigs.len(), 3);

    // Verify presignatures agree on R and r_x
    for i in 1..presigs.len() {
        assert_eq!(
            presigs[i].R.to_bytes(),
            presigs[0].R.to_bytes(),
            "all parties must agree on R"
        );
        assert_eq!(
            presigs[i].r_x, presigs[0].r_x,
            "all parties must agree on r_x"
        );
    }

    // 4. Run online sign
    let message = test_message_digest(b"DKLs23 threshold ECDSA");
    let sig = run_online_sign(presigs, message);

    // 5. Verify ECDSA signature
    verify_ecdsa::<C>(&sig, &shares[0].public_key, &message)
        .expect("DKLs23 3-of-5 signature must verify");
}

#[test]
fn test_dkls23_different_signer_subsets() {
    // Verify that different subsets of parties can sign independently
    let shares = run_keygen(3, 1); // corruption threshold=1, need 2 to sign
    let message = test_message_digest(b"different subsets");

    // Sign with parties {1, 2}
    let presigs_12 = run_presign(&shares, &[1, 2]);
    let sig_12 = run_online_sign(presigs_12, message);
    verify_ecdsa::<C>(&sig_12, &shares[0].public_key, &message)
        .expect("signature from {1,2} must verify");

    // Sign with parties {2, 3}
    let presigs_23 = run_presign(&shares, &[2, 3]);
    let sig_23 = run_online_sign(presigs_23, message);
    verify_ecdsa::<C>(&sig_23, &shares[0].public_key, &message)
        .expect("signature from {2,3} must verify");

    // Sign with parties {1, 3}
    let presigs_13 = run_presign(&shares, &[1, 3]);
    let sig_13 = run_online_sign(presigs_13, message);
    verify_ecdsa::<C>(&sig_13, &shares[0].public_key, &message)
        .expect("signature from {1,3} must verify");
}

#[test]
fn test_dkls23_different_messages() {
    // Verify that the same keygen can sign different messages
    let shares = run_keygen(3, 1); // corruption threshold=1, need 2 to sign
    let signer_indices = &[1u16, 2];

    let msg1 = test_message_digest(b"message one");
    let msg2 = test_message_digest(b"message two");

    // Two independent presign sessions
    let presigs1 = run_presign(&shares, signer_indices);
    let presigs2 = run_presign(&shares, signer_indices);

    let sig1 = run_online_sign(presigs1, msg1);
    let sig2 = run_online_sign(presigs2, msg2);

    verify_ecdsa::<C>(&sig1, &shares[0].public_key, &msg1).expect("sig1 must verify");
    verify_ecdsa::<C>(&sig2, &shares[0].public_key, &msg2).expect("sig2 must verify");
}

#[test]
fn test_dkls23_2_of_2() {
    // Minimal threshold case: 2-of-2 (corruption threshold=1)
    let shares = run_keygen(2, 1);
    let message = test_message_digest(b"2-of-2 signing");

    let presigs = run_presign(&shares, &[1, 2]);
    let sig = run_online_sign(presigs, message);

    verify_ecdsa::<C>(&sig, &shares[0].public_key, &message).expect("2-of-2 signature must verify");
}

// ---------------------------------------------------------------------------
// Timing benchmark (run with: cargo test -p tecdsa-dkls23 bench_timing -- --nocapture --ignored)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn bench_timing_dkls23() {
    use std::time::Instant;

    let configs: Vec<(u16, u16, &[u16])> = vec![
        (2, 1, &[1, 2]),          // 2-of-2 (corruption t=1)
        (3, 1, &[1, 2]),          // 2-of-3 (corruption t=1)
        (3, 2, &[1, 2, 3]),       // 3-of-3 (corruption t=2)
        (5, 2, &[1, 3, 5]),       // 3-of-5 (corruption t=2)
        (5, 4, &[1, 2, 3, 4, 5]), // 5-of-5 (corruption t=4)
    ];
    let warmup = 2;
    let iterations = 5;

    println!("\n========================================");
    println!(" DKLs23 Timing Benchmark (secp256k1)");
    println!("========================================\n");

    for (n, t, signers) in &configs {
        // --- KeyGen ---
        let mut keygen_times = Vec::new();
        let mut shares = Vec::new();
        for i in 0..(warmup + iterations) {
            let start = Instant::now();
            let s = run_keygen(*n, *t);
            let elapsed = start.elapsed();
            if i >= warmup {
                keygen_times.push(elapsed);
            }
            shares = s;
        }

        // --- Presign ---
        let mut presign_times = Vec::new();
        let mut presigs = Vec::new();
        for i in 0..(warmup + iterations) {
            let start = Instant::now();
            let p = run_presign(&shares, signers);
            let elapsed = start.elapsed();
            if i >= warmup {
                presign_times.push(elapsed);
            }
            presigs = p; // keep last iteration for sign benchmark
        }
        let _ = &presigs; // suppress unused-value warning

        // --- OnlineSign ---
        let message = test_message_digest(b"benchmark message");
        let mut sign_times = Vec::new();
        for i in 0..(warmup + iterations) {
            let p = run_presign(&shares, signers);
            let start = Instant::now();
            let sig = run_online_sign(p, message);
            let elapsed = start.elapsed();
            if i >= warmup {
                sign_times.push(elapsed);
            }
            verify_ecdsa::<C>(&sig, &shares[0].public_key, &message)
                .expect("benchmark signature must verify");
        }

        let avg = |times: &[std::time::Duration]| -> f64 {
            times.iter().map(|d| d.as_secs_f64() * 1000.0).sum::<f64>() / times.len() as f64
        };

        let keygen_ms = avg(&keygen_times);
        let presign_ms = avg(&presign_times);
        let sign_ms = avg(&sign_times);
        let total_ms = presign_ms + sign_ms;

        println!("({t}-of-{n}, {t} signers):");
        println!("  KeyGen:     {keygen_ms:8.2} ms");
        println!("  Presign:    {presign_ms:8.2} ms  (3 rounds, real RVOLE)");
        println!("  OnlineSign: {sign_ms:8.2} ms  (1 round)");
        println!("  Total Sign: {total_ms:8.2} ms");
        println!();
    }
    println!("========================================");
    println!("Note: single-threaded, in-memory orchestrator, no network latency.");
    println!("Paper reports computation-only times on secp256k1.");
}
