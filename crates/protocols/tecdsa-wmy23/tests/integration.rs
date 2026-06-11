// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 integration tests and benchmark.
//!
//! Paper: Wong, Ma, Yin, Chow. "Real Threshold ECDSA." NDSS 2023.
//! Paper benchmark: n=5, t=4, secp256k1, |Delta_q|=1860, Ryzen 7 3700X @4GHz.

#![allow(non_snake_case)]

use sha2::{Digest, Sha256};
use tecdsa_class_group::cl::ClSetup;
use tecdsa_protocol::ecdsa::{verify_ecdsa, DataToSign};
use tecdsa_wmy23::{
    key_share::Wmy23KeyShare,
    keygen::Wmy23KeygenMachine,
    presign::rounds::{
        drg_presign_finalize, drg_presign_round1, drg_presign_round2, drg_presign_round3_bob,
        drg_presign_round4_compute, DrgPresignR1P2P,
    },
    sign::rounds::{combine_signatures, compute_partial_signature},
};

fn hash_message(msg: &[u8]) -> k256::Scalar {
    use elliptic_curve::PrimeField;
    let hash = Sha256::digest(msg);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    k256::Scalar::from_repr(k256::FieldBytes::from(bytes))
        .into_option()
        .unwrap_or_else(|| {
            use rug::{integer::Order, Integer};
            let q = Integer::from_str_radix(tecdsa_class_group::cl::SECP256K1_ORDER, 10).unwrap();
            let val = Integer::from_digits(&bytes, Order::Msf) % &q;
            let mut padded = [0u8; 32];
            let offset = 32 - val.to_digits::<u8>(Order::Msf).len();
            padded[offset..].copy_from_slice(&val.to_digits::<u8>(Order::Msf));
            k256::Scalar::from_repr(k256::FieldBytes::from(padded))
                .into_option()
                .unwrap()
        })
}

/// Run keygen for `n` parties with reconstruction threshold `t`.
///
/// `t` parties are needed to sign.
fn run_keygen(n: usize, t: u16, use_128bit: bool) -> Vec<Wmy23KeyShare> {
    use tecdsa_protocol::PartyId;
    use tecdsa_testkit::Orchestrator;

    let seed = "12345";
    let all_parties: Vec<PartyId> = (1..=n as u16).map(PartyId).collect();

    let machines: Vec<(PartyId, Wmy23KeygenMachine)> = all_parties
        .iter()
        .map(|&pid| {
            (
                pid,
                Wmy23KeygenMachine::new(pid, all_parties.clone(), t, seed, use_128bit)
                    .expect("keygen machine"),
            )
        })
        .collect();

    Orchestrator::new(machines, 15)
        .run()
        .expect("keygen orchestrator")
        .outputs
        .into_iter()
        .map(|r| r.expect("keygen finish"))
        .collect()
}

fn run_drg_presign(
    shares: &[Wmy23KeyShare],
    setup: &mut ClSetup,
) -> Vec<tecdsa_wmy23::presign::Wmy23Presignature> {
    let n = shares.len();
    let t = shares[0].threshold;
    let signer_ids: Vec<u16> = (1..=n as u16).collect();
    let mut rng = rand::thread_rng();

    // Round 1: DRG.Gen for k and gamma.
    let mut r1s = Vec::new();
    let mut r1b = Vec::new();
    let mut r1p = Vec::new();
    for i in 0..n {
        let (s, b, p) =
            drg_presign_round1(i, n, t, &signer_ids, &shares[i], setup, &mut rng).unwrap();
        r1s.push(s);
        r1b.push(b);
        r1p.push(p);
    }

    // Round 2: DRG.GenVf + DRG.Comb + MtAwc Alice step 1.
    let mut r2s = Vec::new();
    let mut r2b = Vec::new();
    for i in 0..n {
        // Shares received by party i, indexed by sender.
        let received: Vec<Option<DrgPresignR1P2P>> = (0..n).map(|j| r1p[j][i].clone()).collect();
        let (s, b) =
            drg_presign_round2(&r1s[i], &r1b, &received, &signer_ids, &shares[i], setup).unwrap();
        r2s.push(s);
        r2b.push(b);
    }

    // Round 3: MtAwc Bob responses.
    let mut r3 = Vec::new();
    for i in 0..n {
        let d = drg_presign_round3_bob(
            &r2s[i],
            &r1s[i],
            &signer_ids,
            &shares[i],
            &r2b,
            setup,
            &mut rng,
        )
        .unwrap();
        r3.push(d);
    }

    // Round 4: Alice decrypt + Phase 3 share revelation.
    let r1_commitments: Vec<[u8; 32]> = r1b.iter().map(|b| b.commitment).collect();
    let mut r4s = Vec::new();
    for i in 0..n {
        let (r4, _phase3) = drg_presign_round4_compute(
            &r1s[i],
            &r1_commitments,
            &r2s[i],
            &r2b,
            &r3,
            &signer_ids,
            &shares[i],
            setup,
            &mut rng,
        )
        .unwrap();
        r4s.push(r4);
    }

    // Output phase: reconstruct delta and R from the revealed shares.
    let deltas: Vec<k256::Scalar> = r4s.iter().map(|r| r.delta_i).collect();
    let big_ds: Vec<k256::ProjectivePoint> = r4s.iter().map(|r| r.big_d_i).collect();
    r4s.iter()
        .map(|r4| drg_presign_finalize(r4, &deltas, &big_ds).unwrap())
        .collect()
}

fn run_sign(
    presigs: &[tecdsa_wmy23::presign::Wmy23Presignature],
    msg: k256::Scalar,
    pk: &k256::ProjectivePoint,
) -> tecdsa_protocol::Signature<k256::Secp256k1> {
    let m = DataToSign::from_digest(msg);
    let partials: Vec<_> = presigs
        .iter()
        .map(|p| compute_partial_signature(p, &m))
        .collect();
    let sig = combine_signatures(&partials, &presigs[0], &m, pk).unwrap();
    verify_ecdsa::<k256::Secp256k1>(&sig, pk, &m).unwrap();
    sig
}

// ---------------------------------------------------------------------------
// Correctness test (fast, insecure CL params)
// ---------------------------------------------------------------------------

#[test]
fn test_wmy23_full_sign() {
    let shares = run_keygen(3, 3, false); // reconstruction threshold=3, need 3 to sign (3-of-3)
    let mut setup = ClSetup::new_secp256k1("12345").unwrap();
    let presigs = run_drg_presign(&shares, &mut setup);
    let msg = hash_message(b"WMY23 correctness test");
    let sig = run_sign(&presigs, msg, &shares[0].public_key);
    println!("WMY23 3-of-3 sign OK: r={:?}", sig.r);
}

// ---------------------------------------------------------------------------
// Full DRG presign via the state machines, all 3 parties signing.
//
// Exercises the paper-compliant message-driven path end to end:
// keygen machines -> DRG-based presign machines (DRG.Gen/GenVf/Comb with
// Pedersen VSS + R_Enc-PC, MtAwc, share revelation) -> online sign
// machines, and verifies the final ECDSA signature against the joint
// public key.
// ---------------------------------------------------------------------------

#[test]
fn test_wmy23_machine_3party_e2e() {
    use tecdsa_protocol::PartyId;
    use tecdsa_testkit::Orchestrator;
    use tecdsa_wmy23::{
        presign::{PresignConfig, Wmy23PresignMachine},
        sign::Wmy23OnlineSignMachine,
    };

    let seed = "12345";
    let n = 3u16;
    let t = 2u16;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    // --- KeyGen via the DRG state machine ---
    let key_shares = run_keygen(n as usize, t, false);
    let public_key = key_shares[0].public_key;
    for ks in &key_shares {
        assert_eq!(ks.public_key, public_key, "parties must agree on joint PK");
    }

    // --- Presign with all 3 parties via the DRG presign machine ---
    let presign_machines: Vec<(PartyId, Wmy23PresignMachine)> = all_parties
        .iter()
        .map(|&pid| {
            let setup = ClSetup::new_secp256k1(seed).expect("cl setup");
            let config = PresignConfig {
                key_share: key_shares[(pid.0 - 1) as usize].clone(),
                my_id: pid,
                signer_parties: all_parties.clone(),
                cl_setup: setup,
            };
            (
                pid,
                Wmy23PresignMachine::new(config).expect("presign machine"),
            )
        })
        .collect();
    let presigs: Vec<_> = Orchestrator::new(presign_machines, 10)
        .run()
        .expect("presign orchestrator")
        .outputs
        .into_iter()
        .map(|r| r.expect("presign finish"))
        .collect();

    let r_x = presigs[0].r_x;
    for p in &presigs {
        assert_eq!(p.r_x, r_x, "signers must agree on r");
        assert_eq!(p.big_r, presigs[0].big_r, "signers must agree on R");
    }

    // --- Online sign with all 3 parties ---
    let msg = hash_message(b"WMY23 3-party machine e2e");
    let msg_data = DataToSign::from_digest(msg);
    let sign_machines: Vec<(PartyId, Wmy23OnlineSignMachine)> = all_parties
        .iter()
        .zip(presigs)
        .map(|(&pid, presig)| {
            (
                pid,
                Wmy23OnlineSignMachine::new(
                    pid,
                    all_parties.clone(),
                    presig,
                    msg_data,
                    public_key,
                )
                .expect("sign machine"),
            )
        })
        .collect();
    let sigs: Vec<_> = Orchestrator::new(sign_machines, 10)
        .run()
        .expect("sign orchestrator")
        .outputs
        .into_iter()
        .map(|r| r.expect("sign finish"))
        .collect();

    for sig in &sigs {
        assert_eq!(sig.r, sigs[0].r, "all signers produce the same r");
        assert_eq!(sig.s, sigs[0].s, "all signers produce the same s");
    }
    verify_ecdsa::<k256::Secp256k1>(&sigs[0], &public_key, &msg_data)
        .expect("ECDSA verification must pass for the 3-party machine run");
    println!("WMY23 3-party machine e2e OK: r={:?}", sigs[0].r);
}

// ---------------------------------------------------------------------------
// Threshold (t-of-n) subset signing via the state machines.
//
// Demonstrates that, with Feldman-VSS key shares, a strict `t` quorum can
// sign: the presign machine Lagrange-weights each signer's Shamir share for
// the active quorum (w_i = lambda_i * x_i), so the additive MtAwc machinery
// reconstructs the joint key from the subset alone.
// ---------------------------------------------------------------------------

#[test]
fn test_wmy23_threshold_subset_sign() {
    use tecdsa_class_group::cl::ClSetup;
    use tecdsa_protocol::PartyId;
    use tecdsa_testkit::Orchestrator;
    use tecdsa_wmy23::{
        keygen::Wmy23KeygenMachine,
        presign::{PresignConfig, Wmy23PresignMachine},
        sign::Wmy23OnlineSignMachine,
    };

    let seed = "12345";
    let n = 3u16;
    let reconstruction_threshold = 2u16; // t=2, 2-of-3 signing
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    // --- KeyGen via the Feldman-VSS state machine ---
    let kg_machines: Vec<(PartyId, Wmy23KeygenMachine)> = all_parties
        .iter()
        .map(|&pid| {
            (
                pid,
                Wmy23KeygenMachine::new(
                    pid,
                    all_parties.clone(),
                    reconstruction_threshold,
                    seed,
                    false,
                )
                .expect("keygen machine"),
            )
        })
        .collect();
    let key_shares: Vec<Wmy23KeyShare> = Orchestrator::new(kg_machines, 10)
        .run()
        .expect("keygen orchestrator")
        .outputs
        .into_iter()
        .map(|r| r.expect("keygen finish"))
        .collect();

    let public_key = key_shares[0].public_key;
    for ks in &key_shares {
        assert_eq!(ks.public_key, public_key, "parties must agree on joint PK");
    }
    // Shares must be distinct Shamir shares (not additive duplicates).
    assert_ne!(key_shares[0].secret_share, key_shares[1].secret_share);

    // --- Sign with the subset {1, 2} (a t=2 quorum, NOT all n) ---
    let signers = [1u16, 2];
    let signer_parties: Vec<PartyId> = signers.iter().map(|&s| PartyId(s)).collect();

    let presign_machines: Vec<(PartyId, Wmy23PresignMachine)> = signers
        .iter()
        .map(|&s| {
            let pid = PartyId(s);
            let setup = ClSetup::new_secp256k1(seed).expect("cl setup");
            let config = PresignConfig {
                key_share: key_shares[(s - 1) as usize].clone(),
                my_id: pid,
                signer_parties: signer_parties.clone(),
                cl_setup: setup,
            };
            (
                pid,
                Wmy23PresignMachine::new(config).expect("presign machine"),
            )
        })
        .collect();
    let presigs: Vec<_> = Orchestrator::new(presign_machines, 10)
        .run()
        .expect("presign orchestrator")
        .outputs
        .into_iter()
        .map(|r| r.expect("presign finish"))
        .collect();

    let r_x = presigs[0].r_x;
    for p in &presigs {
        assert_eq!(p.r_x, r_x, "signers must agree on r");
    }

    let msg = hash_message(b"WMY23 t-of-n subset test");
    let msg_data = DataToSign::from_digest(msg);

    let sign_machines: Vec<(PartyId, Wmy23OnlineSignMachine)> = signers
        .iter()
        .zip(presigs)
        .map(|(&s, presig)| {
            let pid = PartyId(s);
            (
                pid,
                Wmy23OnlineSignMachine::new(
                    pid,
                    signer_parties.clone(),
                    presig,
                    msg_data,
                    public_key,
                )
                .expect("sign machine"),
            )
        })
        .collect();
    let sigs: Vec<_> = Orchestrator::new(sign_machines, 10)
        .run()
        .expect("sign orchestrator")
        .outputs
        .into_iter()
        .map(|r| r.expect("sign finish"))
        .collect();

    for sig in &sigs {
        assert_eq!(sig.r, sigs[0].r, "all signers produce the same r");
        assert_eq!(sig.s, sigs[0].s, "all signers produce the same s");
    }
    verify_ecdsa::<k256::Secp256k1>(&sigs[0], &public_key, &msg_data)
        .expect("ECDSA verification must pass for the 2-of-3 subset");
    println!("WMY23 2-of-3 subset sign OK: r={:?}", sigs[0].r);
}

// ---------------------------------------------------------------------------
// Paper-exact benchmark: n=5, t=4, |Delta_K|=1828, full DRG
// Run: cargo test -p tecdsa-wmy23 --release bench -- --nocapture --ignored
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn bench_wmy23_paper_params() {
    use std::time::Instant;

    println!("\n=============================================");
    println!(" WMY23 Benchmark (n=5, t=4, secp256k1)");
    println!(" |Delta_K|=1828 bits, full DRG + R_Enc-PC");
    println!("=============================================\n");

    let n = 5;
    let t = 4u16; // reconstruction threshold: need 4 to sign
    let iters = 3;

    let start = Instant::now();
    let shares = run_keygen(n, t, true);
    let keygen_ms = start.elapsed().as_secs_f64() * 1000.0;

    let mut times = Vec::new();
    let mut presigs = Vec::new();
    for _ in 0..iters {
        let mut setup = ClSetup::new_secp256k1_128bit("12345").unwrap();
        let start = Instant::now();
        presigs = run_drg_presign(&shares, &mut setup);
        times.push(start.elapsed());
    }
    let presign_ms: f64 =
        times.iter().map(|t| t.as_secs_f64() * 1000.0).sum::<f64>() / iters as f64;

    let msg = hash_message(b"benchmark");
    let start = Instant::now();
    let _sig = run_sign(&presigs, msg, &shares[0].public_key);
    let sign_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Paper uses t=4 signers (12 MtA pairs), we run n=5 (20 pairs)
    let adj = presign_ms * 12.0 / 20.0;

    println!("KeyGen:     {:7.0} ms", keygen_ms);
    println!("PreSign:    {:7.0} ms  (5-of-5, 20 MtA pairs)", presign_ms);
    println!("  adj 4-of-5: {:5.0} ms  (12 pairs, estimated)", adj);
    println!("OnlineSign: {:7.1} ms", sign_ms);
    println!();
    println!("Paper:      {:7.0} ms  (4-of-5, Ryzen 7 3700X)", 3874.0);
    println!("Ratio:       {:5.2}x  (adj/paper)", adj / 3874.0);
    println!("=============================================");
}
