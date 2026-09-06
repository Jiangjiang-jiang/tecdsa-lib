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
        drg_presign_round4_compute, verify_phase3_party, DrgPresignR1P2P, DrgPresignR4State,
    },
    sign::rounds::{
        combine_signatures, compute_contribution, verify_contribution,
        verify_contribution_equation, verify_contribution_proofs,
    },
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
            let q = tecdsa_curve::conv::curve_order::<k256::Secp256k1>();
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
    let r4s = run_drg_presign_r4(shares, setup);
    // Output phase: reconstruct delta and R from the revealed shares.
    let deltas: Vec<k256::Scalar> = r4s.iter().map(|r| r.delta_i).collect();
    let big_ds: Vec<k256::ProjectivePoint> = r4s.iter().map(|r| r.big_d_i).collect();
    r4s.iter()
        .map(|r4| drg_presign_finalize(r4, &deltas, &big_ds).unwrap())
        .collect()
}

/// Drive presign Rounds 1-4 (compute) for every party and return their
/// Round-4 states (which carry `delta_i`, `D_i`, `pi_{D_i}` and the broadcast
/// `B`-matrix needed for Phase-3 cross-verification).
fn run_drg_presign_r4(shares: &[Wmy23KeyShare], setup: &mut ClSetup) -> Vec<DrgPresignR4State> {
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

    // Round 4: CombVf/ExpVf + MtAwc receiver checks + Phase 3 revelation.
    let mut r4s = Vec::new();
    for i in 0..n {
        let (r4, _phase3) = drg_presign_round4_compute(
            &r1s[i],
            &r1b,
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

    r4s
}

fn run_sign(
    presigs: &[tecdsa_wmy23::presign::Wmy23Presignature],
    msg: k256::Scalar,
    pk: &k256::ProjectivePoint,
) -> tecdsa_protocol::Signature<k256::Secp256k1> {
    let m = DataToSign::from_digest(msg);
    let n = presigs.len();
    let mut rng = rand::thread_rng();

    // Phase 1a: every party computes its contribution (partial signature +
    // MtAwc shares-in-exponent + NIZKDL-2PC proofs).
    let contribs: Vec<_> = presigs
        .iter()
        .map(|p| compute_contribution(p, &m, &mut rng))
        .collect();

    // Phase 1b: every party verifies every contribution (NIZKDL-2PC + Eq.(3)).
    for i in 0..n {
        assert!(
            verify_contribution(&presigs[0], &m, &contribs, i),
            "WMY23 online verification failed for party {i}"
        );
    }

    // Phase 2: reconstruct s = sum_i s_i and verify the ECDSA signature.
    let sig = combine_signatures(&presigs[0], &contribs, &m, pk).unwrap();
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
                Wmy23OnlineSignMachine::new(pid, all_parties.clone(), presig, msg_data, public_key)
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
// Cheater identification in online signing (WMY23 Figs 7-9, Eq. (3)).
//
// These exercise the two-phase identification the online sign machine runs:
//   (1) NIZKDL-2PC proof checks pinpoint a party that broadcasts a malformed
//       MtAwc share-in-exponent M_{ij};
//   (2) with all M's well-formed, the Equation-(3) check pinpoints a party
//       that broadcasts an inconsistent partial signature s_i.
// ---------------------------------------------------------------------------

#[test]
fn test_wmy23_online_identifies_bad_partial_signature() {
    let shares = run_keygen(3, 3, false);
    let mut setup = ClSetup::new_secp256k1("12345").unwrap();
    let presigs = run_drg_presign(&shares, &mut setup);
    let m = DataToSign::from_digest(hash_message(b"cheater: bad s_i"));
    let mut rng = rand::thread_rng();

    let mut contribs: Vec<_> = presigs
        .iter()
        .map(|p| compute_contribution(p, &m, &mut rng))
        .collect();

    // Party 1 lies about its partial signature s_1 (no MtA share touched).
    let cheater = 1usize;
    contribs[cheater].s_i += k256::Scalar::ONE;

    // Phase 1 (proofs) must still pass for everyone: only s_i was changed.
    let proof_blamed: Vec<usize> = (0..3)
        .filter(|&i| !verify_contribution_proofs(&presigs[0], &contribs, i))
        .collect();
    assert!(
        proof_blamed.is_empty(),
        "no NIZKDL-2PC proof should fail for an s_i-only tamper, got {proof_blamed:?}"
    );

    // Phase 2 (Eq. (3)) must blame exactly the cheater.
    let eq_blamed: Vec<usize> = (0..3)
        .filter(|&i| !verify_contribution_equation(&presigs[0], &m, &contribs, i))
        .collect();
    assert_eq!(
        eq_blamed,
        vec![cheater],
        "Equation (3) must identify exactly the cheating party"
    );
}

#[test]
fn test_wmy23_online_identifies_bad_mta_share() {
    let shares = run_keygen(3, 3, false);
    let mut setup = ClSetup::new_secp256k1("12345").unwrap();
    let presigs = run_drg_presign(&shares, &mut setup);
    let m = DataToSign::from_digest(hash_message(b"cheater: bad M_ij"));
    let mut rng = rand::thread_rng();

    let mut contribs: Vec<_> = presigs
        .iter()
        .map(|p| compute_contribution(p, &m, &mut rng))
        .collect();

    // Party 2 broadcasts a malformed M_{2j} (inconsistent with its proof).
    let cheater = 2usize;
    let j = (0..3)
        .find(|&j| j != cheater && contribs[cheater].m_row[j].is_some())
        .expect("a counterparty share exists");
    let bad = contribs[cheater].m_row[j].unwrap()
        + <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR;
    contribs[cheater].m_row[j] = Some(bad);

    // Phase 1 (proofs) must blame exactly the cheater: M_{ij} is bound to it
    // by its NIZKDL-2PC proof, which now fails.
    let proof_blamed: Vec<usize> = (0..3)
        .filter(|&i| !verify_contribution_proofs(&presigs[0], &contribs, i))
        .collect();
    assert_eq!(
        proof_blamed,
        vec![cheater],
        "NIZKDL-2PC proof check must identify exactly the malformed-share party"
    );

    // The honest parties' NIZKDL-2PC proofs still verify; their Equation-(3)
    // checks may be poisoned by the cheater's malformed M (which is exactly
    // why proofs are checked first and the cheater is removed before any
    // equation is trusted).
    for i in (0..3).filter(|&i| i != cheater) {
        assert!(
            verify_contribution_proofs(&presigs[0], &contribs, i),
            "honest party {i} proofs must verify"
        );
    }
}

#[test]
fn test_wmy23_online_machine_reports_cheater() {
    use tecdsa_protocol::{IaReport, PartyId, StateMachine};
    use tecdsa_wmy23::sign::{msg::serialize_contribution, Wmy23OnlineSignMachine};

    let shares = run_keygen(3, 3, false);
    let mut setup = ClSetup::new_secp256k1("12345").unwrap();
    let presigs = run_drg_presign(&shares, &mut setup);
    let public_key = shares[0].public_key;
    let m = DataToSign::from_digest(hash_message(b"machine cheater test"));
    let all_parties: Vec<PartyId> = (1..=3u16).map(PartyId).collect();
    let mut rng = rand::thread_rng();

    // Honest machine for party P1 (local index 0).
    let mut machine = Wmy23OnlineSignMachine::new(
        PartyId(1),
        all_parties.clone(),
        // presig is consumed; clone the fields the machine needs by rebuilding.
        rebuild_presig(&presigs[0]),
        m,
        public_key,
    )
    .expect("sign machine");
    let _ = machine.drain_outgoing();

    // Party P2 (index 1) cheats on its partial signature.
    let mut bad = compute_contribution(&presigs[1], &m, &mut rng);
    bad.s_i += k256::Scalar::ONE;
    let bad_bytes = serialize_contribution(&bad).expect("serialize bad");

    // Party P3 (index 2) is honest.
    let good = compute_contribution(&presigs[2], &m, &mut rng);
    let good_bytes = serialize_contribution(&good).expect("serialize good");

    use tecdsa_wmy23::sign::msg::Wmy23SignMsg;
    machine
        .handle(PartyId(2), Wmy23SignMsg::Round5(bad_bytes))
        .expect("first message accepted");
    // The final message triggers verification, which must abort.
    let result = machine.handle(PartyId(3), Wmy23SignMsg::Round5(good_bytes));
    assert!(result.is_err(), "machine must abort on a cheating party");

    let report: &IaReport = machine.ia_report().expect("an IA report must be produced");
    assert_eq!(
        report.blamed,
        vec![PartyId(2)],
        "the IA report must blame exactly the cheating party P2"
    );
}

/// Rebuild a presignature (the type is not `Clone`; tests need a second copy
/// to feed a state machine while keeping the originals for peer messages).
fn rebuild_presig(
    p: &tecdsa_wmy23::presign::Wmy23Presignature,
) -> tecdsa_wmy23::presign::Wmy23Presignature {
    tecdsa_wmy23::presign::Wmy23Presignature {
        k_i: p.k_i,
        big_r: p.big_r,
        r_x: p.r_x,
        sigma_i: p.sigma_i,
        n_signers: p.n_signers,
        index: p.index,
        hat_k_randomness: p.hat_k_randomness,
        hat_x_i: p.hat_x_i,
        mu_shares: p.mu_shares.clone(),
        nu_points: p.nu_points.clone(),
        pc_hat_k: p.pc_hat_k.clone(),
        big_r_shares: p.big_r_shares.clone(),
        xhat_points: p.xhat_points.clone(),
    }
}

// ---------------------------------------------------------------------------
// Pre-sign Phase-3 cross-verification / cheater identification (WMY23 Fig. 5,
// Eq. (2) + pi_D). With the MtAwc material broadcast, every party verifies
// every other party's revealed pseudo-nonce share, closing the TX25 gap.
// ---------------------------------------------------------------------------

#[test]
fn test_wmy23_presign_phase3_crossverify_honest() {
    let shares = run_keygen(3, 3, false);
    let mut setup = ClSetup::new_secp256k1("12345").unwrap();
    let r4s = run_drg_presign_r4(&shares, &mut setup);

    // Every party (verifier v) accepts every party j's revealed share.
    for v in 0..3 {
        for j in 0..3 {
            assert!(
                verify_phase3_party(
                    &r4s[v],
                    j,
                    &r4s[j].delta_i,
                    &r4s[j].big_d_i,
                    &r4s[j].d_proof,
                ),
                "verifier {v} must accept honest party {j}'s Phase-3 share"
            );
        }
    }
}

#[test]
fn test_wmy23_presign_identifies_bad_delta() {
    let shares = run_keygen(3, 3, false);
    let mut setup = ClSetup::new_secp256k1("12345").unwrap();
    let r4s = run_drg_presign_r4(&shares, &mut setup);

    // Party 1 tampers its revealed delta_1 (leaves D_1 / pi_{D_1} intact):
    // Equation (2) must reject it, while honest parties still verify.
    let cheater = 1usize;
    let bad_delta = r4s[cheater].delta_i + k256::Scalar::ONE;

    let blamed: Vec<usize> = (0..3)
        .filter(|&j| {
            let delta = if j == cheater {
                bad_delta
            } else {
                r4s[j].delta_i
            };
            !verify_phase3_party(&r4s[0], j, &delta, &r4s[j].big_d_i, &r4s[j].d_proof)
        })
        .collect();
    assert_eq!(
        blamed,
        vec![cheater],
        "Equation (2) must identify exactly the party with a bad delta"
    );
}

#[test]
fn test_wmy23_presign_identifies_bad_big_d() {
    use elliptic_curve::CurveArithmetic;
    let shares = run_keygen(3, 3, false);
    let mut setup = ClSetup::new_secp256k1("12345").unwrap();
    let r4s = run_drg_presign_r4(&shares, &mut setup);

    // Party 2 tampers D_2: pi_{D_2} (R_DL-PC, base Gamma) must reject it.
    let cheater = 2usize;
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let bad_d = r4s[cheater].big_d_i + g;

    assert!(
        !verify_phase3_party(
            &r4s[0],
            cheater,
            &r4s[cheater].delta_i,
            &bad_d,
            &r4s[cheater].d_proof,
        ),
        "pi_D must reject a tampered D_i"
    );
    // Honest parties still verify.
    for j in [0usize, 1] {
        assert!(
            verify_phase3_party(
                &r4s[0],
                j,
                &r4s[j].delta_i,
                &r4s[j].big_d_i,
                &r4s[j].d_proof
            ),
            "honest party {j} must still verify"
        );
    }
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
