// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    non_snake_case
)]

//! End-to-end integration tests for JTX25 threshold ECDSA.
//!
//! Tests: keygen -> presign -> online sign -> verify.
//! Robust tests require `--features robust`.

use elliptic_curve::CurveArithmetic;
use tecdsa_class_group::cl::{ClSetup, Qfi};
use tecdsa_jtx25::{key_share::Jtx25KeyShare, keygen::Jtx25KeygenMachine};
use tecdsa_protocol::PartyId;

// ---------------------------------------------------------------------------
// Helper: run keygen state machine
// ---------------------------------------------------------------------------

/// Run keygen for `n` parties with corruption threshold `corrupted_t`.
///
/// Reconstruction requires `corrupted_t + 1` parties.
fn run_keygen(n: usize, corrupted_t: u16) -> Vec<Jtx25KeyShare> {
    let seed = "50001";
    let parties: Vec<PartyId> = (0..n as u16).map(PartyId).collect();
    let reconstruction_threshold = corrupted_t + 1;

    let machines: Vec<(PartyId, Jtx25KeygenMachine)> = parties
        .iter()
        .map(|&pid| {
            let machine = Jtx25KeygenMachine::new(
                pid,
                parties.clone(),
                reconstruction_threshold,
                seed,
                false,
            )
            .unwrap_or_else(|e| panic!("keygen new() failed for party {pid}: {e}"));
            (pid, machine)
        })
        .collect();

    let orchestrator = tecdsa_testkit::Orchestrator::new(machines, 10);
    let results = orchestrator.run().expect("orchestrator must succeed");

    results
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.unwrap_or_else(|e| panic!("party {i} keygen finish() failed: {e}")))
        .collect()
}

// ---------------------------------------------------------------------------
// Helper: set up threshold CL keys for the key shares
// ---------------------------------------------------------------------------

/// Given keygen outputs (which have individual CL keys), replace the CL key
/// material with proper threshold CL key shares.
///
/// This implements the "trusted setup" approach: generate a master CL keypair,
/// share the secret key using delta-scaled Shamir, and distribute the shares.
fn setup_threshold_cl_keys(shares: &mut [Jtx25KeyShare], seed: &str) {
    let n = shares.len();
    let t = shares[0].threshold as usize;

    let mut setup = ClSetup::new_secp256k1(seed).expect("ClSetup");

    // Generate master CL keypair.
    let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
    let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_to_bytes");

    // Share the secret key using delta-scaled Shamir.
    let sk_shares = tecdsa_jtx25::keygen::shamir_share_delta(&mut setup, &sk_bytes, n, t)
        .expect("shamir_share_delta");

    // Compute per-party public key shares: pk_i = h^{sk_i}.
    let mut pk_share_qfis: Vec<Qfi> = Vec::with_capacity(n);
    for share in &sk_shares {
        // For negative shares (which can happen with random coefficients),
        // we need to handle the sign properly.
        // The share is a signed integer string. We need to compute h^share.
        // If share is negative, h^share = (h^|share|)^{-1}.
        // share bytes are unsigned big-endian; compute h^share directly.
        let pk_share = setup.power_of_h_bytes(share).expect("power_of_h");
        pk_share_qfis.push(pk_share);
    }

    // Update each key share with the threshold CL material.
    for (i, share) in shares.iter_mut().enumerate() {
        share.cl_sk_share = sk_shares[i].clone();
        share.cl_pk = setup.pk_from_qfi(&pk_raw.elt()).expect("pk_from_qfi");
        share.cl_pk_shares = pk_share_qfis.iter().map(|qfi| qfi.clone()).collect();
        share.n_parties_dkg = n;
    }
}

// ---------------------------------------------------------------------------
// Helper: run Robust presign state machine
// ---------------------------------------------------------------------------

#[cfg(feature = "robust")]
use tecdsa_jtx25::presign::robust::{Jtx25RobustPresignMachine, Jtx25RobustPresignature};
#[cfg(feature = "robust")]
use tecdsa_jtx25::sign::robust::Jtx25RobustOnlineSignMachine;

#[cfg(feature = "robust")]
fn run_robust_presign(
    key_shares: &[Jtx25KeyShare],
    signer_indices: &[usize],
) -> Vec<Jtx25RobustPresignature> {
    let seed = &key_shares[0].cl_setup_seed;
    let signer_parties: Vec<PartyId> = signer_indices
        .iter()
        .map(|&i| PartyId(key_shares[i].party_index - 1))
        .collect();

    let mut machines: Vec<(PartyId, Jtx25RobustPresignMachine)> = Vec::new();

    for &idx in signer_indices {
        let share = &key_shares[idx];
        let pid = PartyId(share.party_index - 1);
        let setup = if share.use_128bit_security {
            ClSetup::new_secp256k1_128bit(seed).expect("ClSetup 128")
        } else {
            ClSetup::new_secp256k1(seed).expect("ClSetup")
        };

        let machine = Jtx25RobustPresignMachine::new(pid, signer_parties.clone(), share, setup)
            .unwrap_or_else(|e| {
                panic!("presign new() failed for party {}: {e}", share.party_index)
            });

        machines.push((pid, machine));
    }

    let orchestrator = tecdsa_testkit::Orchestrator::new(machines, 10);
    let results = orchestrator.run().expect("orchestrator must succeed");

    results
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            r.unwrap_or_else(|e| panic!("party {} presign finish() failed: {e}", signer_indices[i]))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helper: run Robust online sign state machine
// ---------------------------------------------------------------------------

#[cfg(feature = "robust")]
fn run_robust_online_sign(
    key_shares: &[Jtx25KeyShare],
    presignatures: Vec<Jtx25RobustPresignature>,
    signer_indices: &[usize],
    message: &[u8],
) -> Vec<tecdsa_protocol::Signature<k256::Secp256k1>> {
    let signer_parties: Vec<PartyId> = signer_indices
        .iter()
        .map(|&i| PartyId(key_shares[i].party_index - 1))
        .collect();
    let public_key = key_shares[0].public_key;

    let mut machines: Vec<(PartyId, Jtx25RobustOnlineSignMachine)> = Vec::new();

    for (pi, presig) in presignatures.into_iter().enumerate() {
        let idx = signer_indices[pi];
        let pid = PartyId(key_shares[idx].party_index - 1);

        let machine = Jtx25RobustOnlineSignMachine::new(
            pid,
            signer_parties.clone(),
            presig,
            message,
            public_key,
        )
        .unwrap_or_else(|e| {
            panic!(
                "online_sign new() failed for party {}: {e}",
                key_shares[idx].party_index
            )
        });

        machines.push((pid, machine));
    }

    let orchestrator = tecdsa_testkit::Orchestrator::new(machines, 10);
    let results = orchestrator.run().expect("orchestrator must succeed");

    results
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            r.unwrap_or_else(|e| panic!("party {} sign finish() failed: {e}", signer_indices[i]))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_keygen_5_of_2() {
    let shares = run_keygen(5, 1); // corruption threshold=1, need 2 to reconstruct

    // All parties agree on joint public key.
    let pk0 = shares[0].public_key;
    for share in &shares[1..] {
        assert_eq!(
            pk0, share.public_key,
            "all parties must agree on the joint PK"
        );
    }

    // Each party has a distinct secret share.
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            assert_ne!(
                shares[i].secret_share, shares[j].secret_share,
                "parties {} and {} should have distinct secret shares",
                i, j
            );
        }
    }

    // Verify public_shares[i] = secret_share_i * G.
    for share in &shares {
        let expected =
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * share.secret_share;
        let my_idx = (share.party_index - 1) as usize;
        assert_eq!(
            share.public_shares[my_idx], expected,
            "public_share should match secret_share * G for party {}",
            share.party_index
        );
    }

    // Verify Lagrange reconstruction.
    let indices: Vec<u16> = (1..=5).collect();
    let lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
    let reconstructed_pk = shares[0].public_shares.iter().zip(lambdas.iter()).fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, (x_j, l_j)| acc + *x_j * l_j,
    );
    assert_eq!(
        pk0, reconstructed_pk,
        "Lagrange reconstruction must match joint PK"
    );
}

#[test]
fn test_keygen_3_of_2() {
    let shares = run_keygen(3, 1); // corruption threshold=1, need 2 to reconstruct

    let pk0 = shares[0].public_key;
    for share in &shares[1..] {
        assert_eq!(pk0, share.public_key);
    }

    // Subset reconstruction with 2 out of 3.
    let subset: Vec<u16> = vec![1, 3];
    let lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&subset);
    let subset_shares: Vec<k256::ProjectivePoint> = subset
        .iter()
        .map(|&i| shares[0].public_shares[(i - 1) as usize])
        .collect();
    let subset_pk = subset_shares.iter().zip(lambdas.iter()).fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, (x_j, l_j)| acc + *x_j * l_j,
    );
    assert_eq!(pk0, subset_pk, "subset reconstruction must match");
}

#[test]
#[cfg(feature = "robust")]
fn test_robust_full_protocol() {
    let n = 5;
    let corrupted_t = 1u16; // corruption threshold
    let seed = "50001";

    let mut key_shares = run_keygen(n, corrupted_t);
    setup_threshold_cl_keys(&mut key_shares, seed);

    let signer_indices: Vec<usize> = (0..n).collect();
    let presignatures = run_robust_presign(&key_shares, &signer_indices);

    let r0 = presignatures[0].r_point;
    let rx0 = presignatures[0].r_x;
    for presig in &presignatures[1..] {
        assert_eq!(r0, presig.r_point, "all presignatures must agree on R");
        assert_eq!(rx0, presig.r_x, "all presignatures must agree on r_x");
    }

    let message = b"Hello JTX25 threshold ECDSA!";
    let signatures = run_robust_online_sign(&key_shares, presignatures, &signer_indices, message);

    // All parties produce the same signature.
    let sig0 = &signatures[0];
    for sig in &signatures[1..] {
        assert_eq!(sig0.r, sig.r, "r values must match");
        assert_eq!(sig0.s, sig.s, "s values must match");
    }

    // Verify the signature independently.
    let public_key = key_shares[0].public_key;
    let m = {
        use elliptic_curve::PrimeField;
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(message).into();
        let mut repr = k256::FieldBytes::default();
        repr.copy_from_slice(&hash);
        if let Some(s) = Option::from(k256::Scalar::from_repr(repr)) {
            s
        } else {
            let mut repr2 = repr;
            repr2[0] &= 0x7F;
            Option::from(k256::Scalar::from_repr(repr2)).expect("scalar")
        }
    };
    let msg_data = tecdsa_protocol::ecdsa::DataToSign::from_digest(m);
    tecdsa_protocol::ecdsa::verify_ecdsa::<k256::Secp256k1>(sig0, &public_key, &msg_data)
        .expect("ECDSA signature verification must pass");
}

#[test]
#[cfg(feature = "robust")]
fn test_robust_threshold_subset_signing() {
    let n = 5;
    let corrupted_t = 1u16; // corruption threshold
    let seed = "50002";

    let mut key_shares = run_keygen(n, corrupted_t);
    setup_threshold_cl_keys(&mut key_shares, seed);

    let signer_indices = vec![0, 2, 4];
    let presignatures = run_robust_presign(&key_shares, &signer_indices);

    let message = b"threshold subset signing test";
    let signatures = run_robust_online_sign(&key_shares, presignatures, &signer_indices, message);

    // All parties produce the same signature.
    let sig0 = &signatures[0];
    for sig in &signatures[1..] {
        assert_eq!(sig0.r, sig.r);
        assert_eq!(sig0.s, sig.s);
    }

    // Verify against the joint public key.
    let public_key = key_shares[0].public_key;
    let m = {
        use elliptic_curve::PrimeField;
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(message).into();
        let mut repr = k256::FieldBytes::default();
        repr.copy_from_slice(&hash);
        if let Some(s) = Option::from(k256::Scalar::from_repr(repr)) {
            s
        } else {
            let mut repr2 = repr;
            repr2[0] &= 0x7F;
            Option::from(k256::Scalar::from_repr(repr2)).expect("scalar")
        }
    };
    let msg_data = tecdsa_protocol::ecdsa::DataToSign::from_digest(m);
    tecdsa_protocol::ecdsa::verify_ecdsa::<k256::Secp256k1>(sig0, &public_key, &msg_data)
        .expect("ECDSA verification must pass for threshold subset");
}

// ===========================================================================
// Default (Normal) tests
// ===========================================================================

use tecdsa_jtx25::{
    presign::{Jtx25PresignMachine, Jtx25Presignature},
    sign::Jtx25OnlineSignMachine,
};

fn run_presign(key_shares: &[Jtx25KeyShare], signer_indices: &[usize]) -> Vec<Jtx25Presignature> {
    let seed = &key_shares[0].cl_setup_seed;
    let signer_parties: Vec<PartyId> = signer_indices
        .iter()
        .map(|&i| PartyId(key_shares[i].party_index - 1))
        .collect();

    let mut machines: Vec<(PartyId, Jtx25PresignMachine)> = Vec::new();

    for &idx in signer_indices {
        let share = &key_shares[idx];
        let pid = PartyId(share.party_index - 1);
        let setup = if share.use_128bit_security {
            ClSetup::new_secp256k1_128bit(seed).expect("ClSetup 128")
        } else {
            ClSetup::new_secp256k1(seed).expect("ClSetup")
        };

        let machine = Jtx25PresignMachine::new(pid, signer_parties.clone(), share, setup)
            .unwrap_or_else(|e| {
                panic!("presign new() failed for party {}: {e}", share.party_index)
            });

        machines.push((pid, machine));
    }

    let orchestrator = tecdsa_testkit::Orchestrator::new(machines, 10);
    let results = orchestrator.run().expect("orchestrator must succeed");

    results
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            r.unwrap_or_else(|e| panic!("party {} presign finish() failed: {e}", signer_indices[i]))
        })
        .collect()
}

fn run_online_sign(
    key_shares: &[Jtx25KeyShare],
    presignatures: Vec<Jtx25Presignature>,
    signer_indices: &[usize],
    message: &[u8],
) -> Vec<tecdsa_protocol::Signature<k256::Secp256k1>> {
    let signer_parties: Vec<PartyId> = signer_indices
        .iter()
        .map(|&i| PartyId(key_shares[i].party_index - 1))
        .collect();
    let public_key = key_shares[0].public_key;

    let mut machines: Vec<(PartyId, Jtx25OnlineSignMachine)> = Vec::new();

    for (pi, presig) in presignatures.into_iter().enumerate() {
        let idx = signer_indices[pi];
        let pid = PartyId(key_shares[idx].party_index - 1);

        let machine =
            Jtx25OnlineSignMachine::new(pid, signer_parties.clone(), presig, message, public_key)
                .unwrap_or_else(|e| {
                    panic!(
                        "online_sign new() failed for party {}: {e}",
                        key_shares[idx].party_index
                    )
                });

        machines.push((pid, machine));
    }

    let orchestrator = tecdsa_testkit::Orchestrator::new(machines, 10);
    let results = orchestrator.run().expect("orchestrator must succeed");

    results
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            r.unwrap_or_else(|e| {
                panic!(
                    "party {} normal sign finish() failed: {e}",
                    signer_indices[i]
                )
            })
        })
        .collect()
}

#[test]
fn test_full_protocol() {
    let n = 5;
    let corrupted_t = 1u16; // corruption threshold
    let seed = "60001";

    let mut key_shares = run_keygen(n, corrupted_t);
    setup_threshold_cl_keys(&mut key_shares, seed);

    let signer_indices: Vec<usize> = (0..n).collect();
    let presignatures = run_presign(&key_shares, &signer_indices);

    let r0 = presignatures[0].r_point;
    let rx0 = presignatures[0].r_x;
    for presig in &presignatures[1..] {
        assert_eq!(r0, presig.r_point, "all presignatures must agree on R");
        assert_eq!(rx0, presig.r_x, "all presignatures must agree on r_x");
    }

    let message = b"Hello JTX25-Normal threshold ECDSA!";
    let signatures = run_online_sign(&key_shares, presignatures, &signer_indices, message);

    let sig0 = &signatures[0];
    for sig in &signatures[1..] {
        assert_eq!(sig0.r, sig.r, "r values must match");
        assert_eq!(sig0.s, sig.s, "s values must match");
    }

    let public_key = key_shares[0].public_key;
    let m = {
        use elliptic_curve::PrimeField;
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(message).into();
        let mut repr = k256::FieldBytes::default();
        repr.copy_from_slice(&hash);
        if let Some(s) = Option::from(k256::Scalar::from_repr(repr)) {
            s
        } else {
            let mut repr2 = repr;
            repr2[0] &= 0x7F;
            Option::from(k256::Scalar::from_repr(repr2)).expect("scalar")
        }
    };
    let msg_data = tecdsa_protocol::ecdsa::DataToSign::from_digest(m);
    tecdsa_protocol::ecdsa::verify_ecdsa::<k256::Secp256k1>(sig0, &public_key, &msg_data)
        .expect("ECDSA signature verification must pass for default variant");
}

#[test]
fn test_threshold_subset_signing() {
    let n = 5;
    let corrupted_t = 1u16; // corruption threshold
    let seed = "60002";

    let mut key_shares = run_keygen(n, corrupted_t);
    setup_threshold_cl_keys(&mut key_shares, seed);

    let signer_indices = vec![0, 2, 4];
    let presignatures = run_presign(&key_shares, &signer_indices);

    let message = b"threshold subset signing test";
    let signatures = run_online_sign(&key_shares, presignatures, &signer_indices, message);

    let sig0 = &signatures[0];
    for sig in &signatures[1..] {
        assert_eq!(sig0.r, sig.r);
        assert_eq!(sig0.s, sig.s);
    }

    let public_key = key_shares[0].public_key;
    let m = {
        use elliptic_curve::PrimeField;
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(message).into();
        let mut repr = k256::FieldBytes::default();
        repr.copy_from_slice(&hash);
        if let Some(s) = Option::from(k256::Scalar::from_repr(repr)) {
            s
        } else {
            let mut repr2 = repr;
            repr2[0] &= 0x7F;
            Option::from(k256::Scalar::from_repr(repr2)).expect("scalar")
        }
    };
    let msg_data = tecdsa_protocol::ecdsa::DataToSign::from_digest(m);
    tecdsa_protocol::ecdsa::verify_ecdsa::<k256::Secp256k1>(sig0, &public_key, &msg_data)
        .expect("ECDSA verification must pass for threshold subset");
}

// ===========================================================================
// CL homomorphic math test
// ===========================================================================

/// Minimal inline test to verify the CL homomorphic math.
#[test]
fn test_cl_homomorphic_math() {
    use num_bigint::BigUint;
    use tecdsa_class_group::{cl::ClSetup, t_cl};

    let seed = "70001";
    let mut setup = ClSetup::new_secp256k1(seed).unwrap();
    let (sk_raw, pk_raw) = setup.keygen().unwrap();
    let sk_bytes = setup.sk_to_bytes(&sk_raw).unwrap();

    let n = 3usize;
    let t = 2usize;

    // Share the SK for threshold decryption.
    let sk_shares = tecdsa_jtx25::keygen::shamir_share_delta(&mut setup, &sk_bytes, n, t).unwrap();

    // Sample phi and k as small test values.
    let phi = "7";
    let k = "11";
    let m_val = "13";
    let _x = "17";
    let _r_x = "19"; // dummy r_x for test

    // Encrypt phi under pk.
    let ct_phi = setup.encrypt(&pk_raw, phi).unwrap();

    // Scalar multiply by k: ct_phi_k = ct_phi^k
    let (c1_phi, c2_phi) = setup.ct_components(&ct_phi).unwrap();
    let c1_k = setup.exp(&c1_phi, k).unwrap();
    let c2_k = setup.exp(&c2_phi, k).unwrap();
    let ct_phi_k = setup.ct_from_components(&c1_k, &c2_k).unwrap();

    // Partial decrypt ct_phi_k using threshold CL.
    let pd1 = t_cl::partial_decrypt(&setup, &ct_phi_k, 1, &sk_shares[0]).unwrap();
    let pd2 = t_cl::partial_decrypt(&setup, &ct_phi_k, 2, &sk_shares[1]).unwrap();
    let p0 = t_cl::final_decrypt(&setup, &ct_phi_k, n, &[pd1, pd2]).unwrap();

    let p0_bu = BigUint::from_bytes_be(&p0);
    eprintln!(
        "[test_cl_homo] p0 (should be phi*k=77) = {}",
        p0_bu.to_str_radix(10)
    );

    // Also test addition: Enc(phi*m) = Enc(phi)^m
    let (c1_m, c2_m) = (
        setup.exp(&c1_phi, m_val).unwrap(),
        setup.exp(&c2_phi, m_val).unwrap(),
    );
    // Enc(phi*x*r_x)
    let xr = "323"; // 17 * 19
    let (c1_xr, c2_xr) = (
        setup.exp(&c1_phi, xr).unwrap(),
        setup.exp(&c2_phi, xr).unwrap(),
    );

    // Add: Enc(phi*m + phi*x*r_x) = Enc(phi*(m + x*r_x))
    let c1_sum = setup.compose(&c1_m, &c1_xr).unwrap();
    let c2_sum = setup.compose(&c2_m, &c2_xr).unwrap();
    let ct_sum = setup.ct_from_components(&c1_sum, &c2_sum).unwrap();

    let pd1_sum = t_cl::partial_decrypt(&setup, &ct_sum, 1, &sk_shares[0]).unwrap();
    let pd2_sum = t_cl::partial_decrypt(&setup, &ct_sum, 2, &sk_shares[1]).unwrap();
    let p1 = t_cl::final_decrypt(&setup, &ct_sum, n, &[pd1_sum, pd2_sum]).unwrap();

    // Expected: phi * (m + x * r_x) = 7 * (13 + 17*19) = 7 * (13 + 323) = 7 * 336 = 2352
    let p1_bu = BigUint::from_bytes_be(&p1);
    eprintln!(
        "[test_cl_homo] p1 (should be 2352) = {}",
        p1_bu.to_str_radix(10)
    );

    // s = p1 / p0 mod q = 2352 / 77 mod q
    let q_bytes = setup.q_bytes().unwrap();
    let q = BigUint::from_bytes_be(&q_bytes);
    let q_minus_2 = &q - BigUint::from(2u32);
    let p0_inv = p0_bu.modpow(&q_minus_2, &q);
    let s = (&p1_bu * &p0_inv) % &q;

    // Expected: 2352 / 77 = 2352 * 77^(-1) mod q
    // 2352 / 77 = 30.545... but mod q: 77^{-1} mod q * 2352 mod q
    // Actually 2352 = 77 * 30 + 42, so 2352/77 != integer.
    // Wait: phi*k = 7*11 = 77, phi*(m+x*r) = 7*(13+323) = 7*336 = 2352
    // s = 2352/77 = (m+x*r)/k = (13+323)/11 = 336/11 = 30.545...
    // This is NOT an integer! So s mod q = 336 * 11^(-1) mod q.
    eprintln!("[test_cl_homo] s = {}", s.to_str_radix(10));

    // The correct s should be: (m + x * r_x) * k^{-1} mod q
    let m_bu = BigUint::from(13u32);
    let x_bu = BigUint::from(17u32);
    let rx_bu = BigUint::from(19u32);
    let k_bu = BigUint::from(11u32);
    let k_inv = k_bu.modpow(&q_minus_2, &q);
    let expected_s = ((&m_bu + &x_bu * &rx_bu) * &k_inv) % &q;
    eprintln!(
        "[test_cl_homo] expected s = {}",
        expected_s.to_str_radix(10)
    );

    assert_eq!(s, expected_s, "s must match expected");
    assert_eq!(p0_bu, BigUint::from(77u32), "p0 must be phi*k = 77");
    assert_eq!(
        p1_bu,
        BigUint::from(2352u32),
        "p1 must be phi*(m+x*r) = 2352"
    );
}
