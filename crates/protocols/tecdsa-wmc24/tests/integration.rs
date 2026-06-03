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

//! End-to-end integration tests for the WMC24 threshold ECDSA protocol.
//!
//! Tests: keygen -> presign -> online sign -> verify.

use elliptic_curve::CurveArithmetic;
use num_bigint::{BigInt, BigUint};
use tecdsa_class_group::cl::{ClSetup, Qfi};
use tecdsa_protocol::PartyId;
use tecdsa_wmc24::{
    key_share::Wmc24KeyShare,
    keygen::Wmc24KeygenMachine,
    presign::{Wmc24PresignMachine, Wmc24Presignature},
    sign::Wmc24OnlineSignMachine,
};

// ---------------------------------------------------------------------------
// Helper: run keygen state machine
// ---------------------------------------------------------------------------

/// Run keygen for `n` parties with corruption threshold `corrupted_t`.
///
/// Reconstruction requires `corrupted_t + 1` parties.
fn run_keygen(n: usize, corrupted_t: u16) -> Vec<Wmc24KeyShare> {
    let seed = "60001";
    let parties: Vec<PartyId> = (0..n as u16).map(PartyId).collect();
    let reconstruction_threshold = corrupted_t + 1;

    let machines: Vec<(PartyId, Wmc24KeygenMachine)> = parties
        .iter()
        .map(|&pid| {
            let machine = Wmc24KeygenMachine::new(
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

fn setup_threshold_cl_keys(shares: &mut [Wmc24KeyShare], seed: &str) {
    let n = shares.len();
    let t = shares[0].threshold as usize;

    let mut setup = ClSetup::new_secp256k1(seed).expect("ClSetup");

    let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
    let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_to_bytes");

    let sk_shares = tecdsa_wmc24::keygen::shamir_share_delta(&mut setup, &sk_bytes, n, t)
        .expect("shamir_share_delta");

    let mut pk_share_qfis: Vec<Qfi> = Vec::with_capacity(n);
    for share in &sk_shares {
        let share_bi = BigInt::from(BigUint::from_bytes_be(share));
        let (sign, abs_str) = if share_bi < BigInt::from(0) {
            let abs = (-&share_bi).to_string();
            (true, abs)
        } else {
            (false, share_bi.to_string())
        };

        let mut h_share = setup.power_of_h(&abs_str).expect("power_of_h");
        let pk_share = if sign {
            h_share.neg();
            h_share
        } else {
            h_share
        };
        pk_share_qfis.push(pk_share);
    }

    // Also set up threshold ElGamal keys with Shamir sharing.
    // Generate a master ElGamal key and distribute using Shamir.
    let master_eldk = shares
        .iter()
        .fold(k256::Scalar::ZERO, |acc, s| acc + s.eldk_i);
    let master_elek =
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * master_eldk;

    // Create Shamir shares of master_eldk (standard polynomial sharing mod q).
    let master_eldk_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&master_eldk);
    let q_bytes = setup.q_bytes().expect("q_bytes");
    let q = num_bigint::BigUint::from_bytes_be(&q_bytes);

    // Generate a random t-1 degree polynomial with constant term = master_eldk.
    let mut coeffs: Vec<num_bigint::BigUint> = Vec::with_capacity(t);
    coeffs.push(num_bigint::BigUint::from_bytes_be(&master_eldk_bytes));
    for _ in 1..t {
        let (rsk, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&rsk).expect("sk_bytes");
        let r_val = num_bigint::BigUint::from_bytes_be(&r_bytes);
        coeffs.push(r_val % &q);
    }

    // Evaluate polynomial at i = 1, 2, ..., n (mod q).
    let mut elg_shares: Vec<k256::Scalar> = Vec::with_capacity(n);
    let mut elg_pk_shares: Vec<k256::ProjectivePoint> = Vec::with_capacity(n);
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    for i in 1..=n {
        let x = num_bigint::BigUint::from(i as u64);
        let mut val = num_bigint::BigUint::ZERO;
        let mut x_pow = num_bigint::BigUint::from(1u32);
        for coeff in &coeffs {
            val = (&val + coeff * &x_pow) % &q;
            x_pow = (&x_pow * &x) % &q;
        }
        let scalar = tecdsa_curve::conv::biguint_to_scalar::<k256::Secp256k1>(&val);
        elg_pk_shares.push(g * scalar);
        elg_shares.push(scalar);
    }

    for (i, share) in shares.iter_mut().enumerate() {
        share.cl_sk_share = sk_shares[i].clone();
        share.cl_pk = setup.pk_from_qfi(&pk_raw.elt()).expect("pk_from_qfi");
        share.cl_pk_shares = pk_share_qfis.iter().map(|qfi| qfi.clone()).collect();
        share.n_parties_dkg = n;
        // Set threshold ElGamal keys.
        share.eldk_i = elg_shares[i];
        share.elek_shares = elg_pk_shares.clone();
        share.elek = master_elek;
    }
}

// ---------------------------------------------------------------------------
// Helper: run presign state machine
// ---------------------------------------------------------------------------

fn run_presign(key_shares: &[Wmc24KeyShare], signer_indices: &[usize]) -> Vec<Wmc24Presignature> {
    let seed = &key_shares[0].cl_setup_seed;
    let signer_parties: Vec<PartyId> = signer_indices
        .iter()
        .map(|&i| PartyId(key_shares[i].party_index - 1))
        .collect();

    let mut machines: Vec<(PartyId, Wmc24PresignMachine)> = Vec::new();

    for &idx in signer_indices {
        let share = &key_shares[idx];
        let pid = PartyId(share.party_index - 1);
        let setup = if share.use_128bit_security {
            ClSetup::new_secp256k1_128bit(seed).expect("ClSetup 128")
        } else {
            ClSetup::new_secp256k1(seed).expect("ClSetup")
        };

        let machine = Wmc24PresignMachine::new(pid, signer_parties.clone(), share, setup)
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
// Helper: run online sign state machine
// ---------------------------------------------------------------------------

fn run_online_sign(
    key_shares: &[Wmc24KeyShare],
    presignatures: Vec<Wmc24Presignature>,
    signer_indices: &[usize],
    message: &[u8],
) -> Vec<tecdsa_protocol::Signature<k256::Secp256k1>> {
    let signer_parties: Vec<PartyId> = signer_indices
        .iter()
        .map(|&i| PartyId(key_shares[i].party_index - 1))
        .collect();
    let public_key = key_shares[0].public_key;

    let mut machines: Vec<(PartyId, Wmc24OnlineSignMachine)> = Vec::new();

    for (pi, presig) in presignatures.into_iter().enumerate() {
        let idx = signer_indices[pi];
        let pid = PartyId(key_shares[idx].party_index - 1);

        let machine =
            Wmc24OnlineSignMachine::new(pid, signer_parties.clone(), presig, message, public_key)
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

    let pk0 = shares[0].public_key;
    for share in &shares[1..] {
        assert_eq!(
            pk0, share.public_key,
            "all parties must agree on the joint PK"
        );
    }

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

    // Verify ElGamal keys.
    let elek0 = shares[0].elek;
    for share in &shares[1..] {
        assert_eq!(
            elek0, share.elek,
            "all parties must agree on aggregate ElGamal PK"
        );
    }

    // Verify elek = sum(elek_j).
    let elek_sum = shares[0].elek_shares.iter().fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, p| acc + *p,
    );
    assert_eq!(elek0, elek_sum, "elek must equal sum of elek_shares");
}

#[test]
fn test_full_protocol_keygen_presign_sign() {
    let n = 5;
    let corrupted_t = 1u16; // corruption threshold
    let seed = "60001";

    // Step 1: Keygen.
    let mut key_shares = run_keygen(n, corrupted_t);

    // Step 2: Set up threshold CL keys.
    setup_threshold_cl_keys(&mut key_shares, seed);

    // Step 3: Presign with all 5 parties.
    let signer_indices: Vec<usize> = (0..n).collect();
    let presignatures = run_presign(&key_shares, &signer_indices);

    // Verify all presignatures have the same R point and r_x.
    let r0 = presignatures[0].r_point;
    let rx0 = presignatures[0].r_x;
    for presig in &presignatures[1..] {
        assert_eq!(r0, presig.r_point, "all presignatures must agree on R");
        assert_eq!(rx0, presig.r_x, "all presignatures must agree on r_x");
    }

    // Step 4: Online sign.
    let message = b"Hello WMC24 threshold ECDSA!";
    let signatures = run_online_sign(&key_shares, presignatures, &signer_indices, message);

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
fn test_threshold_subset_signing() {
    // n=5, corruption t=1, sign with parties {0, 2, 4} (a subset of t+1=2 or more).
    let n = 5;
    let corrupted_t = 1u16; // corruption threshold
    let seed = "60001";

    let mut key_shares = run_keygen(n, corrupted_t);
    setup_threshold_cl_keys(&mut key_shares, seed);

    let signer_indices = vec![0, 2, 4];
    let presignatures = run_presign(&key_shares, &signer_indices);

    let message = b"WMC24 threshold subset signing test";
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
