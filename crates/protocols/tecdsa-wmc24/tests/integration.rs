// SPDX-License-Identifier: MIT OR Apache-2.0
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
use tecdsa_class_group::cl::{parse_int_auto, ClSetup};
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

/// Run keygen for `n` parties with reconstruction threshold `t`.
///
/// `t` parties are needed to sign.
fn run_keygen(n: usize, t: u16) -> Vec<Wmc24KeyShare> {
    run_keygen_with_seed(n, t, "60001", false)
}

fn run_keygen_with_seed(
    n: usize,
    t: u16,
    seed: &str,
    use_128bit_security: bool,
) -> Vec<Wmc24KeyShare> {
    let parties: Vec<PartyId> = (1..=n as u16).map(PartyId).collect();

    let machines: Vec<(PartyId, Wmc24KeygenMachine)> = parties
        .iter()
        .map(|&pid| {
            let machine =
                Wmc24KeygenMachine::new(pid, parties.clone(), t, seed, use_128bit_security)
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
// Helper: run presign state machine
// ---------------------------------------------------------------------------

fn run_presign(key_shares: &[Wmc24KeyShare], signer_indices: &[usize]) -> Vec<Wmc24Presignature> {
    let seed = &key_shares[0].cl_setup_seed;
    let signer_parties: Vec<PartyId> = signer_indices
        .iter()
        .map(|&i| PartyId(key_shares[i].party_index))
        .collect();

    let mut machines: Vec<(PartyId, Wmc24PresignMachine)> = Vec::new();

    for &idx in signer_indices {
        let share = &key_shares[idx];
        let pid = PartyId(share.party_index);
        let seed_int = parse_int_auto(seed).expect("parse seed");
        let setup = if share.use_128bit_security {
            ClSetup::new_secp256k1_128bit(&seed_int).expect("ClSetup 128")
        } else {
            ClSetup::new_secp256k1(&seed_int).expect("ClSetup")
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
        .map(|&i| PartyId(key_shares[i].party_index))
        .collect();
    let public_key = key_shares[0].public_key;

    let mut machines: Vec<(PartyId, Wmc24OnlineSignMachine)> = Vec::new();

    for (pi, presig) in presignatures.into_iter().enumerate() {
        let idx = signer_indices[pi];
        let pid = PartyId(key_shares[idx].party_index);

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
    let shares = run_keygen(5, 2); // reconstruction threshold=2, need 2 to sign

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

    // Verify elek = Lagrange interpolation of elek_shares (Shamir polynomial evaluation shares).
    let n = shares.len();
    let indices: Vec<u16> = (1..=n as u16).collect();
    let lagrange_coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
    let elek_interpolated = shares[0]
        .elek_shares
        .iter()
        .zip(lagrange_coeffs.iter())
        .fold(
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
            |acc, (p, l)| acc + *p * l,
        );
    assert_eq!(
        elek0, elek_interpolated,
        "elek must equal Lagrange interpolation of elek_shares"
    );

    // Verify each party's elek_share = eldk_i * G.
    for share in &shares {
        let my_idx = (share.party_index - 1) as usize;
        let expected =
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * share.eldk_i;
        assert_eq!(
            share.elek_shares[my_idx], expected,
            "elek_share[{}] must match eldk_i * G",
            share.party_index
        );
    }
}

#[test]
fn test_keygen_128bit_3_of_2() {
    let shares = run_keygen_with_seed(3, 2, "42042", true);

    let pk0 = shares[0].public_key;
    let elek0 = shares[0].elek;
    for share in &shares[1..] {
        assert_eq!(pk0, share.public_key);
        assert_eq!(elek0, share.elek);
    }
}

#[test]
fn test_full_protocol_keygen_presign_sign() {
    let n = 5;
    let t = 2u16; // reconstruction threshold

    // Step 1: Keygen (now produces proper Shamir ElGamal shares natively).
    let key_shares = run_keygen(n, t);

    // Step 2: Presign with all 5 parties.
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
    // n=5, t=2, sign with parties {0, 2, 4} (a subset of t=2 or more).
    let n = 5;
    let t = 2u16; // reconstruction threshold

    let key_shares = run_keygen(n, t);

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
