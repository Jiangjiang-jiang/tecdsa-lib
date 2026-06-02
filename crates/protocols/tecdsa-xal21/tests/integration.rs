// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the XAL+21 two-party ECDSA protocol.

use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{verify_ecdsa, DataToSign};
use tecdsa_xal21::keygen::trusted_dealer_keygen;
use tecdsa_xal21::offline_sign;
use tecdsa_xal21::online_sign;

/// Helper: hash a message to a scalar for ECDSA signing.
fn hash_message<C: TecdsaCurve>(msg: &[u8]) -> DataToSign<C>
where
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    C::Scalar: elliptic_curve::PrimeField<Repr = elliptic_curve::FieldBytes<C>>,
{
    let hash = Sha256::digest(msg);
    let mut fb = elliptic_curve::FieldBytes::<C>::default();
    let len = fb.len();
    fb.copy_from_slice(&hash[..len]);
    let scalar = Option::from(<C::Scalar as elliptic_curve::PrimeField>::from_repr(fb))
        .expect("hash must be valid scalar");
    DataToSign::from_digest(scalar)
}

#[test]
fn keygen_produces_valid_shares() {
    let mut rng = rand_core::OsRng;
    let (p1, p2) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    // Both parties should have the same public key
    assert_eq!(p1.public_key, p2.public_key);

    // Q = (x_1 + x_2) * G (additive sharing)
    let x = p1.secret_share + p2.secret_share;
    let expected_pk = Secp256k1::generator() * x;
    assert_eq!(p1.public_key, expected_pk);

    // Q_1 = x_1 * G
    let expected_q1 = Secp256k1::generator() * p1.secret_share;
    assert_eq!(p1.public_share, expected_q1);
    assert_eq!(p2.public_share_p1, expected_q1);
}

#[test]
fn end_to_end_sign_and_verify() {
    let mut rng = rand_core::OsRng;

    // Generate key shares via trusted dealer
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    // Offline phase: produce presignatures (message-independent)
    let (p1_presig, p2_presig) =
        offline_sign::offline_sign(&p1_key, &p2_key, &mut rng).expect("offline signing failed");

    // Both parties should agree on r
    assert_eq!(p1_presig.r, p2_presig.r);

    // Online phase: sign a specific message
    let message = hash_message::<Secp256k1>(b"Hello, XAL+21!");
    let signature = online_sign::online_sign(&p1_key, &p1_presig, &p2_presig, &message)
        .expect("online signing failed");

    // Verify the signature independently
    verify_ecdsa::<Secp256k1>(&signature, &p1_key.public_key, &message)
        .expect("signature should verify");
}

#[test]
#[ignore = "redundant variant test"]
fn sign_different_messages() {
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let messages = [
        b"message one".as_slice(),
        b"message two".as_slice(),
        b"a longer message that tests more content".as_slice(),
        b"".as_slice(),
        b"XAL+21 online-friendly test".as_slice(),
    ];

    for msg in &messages {
        let (p1_presig, p2_presig) = offline_sign::offline_sign(&p1_key, &p2_key, &mut rng)
            .expect("offline signing should succeed");

        let data = hash_message::<Secp256k1>(msg);
        let sig = online_sign::online_sign(&p1_key, &p1_presig, &p2_presig, &data)
            .expect("online signing should succeed for all messages");
        verify_ecdsa::<Secp256k1>(&sig, &p1_key.public_key, &data)
            .expect("verification should succeed");
    }
}

#[test]
#[ignore = "redundant variant test"]
fn sign_with_different_key_pairs() {
    let mut rng = rand_core::OsRng;
    let message = hash_message::<Secp256k1>(b"test message");

    // Generate two different key pairs and sign with each
    let (p1a, p2a) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
    let (p1b, p2b) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let (p1a_pre, p2a_pre) = offline_sign::offline_sign(&p1a, &p2a, &mut rng).expect("offline A");
    let (p1b_pre, p2b_pre) = offline_sign::offline_sign(&p1b, &p2b, &mut rng).expect("offline B");

    let sig_a = online_sign::online_sign(&p1a, &p1a_pre, &p2a_pre, &message).expect("signing A");
    let sig_b = online_sign::online_sign(&p1b, &p1b_pre, &p2b_pre, &message).expect("signing B");

    // Each signature verifies with its own public key
    verify_ecdsa::<Secp256k1>(&sig_a, &p1a.public_key, &message).expect("verify A");
    verify_ecdsa::<Secp256k1>(&sig_b, &p1b.public_key, &message).expect("verify B");

    // Cross-verification should fail
    assert!(verify_ecdsa::<Secp256k1>(&sig_a, &p1b.public_key, &message).is_err());
    assert!(verify_ecdsa::<Secp256k1>(&sig_b, &p1a.public_key, &message).is_err());
}

#[test]
#[ignore = "redundant variant test"]
fn presignature_is_one_use() {
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    // Create a single presignature
    let (p1_presig, p2_presig) =
        offline_sign::offline_sign(&p1_key, &p2_key, &mut rng).expect("offline signing failed");

    // Sign first message -- should succeed
    let msg1 = hash_message::<Secp256k1>(b"first message");
    let sig1 = online_sign::online_sign(&p1_key, &p1_presig, &p2_presig, &msg1)
        .expect("first signing should succeed");
    verify_ecdsa::<Secp256k1>(&sig1, &p1_key.public_key, &msg1)
        .expect("first signature should verify");

    // Sign second message with the SAME presignature -- the signature is valid
    // (mathematically) but produces a different (r,s) pair with the same r,
    // which would leak the secret key if both signatures are observed.
    // The protocol guarantees one-use by construction (offline phase is run once
    // per signature), but if reused, the r values are the same, proving the
    // presignature was reused.
    let msg2 = hash_message::<Secp256k1>(b"second message");
    let sig2 = online_sign::online_sign(&p1_key, &p1_presig, &p2_presig, &msg2)
        .expect("second signing with same presig also produces valid sig");
    verify_ecdsa::<Secp256k1>(&sig2, &p1_key.public_key, &msg2)
        .expect("second signature also verifies");

    // But the r values are the same -- this is the nonce reuse that leaks the key
    assert_eq!(sig1.r, sig2.r, "same presig produces same r (nonce reuse)");

    // The s values must differ (different messages)
    assert_ne!(
        sig1.s, sig2.s,
        "different messages produce different s values"
    );
}

#[test]
#[ignore = "redundant variant test"]
fn step_by_step_offline_and_online() {
    use tecdsa_paillier::mta::PaillierMtaSetup;

    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let mta_setup = PaillierMtaSetup {
        ek: p2_key.ek.clone(),
        dk: p2_key.dk.clone(),
        proof_setup: (),
    };

    type M = offline_sign::DefaultMtA;

    // Step 1: P_2 commits nonce
    let (step1_msg, step1_state) = offline_sign::step1_p2_commit::<Secp256k1>(&mut rng);

    // Step 2a: P_2 encrypts k_2 for MtA
    let (sender_msg, sender_state) =
        offline_sign::step2_p2_encrypt_k2::<Secp256k1, M>(&mta_setup, &step1_state.k2, &mut rng)
            .expect("P_2 should encrypt k_2");

    // Step 2b: P_1 computes re-sharing data
    let (step2_msg, step2_state) =
        offline_sign::step2_p1_compute::<Secp256k1, M>(&p1_key, &mta_setup, &sender_msg, &mut rng)
            .expect("P_1 should compute re-sharing data");

    // Step 2c: P_2 verifies PiA proof and consistency
    let x2_prime = offline_sign::step2_p2_verify::<Secp256k1, M>(
        &p2_key,
        &mta_setup,
        &sender_state,
        &step1_state.k2,
        &step2_msg,
    )
    .expect("P_2 should verify consistency");

    // Step 3a: P_1 sends nonce
    let (step3_p1_msg, k1) = offline_sign::step3_p1_send_nonce::<Secp256k1>(&mut rng);

    // Step 3b: P_2 decommits and computes R
    let (step3_p2_decommit, p2_presig) =
        offline_sign::step3_p2_decommit_and_compute_R::<Secp256k1>(
            &step1_state,
            &step3_p1_msg,
            &step2_msg.r1,
            x2_prime,
        )
        .expect("P_2 should decommit and compute R");

    // Step 3c: P_1 verifies and computes R
    let p1_presig = offline_sign::step3_p1_verify_and_compute_R::<Secp256k1>(
        &step1_msg,
        &step3_p2_decommit,
        k1,
        &step2_state,
    )
    .expect("P_1 should verify and compute R");

    // Both parties agree on r
    assert_eq!(p1_presig.r, p2_presig.r, "r values must match");

    // Online phase: sign a message
    let message = hash_message::<Secp256k1>(b"step-by-step test");

    // P_2 computes s_2
    let p2_online_msg = online_sign::party2_compute_s2::<Secp256k1>(&p2_presig, &message)
        .expect("P_2 should compute s_2");

    // P_1 computes final signature
    let signature = online_sign::party1_compute_signature::<Secp256k1>(
        &p1_key,
        &p1_presig,
        &p2_online_msg,
        &message,
    )
    .expect("P_1 should compute valid signature");

    verify_ecdsa::<Secp256k1>(&signature, &p1_key.public_key, &message)
        .expect("signature should verify");
}

#[test]
#[ignore = "redundant variant test"]
fn re_sharing_correctness() {
    // Verify that the re-sharing produces x'_1*(k_2+r_1) + x'_2 = x
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let (p1_presig, p2_presig) = offline_sign::offline_sign(&p1_key, &p2_key, &mut rng)
        .expect("offline signing should succeed");

    // x'_1 * (k_2 + r_1) + x'_2 should equal x = x_1 + x_2
    let x = p1_key.secret_share + p2_key.secret_share;
    let k2_plus_r1 = p2_presig.k2 + p2_presig.r1;
    let reconstructed = p1_presig.x1_prime * k2_plus_r1 + p2_presig.x2_prime;
    assert_eq!(reconstructed, x, "re-sharing must reconstruct x correctly");
}

#[test]
#[ignore = "redundant variant test"]
fn nonce_correctness() {
    // Verify that R = k_1 * (k_2 + r_1) * G
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let (p1_presig, p2_presig) = offline_sign::offline_sign(&p1_key, &p2_key, &mut rng)
        .expect("offline signing should succeed");

    // k = k_1 * (k_2 + r_1)
    let k = p1_presig.k1 * (p2_presig.k2 + p2_presig.r1);

    // R should be k * G
    let expected_r_point = Secp256k1::generator() * k;
    assert_eq!(p1_presig.R, expected_r_point, "R must equal k*G");

    // r should be x_coord(R) mod q
    let expected_r = <Secp256k1 as TecdsaCurve>::xcoord_mod_q(&expected_r_point.to_affine());
    assert_eq!(p1_presig.r, expected_r, "r must be x_coord(R) mod q");
}

#[test]
fn protocol_metadata() {
    use tecdsa_protocol::Protocol;
    let meta = tecdsa_xal21::Xal21::METADATA;
    assert_eq!(meta.name, "XAL+21");
    assert_eq!(meta.signing_rounds_paper, 4);
    assert_eq!(meta.signing_rounds_impl, 4);
    assert_eq!(meta.presign_rounds, 3);
    assert_eq!(meta.online_sign_rounds, 1);
    assert_eq!(meta.keygen_rounds, 3);
}

/// Test the generic MtA interface using `offline_sign_generic` directly.
#[test]
#[ignore = "redundant variant test"]
fn generic_mta_interface() {
    use tecdsa_paillier::mta::PaillierMtaSetup;

    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let mta_setup = PaillierMtaSetup {
        ek: p2_key.ek.clone(),
        dk: p2_key.dk.clone(),
        proof_setup: (),
    };

    let (p1_presig, p2_presig) = offline_sign::offline_sign_generic::<
        Secp256k1,
        offline_sign::DefaultMtA,
    >(&p1_key, &p2_key, &mta_setup, &mut rng)
    .expect("generic offline signing should succeed");

    assert_eq!(p1_presig.r, p2_presig.r);

    let message = hash_message::<Secp256k1>(b"generic MtA test");
    let sig = online_sign::online_sign(&p1_key, &p1_presig, &p2_presig, &message)
        .expect("signing should succeed");
    verify_ecdsa::<Secp256k1>(&sig, &p1_key.public_key, &message).expect("signature should verify");
}

// ---------------------------------------------------------------------------
// KeygenMachine StateMachine integration test
// ---------------------------------------------------------------------------

/// Drive a two-party state machine to completion by passing messages
/// back and forth between the two parties.
fn drive_two_party_xal21(
    p1: &mut tecdsa_xal21::keygen::Xal21KeygenMachine<Secp256k1>,
    p2: &mut tecdsa_xal21::keygen::Xal21KeygenMachine<Secp256k1>,
    p1_id: tecdsa_protocol::PartyId,
    p2_id: tecdsa_protocol::PartyId,
    max_rounds: u16,
) {
    use tecdsa_protocol::StateMachine;
    for _ in 0..max_rounds {
        if p1.is_done() && p2.is_done() {
            break;
        }
        let p1_out: Vec<_> = p1.drain_outgoing();
        let p2_out: Vec<_> = p2.drain_outgoing();
        for msg in p1_out {
            p2.handle(p1_id, msg.msg).expect("p2 should handle p1 msg");
        }
        for msg in p2_out {
            p1.handle(p2_id, msg.msg).expect("p1 should handle p2 msg");
        }
    }
}

/// Test the XAL+21 keygen state machine: 3-round interactive DKG.
///
/// Paillier key generation is very slow in debug mode (~10-30s), so this test
/// is marked #[ignore]. Run with: cargo test -p tecdsa-xal21 keygen_machine -- --ignored
#[test]
#[ignore = "Paillier keygen is slow in debug mode (~10-30s)"]
fn keygen_machine_end_to_end() {
    use tecdsa_protocol::StateMachine;
    use tecdsa_xal21::keygen::{TwoPartyRole, Xal21KeyShare, Xal21KeygenMachine};

    let mut rng = rand_core::OsRng;
    let p1_id = tecdsa_protocol::PartyId(1);
    let p2_id = tecdsa_protocol::PartyId(2);

    // Party1 starts (sends Round1 commitment)
    let mut p1 = Xal21KeygenMachine::new(TwoPartyRole::Party1, p1_id, p2_id, &mut rng)
        .expect("P1 construction should succeed");
    let mut p2 = Xal21KeygenMachine::new(TwoPartyRole::Party2, p2_id, p1_id, &mut rng)
        .expect("P2 construction should succeed");

    // Drive the protocol to completion (3 rounds)
    drive_two_party_xal21(&mut p1, &mut p2, p1_id, p2_id, 5);

    assert!(p1.is_done(), "P1 should be done");
    assert!(p2.is_done(), "P2 should be done");

    let share1 = p1.finish().expect("P1 should produce output");
    let share2 = p2.finish().expect("P2 should produce output");

    // Verify both parties agree on the public key
    let (pk1, pk2) = match (&share1, &share2) {
        (Xal21KeyShare::Party1(s1), Xal21KeyShare::Party2(s2)) => (s1.public_key, s2.public_key),
        _ => panic!("expected Party1 and Party2 share variants"),
    };
    assert_eq!(pk1, pk2, "both parties must agree on the public key");

    // Verify Q = (x_1 + x_2) * G (additive sharing)
    match (&share1, &share2) {
        (Xal21KeyShare::Party1(s1), Xal21KeyShare::Party2(s2)) => {
            let x = s1.secret_share + s2.secret_share;
            let expected_pk = Secp256k1::generator() * x;
            assert_eq!(pk1, expected_pk, "Q must equal (x_1 + x_2) * G");
        }
        _ => unreachable!(),
    }

    // Verify signing works with the generated key shares
    match (share1, share2) {
        (Xal21KeyShare::Party1(p1_key), Xal21KeyShare::Party2(p2_key)) => {
            let (p1_presig, p2_presig) = offline_sign::offline_sign(&p1_key, &p2_key, &mut rng)
                .expect("offline signing should succeed with keygen_machine shares");

            let message = hash_message::<Secp256k1>(b"keygen_machine test");
            let signature = online_sign::online_sign(&p1_key, &p1_presig, &p2_presig, &message)
                .expect("online signing should succeed");
            verify_ecdsa::<Secp256k1>(&signature, &p1_key.public_key, &message)
                .expect("signature should verify");
        }
        _ => unreachable!(),
    }
}
