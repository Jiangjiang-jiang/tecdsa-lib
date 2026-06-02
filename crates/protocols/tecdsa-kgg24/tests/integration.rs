// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the KGG24 two-party ECDSA protocol with proactive security.

use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use tecdsa_kgg24::keygen::trusted_dealer_keygen;
use tecdsa_kgg24::refresh::refresh;
use tecdsa_kgg24::sign;
use tecdsa_protocol::{verify_ecdsa, DataToSign};

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
}

#[test]
fn end_to_end_sign_and_verify() {
    let mut rng = rand_core::OsRng;

    // Generate key shares via trusted dealer
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    // Hash the message
    let message = hash_message::<Secp256k1>(b"Hello, KGG24!");

    // Run the signing protocol
    let result =
        sign::sign(&p1_key, &p2_key, &message, &mut rng).expect("signing protocol should succeed");

    // Verify the signature independently
    verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &message)
        .expect("signature should verify");
}

#[test]
fn sign_different_messages() {
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let messages = [
        b"message one".as_slice(),
        b"message two".as_slice(),
        b"a longer message that tests more content".as_slice(),
        b"".as_slice(),
        b"KGG24 proactive security test".as_slice(),
    ];

    for msg in &messages {
        let data = hash_message::<Secp256k1>(msg);
        let result = sign::sign(&p1_key, &p2_key, &data, &mut rng)
            .expect("signing should succeed for all messages");
        verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &data)
            .expect("verification should succeed");
    }
}

#[test]
fn refresh_then_sign() {
    let mut rng = rand_core::OsRng;
    let (mut p1_key, mut p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let original_pk = p1_key.public_key;

    // Perform a refresh
    refresh(&mut p1_key, &mut p2_key, &mut rng).expect("refresh should succeed");

    // Public key should be unchanged
    assert_eq!(p1_key.public_key, original_pk);
    assert_eq!(p2_key.public_key, original_pk);

    // Sign with refreshed shares
    let message = hash_message::<Secp256k1>(b"signing after refresh");
    let result = sign::sign(&p1_key, &p2_key, &message, &mut rng)
        .expect("signing after refresh should succeed");

    // Verify the signature
    verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &message)
        .expect("signature should verify after refresh");
}

#[test]
fn multiple_refreshes_then_sign() {
    let mut rng = rand_core::OsRng;
    let (mut p1_key, mut p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let original_pk = p1_key.public_key;

    // Perform multiple refreshes
    for i in 0..5 {
        refresh(&mut p1_key, &mut p2_key, &mut rng)
            .unwrap_or_else(|_| panic!("refresh {i} should succeed"));
    }

    // Public key should still be unchanged
    assert_eq!(p1_key.public_key, original_pk);

    // Sign with refreshed shares
    let message = hash_message::<Secp256k1>(b"signing after multiple refreshes");
    let result = sign::sign(&p1_key, &p2_key, &message, &mut rng)
        .expect("signing after multiple refreshes should succeed");

    verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &message)
        .expect("signature should verify after multiple refreshes");
}

#[test]
fn sign_with_different_key_pairs() {
    let mut rng = rand_core::OsRng;
    let message = hash_message::<Secp256k1>(b"test message");

    // Generate two different key pairs and sign with each
    let (p1a, p2a) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
    let (p1b, p2b) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let result_a = sign::sign(&p1a, &p2a, &message, &mut rng).expect("signing A");
    let result_b = sign::sign(&p1b, &p2b, &message, &mut rng).expect("signing B");

    // Each signature verifies with its own public key
    verify_ecdsa::<Secp256k1>(&result_a.signature, &p1a.public_key, &message).expect("verify A");
    verify_ecdsa::<Secp256k1>(&result_b.signature, &p1b.public_key, &message).expect("verify B");

    // Cross-verification should fail
    assert!(verify_ecdsa::<Secp256k1>(&result_a.signature, &p1b.public_key, &message).is_err());
    assert!(verify_ecdsa::<Secp256k1>(&result_b.signature, &p1a.public_key, &message).is_err());
}

#[test]
fn round_by_round_signing() {
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
    let message = hash_message::<Secp256k1>(b"round-by-round test");

    // Round 1: P_1 commits
    let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<Secp256k1>(&mut rng);

    // Round 2: P_2 sends R_2 + proof
    let (p2_r2_msg, p2_state) = sign::party2_round2::<Secp256k1>(&mut rng);

    // Round 3: P_1 verifies P_2's proof and decommits
    sign::party1_round3::<Secp256k1>(&p2_r2_msg).expect("P_1 should verify P_2's proof");

    // P_2 verifies P_1's decommitment and sends partial signature
    let p2_partial_msg = sign::party2_compute_partial_sig(
        &p2_key,
        &p2_state,
        &p1_r1_msg,
        &p1_decommit,
        &message,
        &mut rng,
    )
    .expect("P_2 should compute partial signature");

    // Finalize: P_1 computes and verifies the final signature
    let result = sign::party1_finalize(
        &p1_key,
        &p1_state,
        &p2_state.r2,
        &p2_partial_msg,
        &message,
        &mut rng,
    )
    .expect("P_1 should produce valid signature");

    verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &message)
        .expect("signature should verify");
}

#[test]
fn protocol_metadata() {
    use tecdsa_protocol::Protocol;
    let meta = tecdsa_kgg24::Kgg24::METADATA;
    assert_eq!(meta.name, "KGG24");
    assert_eq!(meta.signing_rounds_paper, 3);
    assert_eq!(meta.signing_rounds_impl, 3);
    assert_eq!(meta.presign_rounds, 0);
    assert_eq!(meta.online_sign_rounds, 3);
    assert_eq!(meta.keygen_rounds, 3);
}

#[test]
fn sign_then_refresh_then_sign_again() {
    let mut rng = rand_core::OsRng;
    let (mut p1_key, mut p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    // Sign before refresh
    let msg1 = hash_message::<Secp256k1>(b"before refresh");
    let result1 =
        sign::sign(&p1_key, &p2_key, &msg1, &mut rng).expect("first signing should succeed");
    verify_ecdsa::<Secp256k1>(&result1.signature, &p1_key.public_key, &msg1)
        .expect("first signature should verify");

    // Refresh
    refresh(&mut p1_key, &mut p2_key, &mut rng).expect("refresh should succeed");

    // Sign after refresh
    let msg2 = hash_message::<Secp256k1>(b"after refresh");
    let result2 = sign::sign(&p1_key, &p2_key, &msg2, &mut rng)
        .expect("signing after refresh should succeed");
    verify_ecdsa::<Secp256k1>(&result2.signature, &p1_key.public_key, &msg2)
        .expect("second signature should verify");

    // Both signatures should verify with the same public key
    verify_ecdsa::<Secp256k1>(&result1.signature, &p1_key.public_key, &msg1)
        .expect("first signature should still verify with unchanged public key");
}

#[test]
fn sign_simple_convenience() {
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
    let message = hash_message::<Secp256k1>(b"simple signing test");

    let signature = sign::sign_simple(&p1_key, &p2_key, &message, &mut rng)
        .expect("simple signing should succeed");

    verify_ecdsa::<Secp256k1>(&signature, &p1_key.public_key, &message)
        .expect("signature should verify");
}

// ---------------------------------------------------------------------------
// KeygenMachine StateMachine integration test
// ---------------------------------------------------------------------------

/// Drive a two-party state machine to completion by passing messages
/// back and forth between the two parties.
fn drive_two_party_kgg24(
    p1: &mut tecdsa_kgg24::keygen::Kgg24KeygenMachine<Secp256k1>,
    p2: &mut tecdsa_kgg24::keygen::Kgg24KeygenMachine<Secp256k1>,
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

/// Test the KGG24 keygen state machine: 3-round interactive DKG.
///
/// Paillier key generation is very slow in debug mode (~10-30s), so this test
/// is marked #[ignore]. Run with: cargo test -p tecdsa-kgg24 keygen_machine -- --ignored
#[test]
#[ignore = "Paillier keygen is slow in debug mode (~10-30s)"]
fn keygen_machine_end_to_end() {
    use tecdsa_kgg24::keygen::{Kgg24KeyShare, Kgg24KeygenMachine, TwoPartyRole};
    use tecdsa_protocol::StateMachine;

    let mut rng = rand_core::OsRng;
    let p1_id = tecdsa_protocol::PartyId(1);
    let p2_id = tecdsa_protocol::PartyId(2);

    // Party2 starts (sends Round1 commitment)
    let mut p1 = Kgg24KeygenMachine::new(TwoPartyRole::Party1, p1_id, p2_id, &mut rng)
        .expect("P1 construction should succeed");
    let mut p2 = Kgg24KeygenMachine::new(TwoPartyRole::Party2, p2_id, p1_id, &mut rng)
        .expect("P2 construction should succeed");

    // Drive the protocol to completion (3 rounds)
    drive_two_party_kgg24(&mut p1, &mut p2, p1_id, p2_id, 5);

    assert!(p1.is_done(), "P1 should be done");
    assert!(p2.is_done(), "P2 should be done");

    let share1 = p1.finish().expect("P1 should produce output");
    let share2 = p2.finish().expect("P2 should produce output");

    // Verify both parties agree on the public key
    let (pk1, pk2) = match (&share1, &share2) {
        (Kgg24KeyShare::Party1(s1), Kgg24KeyShare::Party2(s2)) => (s1.public_key, s2.public_key),
        _ => panic!("expected Party1 and Party2 share variants"),
    };
    assert_eq!(pk1, pk2, "both parties must agree on the public key");

    // Verify Q = (x_1 + x_2) * G (additive sharing)
    match (&share1, &share2) {
        (Kgg24KeyShare::Party1(s1), Kgg24KeyShare::Party2(s2)) => {
            let x = s1.secret_share + s2.secret_share;
            let expected_pk = Secp256k1::generator() * x;
            assert_eq!(pk1, expected_pk, "Q must equal (x_1 + x_2) * G");
        }
        _ => unreachable!(),
    }

    // Verify signing works with the generated key shares
    match (share1, share2) {
        (Kgg24KeyShare::Party1(p1_key), Kgg24KeyShare::Party2(p2_key)) => {
            let message = hash_message::<Secp256k1>(b"keygen_machine test");
            let result = sign::sign(&p1_key, &p2_key, &message, &mut rng)
                .expect("signing should succeed with keygen_machine shares");
            verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &message)
                .expect("signature should verify");
        }
        _ => unreachable!(),
    }
}
