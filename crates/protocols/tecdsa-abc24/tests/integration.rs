// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the ABC+24 two-party ECDSA protocol.

use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
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

// ---------------------------------------------------------------------------
// KeygenMachine StateMachine integration test
// ---------------------------------------------------------------------------

/// Drive a two-party state machine to completion by passing messages
/// back and forth between the two parties.
fn drive_two_party_abc24(
    p1: &mut tecdsa_abc24::keygen::Abc24KeygenMachine<Secp256k1>,
    p2: &mut tecdsa_abc24::keygen::Abc24KeygenMachine<Secp256k1>,
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

/// Test the ABC+24 keygen state machine: 3-step interactive DKG.
///
/// Paillier key generation is very slow in debug mode (~10-30s), so this test
/// is marked #[ignore]. Run with: cargo test -p tecdsa-abc24 keygen_machine -- --ignored
#[test]
#[ignore = "Paillier keygen is slow in debug mode (~10-30s)"]
fn keygen_machine_end_to_end() {
    use tecdsa_abc24::keygen::{Abc24KeyShare, Abc24KeygenMachine, TwoPartyRole};
    use tecdsa_protocol::StateMachine;

    let mut rng = rand_core::OsRng;
    let p1_id = tecdsa_protocol::PartyId(1);
    let p2_id = tecdsa_protocol::PartyId(2);

    // Server (Party1) starts (sends Step1 message)
    let mut p1 = Abc24KeygenMachine::new(TwoPartyRole::Party1, p1_id, p2_id, &mut rng)
        .expect("Server construction should succeed");
    let mut p2 = Abc24KeygenMachine::new(TwoPartyRole::Party2, p2_id, p1_id, &mut rng)
        .expect("Client construction should succeed");

    // Drive the protocol to completion (3 steps)
    drive_two_party_abc24(&mut p1, &mut p2, p1_id, p2_id, 5);

    assert!(p1.is_done(), "Server should be done");
    assert!(p2.is_done(), "Client should be done");

    let share1 = p1.finish().expect("Server should produce output");
    let share2 = p2.finish().expect("Client should produce output");

    // Verify both parties agree on the public key
    let (pk1, pk2) = match (&share1, &share2) {
        (Abc24KeyShare::Party1(s1), Abc24KeyShare::Party2(s2)) => (s1.public_key, s2.public_key),
        _ => panic!("expected Party1 (Server) and Party2 (Client) share variants"),
    };
    assert_eq!(pk1, pk2, "both parties must agree on the public key");

    // Verify Q = (x_1 + x_2) * G (additive sharing)
    // Note: in ABC+24, Server holds x_2 and Client holds x_1
    match (&share1, &share2) {
        (Abc24KeyShare::Party1(s1), Abc24KeyShare::Party2(s2)) => {
            let x = s1.secret_share + s2.secret_share;
            let expected_pk = Secp256k1::generator() * x;
            assert_eq!(pk1, expected_pk, "Q must equal (x_1 + x_2) * G");
        }
        _ => unreachable!(),
    }

    // Verify signing works with the generated key shares
    match (share1, share2) {
        (Abc24KeyShare::Party1(server_key), Abc24KeyShare::Party2(client_key)) => {
            let message = hash_message::<Secp256k1>(b"keygen_machine test");
            let signature = tecdsa_abc24::sign::sign(&server_key, &client_key, &message, &mut rng)
                .expect("signing should succeed with keygen_machine shares");
            verify_ecdsa::<Secp256k1>(&signature, &server_key.public_key, &message)
                .expect("signature should verify");
        }
        _ => unreachable!(),
    }
}

#[test]
fn protocol_metadata() {
    use tecdsa_protocol::Protocol;
    let meta = tecdsa_abc24::Abc24::METADATA;
    assert_eq!(meta.name, "ABC+24");
    assert_eq!(meta.signing_rounds_paper, 2);
    assert_eq!(meta.signing_rounds_impl, 2);
    assert_eq!(meta.presign_rounds, 0);
    assert_eq!(meta.online_sign_rounds, 2);
    assert_eq!(meta.keygen_rounds, 4);
}
