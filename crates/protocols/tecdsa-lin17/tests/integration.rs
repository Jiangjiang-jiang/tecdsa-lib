use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use tecdsa_lin17::{keygen::trusted_dealer_keygen, sign};
use tecdsa_protocol::{verify_ecdsa, DataToSign};

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
fn end_to_end_sign_and_verify() {
    let mut rng = rand_core::OsRng;

    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let message = hash_message::<Secp256k1>(b"Hello, Lindell 2017!");

    let signature =
        sign::sign(&p1_key, &p2_key, &message, &mut rng).expect("signing protocol should succeed");

    verify_ecdsa::<Secp256k1>(&signature, &p1_key.public_key, &message)
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
    ];

    for msg in &messages {
        let data = hash_message::<Secp256k1>(msg);
        let sig = sign::sign(&p1_key, &p2_key, &data, &mut rng)
            .expect("signing should succeed for all messages");
        verify_ecdsa::<Secp256k1>(&sig, &p1_key.public_key, &data)
            .expect("verification should succeed");
    }
}

#[test]
fn sign_with_different_key_pairs() {
    let mut rng = rand_core::OsRng;
    let message = hash_message::<Secp256k1>(b"test message");

    let (p1a, p2a) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
    let (p1b, p2b) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

    let sig_a = sign::sign(&p1a, &p2a, &message, &mut rng).expect("signing A");
    let sig_b = sign::sign(&p1b, &p2b, &message, &mut rng).expect("signing B");

    verify_ecdsa::<Secp256k1>(&sig_a, &p1a.public_key, &message).expect("verify A");
    verify_ecdsa::<Secp256k1>(&sig_b, &p1b.public_key, &message).expect("verify B");

    assert!(verify_ecdsa::<Secp256k1>(&sig_a, &p1b.public_key, &message).is_err());
    assert!(verify_ecdsa::<Secp256k1>(&sig_b, &p1a.public_key, &message).is_err());
}

#[test]
fn round_by_round_signing() {
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = trusted_dealer_keygen::<Secp256k1>(&mut rng);
    let message = hash_message::<Secp256k1>(b"round-by-round test");

    let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<Secp256k1>(&mut rng);

    let (p2_r2_msg, p2_state) = sign::party2_round2::<Secp256k1>(&mut rng);

    sign::party1_round3::<Secp256k1>(&p2_r2_msg).expect("P_1 should verify P_2's proof");

    let p2_r4_msg = sign::party2_round4(
        &p2_key,
        &p2_state,
        &p1_r1_msg,
        &p1_decommit,
        &message,
        &mut rng,
    )
    .expect("P_2 should compute partial signature");

    let signature = sign::party1_finalize(&p1_key, &p1_state, &p2_state.r2, &p2_r4_msg, &message)
        .expect("P_1 should produce valid signature");

    verify_ecdsa::<Secp256k1>(&signature, &p1_key.public_key, &message)
        .expect("signature should verify");
}

#[test]
fn protocol_metadata() {
    use tecdsa_protocol::Protocol;
    let meta = tecdsa_lin17::Lin17::METADATA;
    assert_eq!(meta.name, "Lin17");
    assert_eq!(meta.signing_rounds_paper, 4);
    assert_eq!(meta.signing_rounds_impl, 4);
    assert_eq!(meta.presign_rounds, 0);
    assert_eq!(meta.online_sign_rounds, 4);
    assert_eq!(meta.keygen_rounds, 5);
}

fn drive_two_party_lin17(
    p1: &mut tecdsa_lin17::keygen::Lin17KeygenMachine<Secp256k1>,
    p2: &mut tecdsa_lin17::keygen::Lin17KeygenMachine<Secp256k1>,
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

#[test]
#[ignore = "Paillier keygen is slow in debug mode (~10-30s)"]
fn keygen_machine_end_to_end() {
    use tecdsa_lin17::keygen::{Lin17KeyShare, Lin17KeygenMachine, TwoPartyRole};
    use tecdsa_protocol::StateMachine;

    let mut rng = rand_core::OsRng;
    let p1_id = tecdsa_protocol::PartyId(1);
    let p2_id = tecdsa_protocol::PartyId(2);

    let mut p1 = Lin17KeygenMachine::new(TwoPartyRole::Party1, p1_id, p2_id, &mut rng)
        .expect("P1 construction should succeed");
    let mut p2 = Lin17KeygenMachine::new(TwoPartyRole::Party2, p2_id, p1_id, &mut rng)
        .expect("P2 construction should succeed");

    drive_two_party_lin17(&mut p1, &mut p2, p1_id, p2_id, 10);

    assert!(p1.is_done(), "P1 should be done");
    assert!(p2.is_done(), "P2 should be done");

    let share1 = p1.finish().expect("P1 should produce output");
    let share2 = p2.finish().expect("P2 should produce output");

    let (pk1, pk2) = match (&share1, &share2) {
        (Lin17KeyShare::Party1(s1), Lin17KeyShare::Party2(s2)) => (s1.public_key, s2.public_key),
        _ => panic!("expected Party1 and Party2 share variants"),
    };
    assert_eq!(pk1, pk2, "both parties must agree on the public key");

    match (&share1, &share2) {
        (Lin17KeyShare::Party1(s1), Lin17KeyShare::Party2(s2)) => {
            let x = s1.secret_share * s2.secret_share;
            let expected_pk = Secp256k1::generator() * x;
            assert_eq!(pk1, expected_pk, "Q must equal x_1 * x_2 * G");
        }
        _ => unreachable!(),
    }

    match (share1, share2) {
        (Lin17KeyShare::Party1(p1_key), Lin17KeyShare::Party2(p2_key)) => {
            let message = hash_message::<Secp256k1>(b"keygen_machine test");
            let signature = sign::sign(&p1_key, &p2_key, &message, &mut rng)
                .expect("signing should succeed with keygen_machine shares");
            verify_ecdsa::<Secp256k1>(&signature, &p1_key.public_key, &message)
                .expect("signature should verify");
        }
        _ => unreachable!(),
    }
}
