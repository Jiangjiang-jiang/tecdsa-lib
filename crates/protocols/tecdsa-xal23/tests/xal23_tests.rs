// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the XAL23 threshold ECDSA protocol.
//!
//! Tests the full flow: keygen (trusted dealer) -> presign -> sign -> verify.
//!
//! These tests use reduced statistical security parameters (s=t=8) so that
//! JL parameters can be smaller and tests run in reasonable time.
//! Production would use s=t=40.

use sha2::{Digest, Sha256};
use tecdsa_curve::ScalarExt;
use tecdsa_xal23::{
    key_share::trusted_dealer_keygen,
    presign::presign_all_with_sec,
    sign::{combine_signatures, partial_sign},
};

type C = k256::Secp256k1;

/// For secp256k1 (q ~ 256 bits) with s=t=8:
/// k >= 2*256 + 2*8 + 8 + 2 = 538
/// Use k = 544 (divisible by 32) and p_bits = 800
const TEST_JL_K: u32 = 544;
const TEST_JL_P_BITS: u64 = 800;
const TEST_S: u32 = 8;
const TEST_T: u32 = 8;

/// Hash a message to a scalar for signing.
fn hash_message(msg: &[u8]) -> tecdsa_protocol::DataToSign<C> {
    let hash = Sha256::digest(msg);
    let mut bytes = k256::FieldBytes::default();
    bytes.copy_from_slice(&hash[..32]);
    let scalar = <k256::Scalar as elliptic_curve::PrimeField>::from_repr(bytes)
        .expect("hash should produce valid scalar");
    tecdsa_protocol::DataToSign::from_digest(scalar)
}

/// Test the JL MtA correctness in isolation with secp256k1 scalars.
#[test]
fn xal23_mta_correctness_secp256k1() {
    use tecdsa_curve::TecdsaCurve;
    use tecdsa_joye_libert::{kgen::generate_keypair_with_params, mta::*};

    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair_with_params(TEST_JL_P_BITS, TEST_JL_K, &mut rng);

    let q = C::order();

    // Use actual secp256k1 scalars
    let a_scalar = C::random_scalar(&mut rng);
    let b_scalar = C::random_scalar(&mut rng);
    let ab_scalar = a_scalar * b_scalar;
    let ab_uint = ab_scalar.to_integer();

    let a = a_scalar.to_integer();
    let b = b_scalar.to_integer();

    let sender = JlMtaSender::new(a);
    let receiver = JlMtaReceiver::new(b);

    let (recv_msg, _r) = mta_receiver_step1(&receiver, &pk, &mut rng);
    let (send_msg, sender_out) =
        mta_sender_step_with_sec(&sender, &pk, &recv_msg, &q, TEST_S, TEST_T, &mut rng);
    let receiver_out = mta_receiver_step2(&sk, &pk, &send_msg, &q);

    let sum = (sender_out.alpha + receiver_out.beta) % q;
    assert_eq!(sum, ab_uint, "MtA failed with secp256k1 scalars");
}

#[test]
fn xal23_full_protocol_n2_all_signers() {
    let mut rng = rand::thread_rng();

    // n=2, t=2 (reconstruction threshold)
    let key_shares = trusted_dealer_keygen::<C>(2, 2, TEST_JL_P_BITS, TEST_JL_K, &mut rng);

    let signer_indices: Vec<usize> = vec![0, 1];

    // Presign with reduced security params for testing
    let presigs = presign_all_with_sec::<C>(&key_shares, &signer_indices, TEST_S, TEST_T, &mut rng);

    // Sign
    let message = b"XAL23 two-party test";
    let data = hash_message(message);

    let partials: Vec<_> = presigs.iter().map(|p| partial_sign(p, &data)).collect();
    let sig = combine_signatures(&presigs[0], &partials, &data).expect("signature should verify");

    tecdsa_protocol::verify_ecdsa(&sig, &key_shares[0].public_key, &data)
        .expect("ECDSA verification should succeed");
}

#[test]
fn xal23_full_protocol_n3_all_signers() {
    let mut rng = rand::thread_rng();

    // Key generation: n=3, t=2 (reconstruction threshold)
    let key_shares = trusted_dealer_keygen::<C>(3, 2, TEST_JL_P_BITS, TEST_JL_K, &mut rng);

    // All 3 parties sign
    let signer_indices: Vec<usize> = vec![0, 1, 2];

    // Presign
    let presigs = presign_all_with_sec::<C>(&key_shares, &signer_indices, TEST_S, TEST_T, &mut rng);
    assert_eq!(presigs.len(), 3);

    // Online sign
    let message = b"Hello, XAL23 threshold ECDSA!";
    let data = hash_message(message);

    let partials: Vec<_> = presigs.iter().map(|p| partial_sign(p, &data)).collect();

    // Combine
    let sig = combine_signatures(&presigs[0], &partials, &data).expect("signature should verify");

    // Verify with standard ECDSA verification
    let pk = key_shares[0].public_key;
    tecdsa_protocol::verify_ecdsa(&sig, &pk, &data).expect("ECDSA verification should succeed");
}

#[test]
fn presign_sign_via_orchestrator_3of3() {
    use tecdsa_protocol::PartyId;
    use tecdsa_testkit::Orchestrator;
    use tecdsa_xal23::{presign::Xal23PresignMachine, sign::Xal23SignMachine};

    let mut rng = rand::thread_rng();
    let n = 3u16;
    let key_shares = trusted_dealer_keygen::<C>(n, 2, TEST_JL_P_BITS, TEST_JL_K, &mut rng);
    let all_parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    // Presign via Orchestrator
    let presign_machines: Vec<(PartyId, Xal23PresignMachine<C>)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Xal23PresignMachine::with_sec(
                pid,
                all_parties.clone(),
                &key_shares[pid.0 as usize],
                TEST_S,
                TEST_T,
                &mut rand::thread_rng(),
            )
            .expect("presign machine");
            (pid, machine)
        })
        .collect();

    let presign_result = Orchestrator::new(presign_machines, 10)
        .run()
        .expect("presign orchestrator");
    let presigs: Vec<_> = presign_result
        .outputs
        .into_iter()
        .map(|r| r.expect("presign"))
        .collect();

    assert_eq!(presigs.len(), n as usize);
    for i in 1..presigs.len() {
        assert_eq!(presigs[0].R, presigs[i].R, "all parties must agree on R");
        assert_eq!(presigs[0].r, presigs[i].r, "all parties must agree on r");
    }

    // Online sign via Orchestrator
    let message = b"orchestrator presign test";
    let data = hash_message(message);

    let sign_machines: Vec<(PartyId, Xal23SignMachine<C>)> = presigs
        .iter()
        .map(|p| {
            let pid = p.my_id;
            (pid, Xal23SignMachine::new(p.clone(), data))
        })
        .collect();

    let sign_result = Orchestrator::new(sign_machines, 5)
        .run()
        .expect("sign orchestrator");
    let sigs: Vec<_> = sign_result
        .outputs
        .into_iter()
        .map(|r| r.expect("sign"))
        .collect();

    // All parties produce the same signature
    for i in 1..sigs.len() {
        assert_eq!(sigs[0].r, sigs[i].r);
        assert_eq!(sigs[0].s, sigs[i].s);
    }

    // Verify ECDSA
    tecdsa_protocol::verify_ecdsa(&sigs[0], &key_shares[0].public_key, &data)
        .expect("ECDSA verification should succeed");
}

#[test]
fn xal23_metadata() {
    let meta = &tecdsa_xal23::XAL23_METADATA;
    assert_eq!(meta.name, "XAL23");
    assert_eq!(meta.presign_rounds, 4);
    assert_eq!(meta.online_sign_rounds, 1);
    assert_eq!(meta.mta_variant, "JL (Joye-Libert encryption)");
}
