// SPDX-License-Identifier: MIT OR Apache-2.0
//! LLZ25 integration tests.
//!
//! Paper: Lyu, Li, Zhou, Deng. "Threshold ECDSA in Two Rounds." CCS 2025.
//!
//! Tests the full protocol flow: keygen -> presign -> sign -> verify.

#![allow(non_snake_case)]

use tecdsa_class_group::cl::ClSetup;
use tecdsa_llz25::{
    keygen::keygen_with_dealer,
    presign::{presign_round1, verify_presign_message},
    sign::{combine_signatures, compute_partial_signature},
};

const SEED: &str = "12345";
const MSG: &[u8] = b"Hello, LLZ25 threshold ECDSA!";

/// Run the full LLZ25 protocol: keygen + presign + sign + verify.
///
/// Parameters: n=5, t=2 (corruption threshold; reconstruct = t+1 = 3), insecure CL params (p=7).
#[test]
fn test_llz25_full_sign_5_of_3() {
    let n = 5u16;
    let t = 2u16; // corruption threshold: max 2 corrupted, reconstruct = t+1 = 3

    // -- Setup --
    let mut setup = ClSetup::new_secp256k1(SEED).expect("CL setup");
    let (_sk, pk_crs) = setup.keygen().expect("CRS keygen");

    // -- KeyGen (trusted dealer) --
    let (key_shares, aux_infos) =
        keygen_with_dealer(n, t, &mut setup, &pk_crs, SEED, false).expect("keygen");

    assert_eq!(key_shares.len(), n as usize);
    assert_eq!(aux_infos.len(), n as usize);

    // All parties should have the same public key.
    let public_key = key_shares[0].public_key;
    for ks in &key_shares {
        assert_eq!(ks.public_key, public_key, "public key mismatch");
    }

    // -- Select quorum: parties 1, 3, 5 (3 parties for t+1=3) --
    let quorum_party_indices: Vec<usize> = vec![0, 2, 4]; // 0-based indices into key_shares
    let quorum_indices: Vec<u16> = quorum_party_indices
        .iter()
        .map(|&i| key_shares[i].party_index)
        .collect();

    // -- Presign Round 1 --
    let mut presign_messages = Vec::new();
    let mut presign_states = Vec::new();

    for _ in &quorum_party_indices {
        let (pm, ps) = presign_round1(&mut setup, &pk_crs).expect("presign_round1");
        presign_messages.push(pm);
        presign_states.push(ps);
    }

    // -- Verify presign messages --
    for pm in &presign_messages {
        let valid = verify_presign_message(&setup, &pk_crs, pm).expect("verify presign");
        assert!(valid, "presign message ZK proof verification failed");
    }

    // -- Collect pe_x ciphertexts for the quorum parties --
    // pe_x_list[j] is the pe_x for quorum party at position j.
    let pe_x_list: Vec<_> = quorum_party_indices
        .iter()
        .map(|&i| {
            // Clone the ciphertext by getting its components and reconstructing.
            // Since ClHsmqkCiphertext doesn't impl Clone, we need to work with
            // the raw components.
            let (c1, c2) = setup
                .ct_components(&aux_infos[i].pe_x)
                .expect("ct_components");
            setup
                .ct_from_components(&c1, &c2)
                .expect("ct_from_components")
        })
        .collect();

    // -- Sign (Round 2) --
    let mut partials = Vec::new();
    let mut r_values = Vec::new();

    for (pos, &qi) in quorum_party_indices.iter().enumerate() {
        let (partial, r) = compute_partial_signature(
            &mut setup,
            &key_shares[qi],
            &presign_states[pos],
            &presign_messages,
            &pe_x_list,
            &quorum_indices,
            pos,
            MSG,
        )
        .expect("compute_partial_signature");

        partials.push(partial);
        r_values.push(r);
    }

    // All parties should compute the same r value.
    for rv in &r_values {
        assert_eq!(*rv, r_values[0], "r value mismatch between parties");
    }

    // -- Combine --
    let sig =
        combine_signatures(&partials, &r_values[0], &public_key, MSG).expect("combine_signatures");

    println!("LLZ25 5-of-3 sign OK: r={:?}", sig.r);
}

/// Test with the minimum quorum size (t+1 = 3 out of 5).
#[test]
fn test_llz25_minimum_quorum() {
    let n = 5u16;
    let t = 2u16;

    let mut setup = ClSetup::new_secp256k1("67890").expect("CL setup");
    let (_sk, pk_crs) = setup.keygen().expect("CRS keygen");

    let (key_shares, aux_infos) =
        keygen_with_dealer(n, t, &mut setup, &pk_crs, "67890", false).expect("keygen");

    // Use parties 2, 3, 4 (indices 1, 2, 3).
    let quorum_party_indices: Vec<usize> = vec![1, 2, 3];
    let quorum_indices: Vec<u16> = quorum_party_indices
        .iter()
        .map(|&i| key_shares[i].party_index)
        .collect();

    let mut presign_messages = Vec::new();
    let mut presign_states = Vec::new();
    for &_qi in &quorum_party_indices {
        let (pm, ps) = presign_round1(&mut setup, &pk_crs).expect("presign_round1");
        presign_messages.push(pm);
        presign_states.push(ps);
    }

    let pe_x_list: Vec<_> = quorum_party_indices
        .iter()
        .map(|&i| {
            let (c1, c2) = setup
                .ct_components(&aux_infos[i].pe_x)
                .expect("ct_components");
            setup
                .ct_from_components(&c1, &c2)
                .expect("ct_from_components")
        })
        .collect();

    let msg = b"minimum quorum test";
    let mut partials = Vec::new();
    let mut r_values = Vec::new();

    for (pos, &qi) in quorum_party_indices.iter().enumerate() {
        let (partial, r) = compute_partial_signature(
            &mut setup,
            &key_shares[qi],
            &presign_states[pos],
            &presign_messages,
            &pe_x_list,
            &quorum_indices,
            pos,
            msg,
        )
        .expect("compute_partial_signature");
        partials.push(partial);
        r_values.push(r);
    }

    let sig = combine_signatures(&partials, &r_values[0], &key_shares[0].public_key, msg)
        .expect("combine_signatures");

    println!("LLZ25 minimum quorum (3-of-5) OK: r={:?}", sig.r);
}

/// Test with all n parties signing.
#[test]
fn test_llz25_all_parties_sign() {
    let n = 3u16;
    let t = 1u16; // need 2 parties

    let mut setup = ClSetup::new_secp256k1("11111").expect("CL setup");
    let (_sk, pk_crs) = setup.keygen().expect("CRS keygen");

    let (key_shares, aux_infos) =
        keygen_with_dealer(n, t, &mut setup, &pk_crs, "11111", false).expect("keygen");

    // All parties sign.
    let quorum_party_indices: Vec<usize> = (0..n as usize).collect();
    let quorum_indices: Vec<u16> = quorum_party_indices
        .iter()
        .map(|&i| key_shares[i].party_index)
        .collect();

    let mut presign_messages = Vec::new();
    let mut presign_states = Vec::new();
    for _ in &quorum_party_indices {
        let (pm, ps) = presign_round1(&mut setup, &pk_crs).expect("presign_round1");
        presign_messages.push(pm);
        presign_states.push(ps);
    }

    let pe_x_list: Vec<_> = quorum_party_indices
        .iter()
        .map(|&i| {
            let (c1, c2) = setup
                .ct_components(&aux_infos[i].pe_x)
                .expect("ct_components");
            setup
                .ct_from_components(&c1, &c2)
                .expect("ct_from_components")
        })
        .collect();

    let msg = b"all parties sign test";
    let mut partials = Vec::new();
    let mut r_values = Vec::new();

    for (pos, &qi) in quorum_party_indices.iter().enumerate() {
        let (partial, r) = compute_partial_signature(
            &mut setup,
            &key_shares[qi],
            &presign_states[pos],
            &presign_messages,
            &pe_x_list,
            &quorum_indices,
            pos,
            msg,
        )
        .expect("compute_partial_signature");
        partials.push(partial);
        r_values.push(r);
    }

    let sig = combine_signatures(&partials, &r_values[0], &key_shares[0].public_key, msg)
        .expect("combine_signatures");

    println!("LLZ25 3-of-3 sign OK: r={:?}", sig.r);
}

/// Verify that standard ECDSA verification works with the LLZ25 signature.
#[test]
fn test_llz25_ecdsa_verify() {
    let n = 3u16;
    let t = 1u16;

    let mut setup = ClSetup::new_secp256k1("22222").expect("CL setup");
    let (_sk, pk_crs) = setup.keygen().expect("CRS keygen");

    let (key_shares, aux_infos) =
        keygen_with_dealer(n, t, &mut setup, &pk_crs, "22222", false).expect("keygen");

    let quorum_party_indices: Vec<usize> = vec![0, 1];
    let quorum_indices: Vec<u16> = quorum_party_indices
        .iter()
        .map(|&i| key_shares[i].party_index)
        .collect();

    let mut presign_messages = Vec::new();
    let mut presign_states = Vec::new();
    for _ in &quorum_party_indices {
        let (pm, ps) = presign_round1(&mut setup, &pk_crs).expect("presign_round1");
        presign_messages.push(pm);
        presign_states.push(ps);
    }

    let pe_x_list: Vec<_> = quorum_party_indices
        .iter()
        .map(|&i| {
            let (c1, c2) = setup
                .ct_components(&aux_infos[i].pe_x)
                .expect("ct_components");
            setup
                .ct_from_components(&c1, &c2)
                .expect("ct_from_components")
        })
        .collect();

    let msg = b"ECDSA verification test";
    let mut partials = Vec::new();
    let mut r_values = Vec::new();

    for (pos, &qi) in quorum_party_indices.iter().enumerate() {
        let (partial, r) = compute_partial_signature(
            &mut setup,
            &key_shares[qi],
            &presign_states[pos],
            &presign_messages,
            &pe_x_list,
            &quorum_indices,
            pos,
            msg,
        )
        .expect("compute_partial_signature");
        partials.push(partial);
        r_values.push(r);
    }

    let sig = combine_signatures(&partials, &r_values[0], &key_shares[0].public_key, msg)
        .expect("combine_signatures");

    // Double-check with standalone verify.
    let m = tecdsa_llz25::sign::hash_sig(msg);
    let data = tecdsa_protocol::ecdsa::DataToSign::from_digest(m);
    tecdsa_protocol::ecdsa::verify_ecdsa::<k256::Secp256k1>(&sig, &key_shares[0].public_key, &data)
        .expect("standalone ECDSA verify");

    println!("LLZ25 ECDSA verify OK: r={:?}, s={:?}", sig.r, sig.s);
}
