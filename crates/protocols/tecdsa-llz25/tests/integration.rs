#![allow(non_snake_case)]

use tecdsa_class_group::cl::ClSetup;
use tecdsa_llz25::{
    keygen::keygen_with_dealer,
    presign::{compute_presign_coefficients, presign_round1, verify_presign_message},
    sign::{combine_signatures, compute_partial_signature},
};

const SEED: &str = "12345";
const MSG: &[u8] = b"Hello, LLZ25 threshold ECDSA!";

#[test]
fn test_llz25_full_sign_5_of_3() {
    let n = 5u16;
    let t = 3u16;

    let mut setup = ClSetup::new_secp256k1(SEED).expect("CL setup");
    let (_sk, pk_crs) = setup.keygen().expect("CRS keygen");

    let (key_shares, aux_infos) =
        keygen_with_dealer(n, t, &mut setup, &pk_crs, SEED, false).expect("keygen");

    assert_eq!(key_shares.len(), n as usize);
    assert_eq!(aux_infos.len(), n as usize);

    let public_key = key_shares[0].public_key;
    for ks in &key_shares {
        assert_eq!(ks.public_key, public_key, "public key mismatch");
    }

    let quorum_party_indices: Vec<usize> = vec![0, 2, 4];
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

    for pm in &presign_messages {
        let valid = verify_presign_message(&setup, &pk_crs, pm).expect("verify presign");
        assert!(valid, "presign message ZK proof verification failed");
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

    let mut partials = Vec::new();
    let mut r_values = Vec::new();

    for (pos, &qi) in quorum_party_indices.iter().enumerate() {
        let coeffs = compute_presign_coefficients(
            &mut setup,
            &key_shares[qi],
            &presign_states[pos],
            &presign_messages,
            &pe_x_list,
            &quorum_indices,
            pos,
        )
        .expect("compute_presign_coefficients");

        let (partial, r) =
            compute_partial_signature(&key_shares[qi].public_key, &presign_messages, &coeffs, MSG);

        partials.push(partial);
        r_values.push(r);
    }

    for rv in &r_values {
        assert_eq!(*rv, r_values[0], "r value mismatch between parties");
    }

    let sig =
        combine_signatures(&partials, &r_values[0], &public_key, MSG).expect("combine_signatures");

    println!("LLZ25 5-of-3 sign OK: r={:?}", sig.r);
}

#[test]
fn test_llz25_minimum_quorum() {
    let n = 5u16;
    let t = 3u16;

    let mut setup = ClSetup::new_secp256k1("67890").expect("CL setup");
    let (_sk, pk_crs) = setup.keygen().expect("CRS keygen");

    let (key_shares, aux_infos) =
        keygen_with_dealer(n, t, &mut setup, &pk_crs, "67890", false).expect("keygen");

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
        let coeffs = compute_presign_coefficients(
            &mut setup,
            &key_shares[qi],
            &presign_states[pos],
            &presign_messages,
            &pe_x_list,
            &quorum_indices,
            pos,
        )
        .expect("compute_presign_coefficients");
        let (partial, r) =
            compute_partial_signature(&key_shares[qi].public_key, &presign_messages, &coeffs, msg);
        partials.push(partial);
        r_values.push(r);
    }

    let sig = combine_signatures(&partials, &r_values[0], &key_shares[0].public_key, msg)
        .expect("combine_signatures");

    println!("LLZ25 minimum quorum (3-of-5) OK: r={:?}", sig.r);
}

#[test]
fn test_llz25_all_parties_sign() {
    let n = 3u16;
    let t = 2u16;

    let mut setup = ClSetup::new_secp256k1("11111").expect("CL setup");
    let (_sk, pk_crs) = setup.keygen().expect("CRS keygen");

    let (key_shares, aux_infos) =
        keygen_with_dealer(n, t, &mut setup, &pk_crs, "11111", false).expect("keygen");

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
        let coeffs = compute_presign_coefficients(
            &mut setup,
            &key_shares[qi],
            &presign_states[pos],
            &presign_messages,
            &pe_x_list,
            &quorum_indices,
            pos,
        )
        .expect("compute_presign_coefficients");
        let (partial, r) =
            compute_partial_signature(&key_shares[qi].public_key, &presign_messages, &coeffs, msg);
        partials.push(partial);
        r_values.push(r);
    }

    let sig = combine_signatures(&partials, &r_values[0], &key_shares[0].public_key, msg)
        .expect("combine_signatures");

    println!("LLZ25 3-of-3 sign OK: r={:?}", sig.r);
}

#[test]
fn test_llz25_ecdsa_verify() {
    let n = 3u16;
    let t = 2u16;

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
        let coeffs = compute_presign_coefficients(
            &mut setup,
            &key_shares[qi],
            &presign_states[pos],
            &presign_messages,
            &pe_x_list,
            &quorum_indices,
            pos,
        )
        .expect("compute_presign_coefficients");
        let (partial, r) =
            compute_partial_signature(&key_shares[qi].public_key, &presign_messages, &coeffs, msg);
        partials.push(partial);
        r_values.push(r);
    }

    let sig = combine_signatures(&partials, &r_values[0], &key_shares[0].public_key, msg)
        .expect("combine_signatures");

    let m = tecdsa_llz25::sign::hash_sig(msg);
    let data = tecdsa_protocol::ecdsa::DataToSign::from_digest(m);
    tecdsa_protocol::ecdsa::verify_ecdsa::<k256::Secp256k1>(&sig, &key_shares[0].public_key, &data)
        .expect("standalone ECDSA verify");

    println!("LLZ25 ECDSA verify OK: r={:?}, s={:?}", sig.r, sig.s);
}
