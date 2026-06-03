// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trout integration tests.
//!
//! Paper: Dahari-Garbian, Nof, Parker. "Trout: Two-Round Threshold ECDSA
//! from Class Groups."
//!
//! Tests:
//! - Full keygen -> presign -> sign flow with insecure CL params (p=7).
//! - Scaled decryption correctness.
//! - Proof verification (R_{CL-EC}, R_{ComKwlg}).

#![allow(non_snake_case)]

use elliptic_curve::PrimeField;
use sha2::{Digest, Sha256};
use tecdsa_class_group::cl::ClSetup;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::ecdsa::{verify_ecdsa, DataToSign};
use tecdsa_trout::{
    key_share::TroutKeyShare, keygen::trusted_dealer_keygen, presign::presign_round1,
    sign::sign_round2,
};

fn hash_message(msg: &[u8]) -> k256::Scalar {
    let hash = Sha256::digest(msg);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    k256::Scalar::from_repr(k256::FieldBytes::from(bytes))
        .into_option()
        .unwrap_or_else(|| {
            use num_bigint::BigUint;
            use num_traits::Num;
            let q = BigUint::from_str_radix(tecdsa_class_group::cl::SECP256K1_ORDER, 10).unwrap();
            let val = BigUint::from_bytes_be(&bytes) % &q;
            let mut padded = [0u8; 32];
            let be = val.to_bytes_be();
            let offset = 32 - be.len();
            padded[offset..].copy_from_slice(&be);
            k256::Scalar::from_repr(k256::FieldBytes::from(padded))
                .into_option()
                .unwrap()
        })
}

/// Run full Trout protocol: keygen -> presign -> sign.
#[test]
fn test_trout_full_sign_3_of_5() {
    let seed = "77777";
    let n = 5u16;
    let t = 2u16; // corruption threshold: max 2 corrupted, reconstruct = t+1 = 3

    let mut rng = rand::rngs::OsRng;
    let mut setup = ClSetup::new_secp256k1(seed).expect("CL setup");

    // ---- KeyGen (trusted dealer) ----
    let shares = trusted_dealer_keygen(&mut setup, seed, n, t, false, &mut rng).expect("keygen");
    assert_eq!(shares.len(), n as usize);

    let public_key = shares[0].public_key;

    // ---- Select signing parties: parties 1, 2, 3 (3 out of 5) ----
    let signing_parties: Vec<u16> = vec![1, 2, 3];
    let signing_shares: Vec<&TroutKeyShare> = signing_parties
        .iter()
        .map(|&idx| &shares[(idx - 1) as usize])
        .collect();

    let session_nonce = b"trout-test-session-42";

    // Reconstruct the joint CL public key from the key share.
    // All shares have the same cl_pk_abc.
    let mut setup2 = ClSetup::new_secp256k1(seed).expect("CL setup");
    let (pk_a, pk_b, pk_c) = &shares[0].cl_pk_abc;
    let cl_pk_qfi =
        tecdsa_trout::error::qfi_from_abc(pk_a, pk_b, pk_c).expect("reconstruct CL pk QFI");
    let cl_pk = setup2.pk_from_qfi(&cl_pk_qfi).expect("pk_from_qfi");

    // ---- Round 1 (Presign) ----
    let mut states = Vec::new();
    let mut broadcasts = Vec::new();
    for share in &signing_shares {
        let (state, bcast) = presign_round1(
            share,
            &signing_parties,
            session_nonce,
            &mut setup2,
            &cl_pk,
            &mut rng,
        )
        .expect("presign_round1");
        states.push(state);
        broadcasts.push(bcast);
    }

    // ---- Round 2 (Sign) ----
    // Compute R = sum(R_i)
    let mut big_r = k256::ProjectivePoint::IDENTITY;
    for bcast in &broadcasts {
        let r_i_affine = <k256::Secp256k1 as TecdsaCurve>::point_from_bytes(&bcast.r_i_bytes)
            .expect("valid point");
        let r_i_proj: k256::ProjectivePoint = r_i_affine.into();
        big_r += r_i_proj;
    }
    let r_affine = elliptic_curve::group::Curve::to_affine(&big_r);
    let r_scalar = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&r_affine);

    // Verify eVRF proofs
    for bcast in &broadcasts {
        let party_pos = (bcast.party_index - 1) as usize;
        let evrf_pk = &shares[party_pos].all_evrf_pks[party_pos];
        let ok = bcast
            .evrf_proof
            .verify(evrf_pk, session_nonce, &bcast.evrf_output);
        assert!(ok, "eVRF proof for party {} must verify", bcast.party_index);
    }

    // Build TroutPresignOutput for each party.
    // All parties receive the same set of broadcasts (moved into the first party,
    // shared via the all_broadcasts reference).
    let presign_outputs: Vec<tecdsa_trout::presign::types::TroutPresignOutput> = states
        .into_iter()
        .map(|state| tecdsa_trout::presign::types::TroutPresignOutput {
            party_index: state.party_index,
            big_r,
            r_scalar,
            k_i: state.k_i,
            u_i: state.u_i,
            alpha_i: state.alpha_i.clone(),
            beta_i: state.beta_i.clone(),
            l_i: state.l_i,
            l_i_delta_i: state.l_i_delta_i.clone(),
            all_broadcasts: Vec::new(), // filled below
        })
        .collect();

    // We cannot clone broadcasts because ZK proof types do not implement Clone.
    // Instead, all presign outputs share the same broadcast reference via the
    // first output. The sign function only reads broadcasts from all_presigns[0].
    // Move all broadcasts into the first presign output.
    let mut presign_outputs = presign_outputs;
    presign_outputs[0].all_broadcasts = broadcasts;

    // Sign
    let msg_scalar = hash_message(b"Trout correctness test");
    let message = DataToSign::from_digest(msg_scalar);

    let sig = sign_round2(
        &presign_outputs,
        &message,
        signing_shares[0],
        &setup2,
        &cl_pk,
    )
    .expect("sign_round2");

    // Verify signature independently
    verify_ecdsa::<k256::Secp256k1>(&sig, &public_key, &message)
        .expect("independent ECDSA verification must pass");

    println!("Trout 3-of-5 sign OK: r={:?}", sig.r);
}

/// Test scaled decryption standalone.
#[test]
fn test_scaled_decrypt_standalone() {
    use tecdsa_class_group::scaled_decrypt::*;

    let mut setup = ClSetup::new_secp256k1("8001").expect("setup");
    let mut rng = rand::rngs::OsRng;
    let (_cl_sk, cl_pk) = setup.keygen().expect("keygen");
    let pk_elt = &cl_pk.elt();

    let n = 4;
    let a: Vec<k256::Scalar> = (0..n)
        .map(|_| <k256::Secp256k1 as TecdsaCurve>::random_scalar(&mut rng))
        .collect();
    let b: Vec<k256::Scalar> = (0..n)
        .map(|_| <k256::Secp256k1 as TecdsaCurve>::random_scalar(&mut rng))
        .collect();
    let a_sum: k256::Scalar = a.iter().copied().sum();
    let b_sum: k256::Scalar = b.iter().copied().sum();
    let expected = a_sum * b_sum;

    let mut alphas = Vec::new();
    let mut betas = Vec::new();
    let mut enc_components = Vec::new();
    let mut com_qfis = Vec::new();

    for i in 0..n {
        let a_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&a[i]);
        let b_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&b[i]);

        let (sk_tmp, _) = setup.keygen().expect("keygen");
        let alpha_i = setup.sk_to_bytes(&sk_tmp).expect("sk_bytes");

        let ct = setup
            .encrypt_with_r_bytes(&cl_pk, &a_bytes, &alpha_i)
            .expect("encrypt");
        let (c1, c2) = setup.ct_components(&ct).expect("ct_comp");
        enc_components.push((c1, c2));

        let (sk_tmp2, _) = setup.keygen().expect("keygen");
        let beta_i = setup.sk_to_bytes(&sk_tmp2).expect("sk_bytes");

        let h_beta = setup.power_of_h_bytes(&beta_i).expect("power_of_h");
        let pk_b = setup.exp_bytes(pk_elt, &b_bytes).expect("exp");
        let com = setup.compose(&h_beta, &pk_b).expect("compose");
        com_qfis.push(com);

        alphas.push(alpha_i);
        betas.push(beta_i);
    }

    let (a1, a2) = aggregate_ciphertext_components(&setup, &enc_components).expect("agg_ct");
    let b_agg = aggregate_commitments(&setup, &com_qfis).expect("agg_com");

    let public = ScaledDecryptPublic { a1, a2, b_agg };

    let inputs: Vec<ScaledDecryptPartyInput> = (0..n)
        .map(|i| ScaledDecryptPartyInput {
            alpha_i: alphas[i].clone(),
            beta_i: betas[i].clone(),
            b_i: tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&b[i]),
        })
        .collect();

    let result_bytes = scaled_decrypt_local(&setup, &inputs, &public).expect("scaled_decrypt");
    let result = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&result_bytes);
    assert_eq!(
        result, expected,
        "scaled decryption must correctly compute a*b mod q"
    );
}
