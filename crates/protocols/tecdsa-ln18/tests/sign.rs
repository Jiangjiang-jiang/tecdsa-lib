// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests for the LN18 signing protocol.
//!
//! Tests both the split (presign + online sign) and the legacy combined flow.

use std::collections::BTreeMap;

use elliptic_curve::{FieldBytes, PrimeField};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use tecdsa_core::Csprng;
use tecdsa_ln18::{
    f_mult::{
        init::{InitOutput, InitState},
        input::{InputOutput, InputRound1Msg, InputRound2Msg, InputState},
    },
    key_share::Ln18KeyShare,
    keygen::Ln18KeygenMachine,
    sign::{
        ln18_online_sign_parallel, ln18_presign_parallel, ln18_sign_parallel, Ln18OnlineSignParams,
        Ln18PresignParams,
    },
};
use tecdsa_paillier::{
    backend::Integer, zk::mta_range::NTildeParams, DecryptionKey, EncryptionKey,
};
use tecdsa_protocol::{
    ecdsa::{verify_ecdsa, DataToSign},
    PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine,
};

type C = k256::Secp256k1;

/// Generate a test Paillier decryption key with 512-bit primes.
fn test_paillier_dk(rng: &mut impl CryptoRngCore) -> DecryptionKey {
    let p = Integer::generate_safe_prime(rng, 512);
    let q = Integer::generate_safe_prime(rng, 512);
    DecryptionKey::from_primes(p, q).expect("valid primes")
}

fn make_session_configs(n: u16, t: u16) -> Vec<SessionConfig> {
    let session_id = SessionId([0u8; 32]);
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();
    (0..n)
        .map(|i| SessionConfig {
            session_id: session_id.clone(),
            local_party: PartyInfo {
                id: PartyId(i),
                index: i,
                total: n,
                threshold: t,
            },
            parties: parties.clone(),
        })
        .collect()
}

/// Run the LN18 keygen state machines to completion.
fn run_keygen(n: u16, t: u16) -> Vec<Ln18KeyShare<C>> {
    let configs = make_session_configs(n, t);
    let mut rng = Csprng::new();

    let mut machines: Vec<(PartyId, Ln18KeygenMachine<C>)> = configs
        .iter()
        .map(|cfg| {
            (
                cfg.local_party.id,
                Ln18KeygenMachine::<C>::new(cfg, &mut rng),
            )
        })
        .collect();

    let max_rounds = 10u16;
    for _round in 0..max_rounds {
        let all_done = machines.iter().all(|(_, m)| m.is_done());
        if all_done {
            break;
        }

        let mut pending = Vec::new();
        for (pid, machine) in &mut machines {
            for msg in machine.drain_outgoing() {
                pending.push((*pid, msg));
            }
        }

        for (from, outgoing) in pending {
            match outgoing.to {
                Recipient::Party(to) => {
                    if let Some((_, machine)) = machines.iter_mut().find(|(p, _)| *p == to) {
                        machine
                            .handle(from, outgoing.msg)
                            .unwrap_or_else(|e| panic!("handle error from {from} to {to}: {e}"));
                    }
                }
                Recipient::Broadcast => {
                    for (pid, machine) in &mut machines {
                        if *pid != from {
                            machine
                                .handle(from, outgoing.msg.clone())
                                .unwrap_or_else(|e| {
                                    panic!("handle error from {from} to {pid}: {e}")
                                });
                        }
                    }
                }
            }
        }
    }

    machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("keygen must succeed"))
        .collect()
}

/// Run the init sub-protocol directly to get InitOutput for sign params.
fn run_init_direct(parties: &[PartyId], rng: &mut impl CryptoRngCore) -> Vec<InitOutput<C>> {
    let n = parties.len();

    let mut init_states: Vec<InitState<C>> = Vec::with_capacity(n);
    let mut r1_msgs = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) = InitState::<C>::new(parties[i], parties.to_vec(), rng);
        init_states.push(state);
        r1_msgs.push(msg);
    }

    let mut r2_msgs = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let r2 = init_states[i]
            .handle_round1(&others)
            .expect("init Round-1 should succeed");
        r2_msgs.push(r2);
    }

    let mut init_outputs = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = r2_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let output = init_states[i]
            .finish_round2(&others)
            .expect("init Round-2 should succeed");
        init_outputs.push(output);
    }

    init_outputs
}

/// Generate Ring-Pedersen auxiliary parameters $(N', h_1, h_2)$ for testing.
fn test_ntilde(rng: &mut impl CryptoRngCore) -> NTildeParams {
    let p = Integer::generate_safe_prime(rng, 256);
    let q = Integer::generate_safe_prime(rng, 256);
    let n_tilde = &p * &q;

    let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);
    let phi_n = (&p - Integer::one()) * (&q - Integer::one());
    let lambda = phi_n.random_below_ref(rng);
    let h2 = h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod defined");

    NTildeParams {
        N_tilde: n_tilde,
        h1,
        h2,
    }
}

/// Run the input sub-protocol for x_i shares to produce stored InputOutput
/// that will be reused in signing (per Protocol 5.1, identifier 0).
fn run_input_for_x(
    parties: &[PartyId],
    elgamal_pk: <C as elliptic_curve::CurveArithmetic>::ProjectivePoint,
    x_shares: &[<C as elliptic_curve::CurveArithmetic>::Scalar],
    rng: &mut impl CryptoRngCore,
) -> Vec<InputOutput<C>> {
    let n = parties.len();

    // Round 1: commitments
    let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
    let mut input_r1_msgs: Vec<InputRound1Msg> = Vec::with_capacity(n);
    for i in 0..n {
        let (state, msg) =
            InputState::<C>::new(parties[i], parties.to_vec(), elgamal_pk, x_shares[i], rng);
        input_states.push(state);
        input_r1_msgs.push(msg);
    }

    // Round 2: decommitments
    let mut input_r2_msgs: Vec<InputRound2Msg<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = input_r1_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let r2 = input_states[i]
            .handle_round1(&others)
            .expect("input Round-1 should succeed");
        input_r2_msgs.push(r2);
    }

    // Finish: verify decommitments and proofs
    let mut outputs = Vec::with_capacity(n);
    for i in 0..n {
        let others: Vec<_> = input_r2_msgs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, m)| m.clone())
            .collect();
        let output = input_states[i]
            .finish_round2(&others)
            .expect("input Round-2 should succeed");
        outputs.push(output);
    }
    outputs
}

/// Hash a message to a scalar for ECDSA signing.
fn hash_to_scalar(msg: &[u8]) -> <C as elliptic_curve::CurveArithmetic>::Scalar {
    let hash = Sha256::digest(msg);
    let mut bytes = FieldBytes::<C>::default();
    bytes.copy_from_slice(&hash);
    <<C as elliptic_curve::CurveArithmetic>::Scalar as PrimeField>::from_repr(bytes)
        .into_option()
        .expect("SHA-256 output should be a valid scalar for secp256k1")
}

/// Build Paillier presign params from keygen outputs and init outputs.
fn build_presign_params(
    key_shares: &[Ln18KeyShare<C>],
    init_outputs: &[InitOutput<C>],
    stored_x_inputs: &[InputOutput<C>],
    dks: &[DecryptionKey],
    eks: &BTreeMap<PartyId, EncryptionKey>,
    ntilde_map: &BTreeMap<PartyId, NTildeParams>,
    n: usize,
) -> Vec<Ln18PresignParams<C>> {
    let mut sign_params: Vec<Ln18PresignParams<C>> = Vec::new();
    for i in 0..n {
        let ks = Ln18KeyShare {
            party_index: key_shares[i].party_index,
            secret_share: key_shares[i].secret_share,
            public_key: key_shares[i].public_key,
            elgamal_dk: init_outputs[i].d_i,
            elgamal_pk: init_outputs[i].elgamal_pk,
            elgamal_pk_shares: init_outputs[i].elgamal_pk_shares.clone(),
            n: key_shares[i].n,
            t: key_shares[i].t,
        };

        sign_params.push(Ln18PresignParams {
            key_share: ks,
            paillier_dk: dks[i].clone(),
            paillier_eks: eks.clone(),
            ntilde_params: ntilde_map.clone(),
            init_output: init_outputs[i].clone(),
            stored_x_input: stored_x_inputs[i].clone(),
        });
    }
    sign_params
}

/// Generate Paillier keys and NTilde params for testing.
fn gen_paillier_and_ntilde(
    parties: &[PartyId],
    rng: &mut impl CryptoRngCore,
) -> (
    Vec<DecryptionKey>,
    BTreeMap<PartyId, EncryptionKey>,
    BTreeMap<PartyId, NTildeParams>,
) {
    let mut dks: Vec<DecryptionKey> = Vec::new();
    let mut eks: BTreeMap<PartyId, EncryptionKey> = BTreeMap::new();
    let mut ntilde_map: BTreeMap<PartyId, NTildeParams> = BTreeMap::new();
    for &pid in parties {
        let dk = test_paillier_dk(rng);
        eks.insert(pid, dk.encryption_key().clone());
        dks.push(dk);
        ntilde_map.insert(pid, test_ntilde(rng));
    }
    (dks, eks, ntilde_map)
}

// ===========================================================================
// Presign-only tests
// ===========================================================================

#[test]
fn presign_2of2() {
    let n = 2u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let init_outputs = run_init_direct(&parties, &mut rng);
    let (dks, eks, ntilde_map) = gen_paillier_and_ntilde(&parties, &mut rng);

    let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
    let stored_x_inputs =
        run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

    let presign_params = build_presign_params(
        &key_shares,
        &init_outputs,
        &stored_x_inputs,
        &dks,
        &eks,
        &ntilde_map,
        n as usize,
    );

    let presigs = ln18_presign_parallel(&presign_params, &parties, &mut rng);
    assert_eq!(presigs.len(), n as usize);

    // All parties agree on R and r
    for i in 1..presigs.len() {
        assert_eq!(presigs[0].R, presigs[i].R, "all parties must agree on R");
        assert_eq!(presigs[0].r, presigs[i].r, "all parties must agree on r");
    }

    // r must not be zero
    assert!(!bool::from(presigs[0].r.is_zero()), "r must not be zero");
}

#[test]
#[ignore = "slow: larger/variant test"]
fn presign_3of3() {
    let n = 3u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let init_outputs = run_init_direct(&parties, &mut rng);
    let (dks, eks, ntilde_map) = gen_paillier_and_ntilde(&parties, &mut rng);

    let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
    let stored_x_inputs =
        run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

    let presign_params = build_presign_params(
        &key_shares,
        &init_outputs,
        &stored_x_inputs,
        &dks,
        &eks,
        &ntilde_map,
        n as usize,
    );

    let presigs = ln18_presign_parallel(&presign_params, &parties, &mut rng);
    assert_eq!(presigs.len(), n as usize);

    for i in 1..presigs.len() {
        assert_eq!(presigs[0].R, presigs[i].R);
        assert_eq!(presigs[0].r, presigs[i].r);
    }
}

// ===========================================================================
// Online sign tests (presign + online sign split)
// ===========================================================================

#[test]
fn online_sign_2of2() {
    let n = 2u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let init_outputs = run_init_direct(&parties, &mut rng);
    let (dks, eks, ntilde_map) = gen_paillier_and_ntilde(&parties, &mut rng);

    let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
    let stored_x_inputs =
        run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

    let presign_params = build_presign_params(
        &key_shares,
        &init_outputs,
        &stored_x_inputs,
        &dks,
        &eks,
        &ntilde_map,
        n as usize,
    );

    // Presign (offline)
    let presigs = ln18_presign_parallel(&presign_params, &parties, &mut rng);

    // Build online sign params
    let online_params: Vec<Ln18OnlineSignParams<C>> = presign_params
        .iter()
        .zip(presigs)
        .map(|(p, presig)| Ln18OnlineSignParams {
            paillier_dk: p.paillier_dk.clone(),
            paillier_eks: p.paillier_eks.clone(),
            ntilde_params: p.ntilde_params.clone(),
            presignature: presig,
        })
        .collect();

    // Online sign
    let message = b"hello";
    let m = hash_to_scalar(message);
    let data_to_sign = DataToSign::<C>::from_digest(m);

    let signatures = ln18_online_sign_parallel(&online_params, &parties, &m, &mut rng);
    assert_eq!(signatures.len(), n as usize);

    // All parties agree
    for i in 1..signatures.len() {
        assert_eq!(
            signatures[0].r, signatures[i].r,
            "all parties must agree on r"
        );
        assert_eq!(
            signatures[0].s, signatures[i].s,
            "all parties must agree on s"
        );
    }

    // Verify ECDSA
    let sig = &signatures[0];
    let pk = key_shares[0].public_key;
    verify_ecdsa::<C>(sig, &pk, &data_to_sign).expect("ECDSA signature verification must succeed");
}

#[test]
#[ignore = "slow: larger/variant test"]
fn online_sign_3of3() {
    let n = 3u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let init_outputs = run_init_direct(&parties, &mut rng);
    let (dks, eks, ntilde_map) = gen_paillier_and_ntilde(&parties, &mut rng);

    let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
    let stored_x_inputs =
        run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

    let presign_params = build_presign_params(
        &key_shares,
        &init_outputs,
        &stored_x_inputs,
        &dks,
        &eks,
        &ntilde_map,
        n as usize,
    );

    let presigs = ln18_presign_parallel(&presign_params, &parties, &mut rng);

    let online_params: Vec<Ln18OnlineSignParams<C>> = presign_params
        .iter()
        .zip(presigs)
        .map(|(p, presig)| Ln18OnlineSignParams {
            paillier_dk: p.paillier_dk.clone(),
            paillier_eks: p.paillier_eks.clone(),
            ntilde_params: p.ntilde_params.clone(),
            presignature: presig,
        })
        .collect();

    let message = b"threshold ECDSA with LN18";
    let m = hash_to_scalar(message);
    let data_to_sign = DataToSign::<C>::from_digest(m);

    let signatures = ln18_online_sign_parallel(&online_params, &parties, &m, &mut rng);
    assert_eq!(signatures.len(), n as usize);

    for i in 1..signatures.len() {
        assert_eq!(signatures[0].r, signatures[i].r);
        assert_eq!(signatures[0].s, signatures[i].s);
    }

    let sig = &signatures[0];
    let pk = key_shares[0].public_key;
    verify_ecdsa::<C>(sig, &pk, &data_to_sign).expect("ECDSA signature verification must succeed");
}

// ===========================================================================
// Legacy combined sign tests (backward compatibility)
// ===========================================================================

#[test]
fn sign_2of2_verifies() {
    let n = 2u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let init_outputs = run_init_direct(&parties, &mut rng);
    let (dks, eks, ntilde_map) = gen_paillier_and_ntilde(&parties, &mut rng);

    let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
    let stored_x_inputs =
        run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

    let sign_params = build_presign_params(
        &key_shares,
        &init_outputs,
        &stored_x_inputs,
        &dks,
        &eks,
        &ntilde_map,
        n as usize,
    );

    let message = b"hello";
    let m = hash_to_scalar(message);
    let data_to_sign = DataToSign::<C>::from_digest(m);

    let signatures = ln18_sign_parallel(&sign_params, &parties, &m, &mut rng);
    assert_eq!(signatures.len(), n as usize);

    for i in 1..signatures.len() {
        assert_eq!(
            signatures[0].r, signatures[i].r,
            "all parties must agree on r"
        );
        assert_eq!(
            signatures[0].s, signatures[i].s,
            "all parties must agree on s"
        );
    }

    let sig = &signatures[0];
    let pk = key_shares[0].public_key;
    verify_ecdsa::<C>(sig, &pk, &data_to_sign).expect("ECDSA signature verification must succeed");
}

#[test]
#[ignore = "slow: larger/variant test"]
fn sign_3of3_verifies() {
    let n = 3u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let init_outputs = run_init_direct(&parties, &mut rng);
    let (dks, eks, ntilde_map) = gen_paillier_and_ntilde(&parties, &mut rng);

    let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
    let stored_x_inputs =
        run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

    let sign_params = build_presign_params(
        &key_shares,
        &init_outputs,
        &stored_x_inputs,
        &dks,
        &eks,
        &ntilde_map,
        n as usize,
    );

    let message = b"threshold ECDSA with LN18";
    let m = hash_to_scalar(message);
    let data_to_sign = DataToSign::<C>::from_digest(m);

    let signatures = ln18_sign_parallel(&sign_params, &parties, &m, &mut rng);
    assert_eq!(signatures.len(), n as usize);

    for i in 1..signatures.len() {
        assert_eq!(signatures[0].r, signatures[i].r);
        assert_eq!(signatures[0].s, signatures[i].s);
    }

    let sig = &signatures[0];
    let pk = key_shares[0].public_key;
    verify_ecdsa::<C>(sig, &pk, &data_to_sign).expect("ECDSA signature verification must succeed");
}

// ===========================================================================
// FullSign 8-round tests (interleaved mult1/mult2, message known from start)
// ===========================================================================

#[test]
fn full_sign_8rounds_2of2() {
    use tecdsa_ln18::sign::ln18_full_sign_parallel;

    let n = 2u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let init_outputs = run_init_direct(&parties, &mut rng);
    let (dks, eks, ntilde_map) = gen_paillier_and_ntilde(&parties, &mut rng);

    let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
    let stored_x_inputs =
        run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

    let sign_params = build_presign_params(
        &key_shares,
        &init_outputs,
        &stored_x_inputs,
        &dks,
        &eks,
        &ntilde_map,
        n as usize,
    );

    let message = b"full sign 8-round test";
    let m = hash_to_scalar(message);
    let data_to_sign = DataToSign::<C>::from_digest(m);

    let signatures = ln18_full_sign_parallel(&sign_params, &parties, &m, &mut rng);
    assert_eq!(signatures.len(), n as usize);

    // All parties agree
    for i in 1..signatures.len() {
        assert_eq!(
            signatures[0].r, signatures[i].r,
            "all parties must agree on r"
        );
        assert_eq!(
            signatures[0].s, signatures[i].s,
            "all parties must agree on s"
        );
    }

    // Verify ECDSA
    let sig = &signatures[0];
    let pk = key_shares[0].public_key;
    verify_ecdsa::<C>(sig, &pk, &data_to_sign)
        .expect("ECDSA signature verification must succeed (full sign 8-round)");
}

#[test]
#[ignore = "slow: larger/variant test"]
fn full_sign_8rounds_3of3() {
    use tecdsa_ln18::sign::ln18_full_sign_parallel;

    let n = 3u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let init_outputs = run_init_direct(&parties, &mut rng);
    let (dks, eks, ntilde_map) = gen_paillier_and_ntilde(&parties, &mut rng);

    let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
    let stored_x_inputs =
        run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

    let sign_params = build_presign_params(
        &key_shares,
        &init_outputs,
        &stored_x_inputs,
        &dks,
        &eks,
        &ntilde_map,
        n as usize,
    );

    let message = b"full sign 3-of-3 threshold ECDSA";
    let m = hash_to_scalar(message);
    let data_to_sign = DataToSign::<C>::from_digest(m);

    let signatures = ln18_full_sign_parallel(&sign_params, &parties, &m, &mut rng);
    assert_eq!(signatures.len(), n as usize);

    for i in 1..signatures.len() {
        assert_eq!(signatures[0].r, signatures[i].r);
        assert_eq!(signatures[0].s, signatures[i].s);
    }

    let sig = &signatures[0];
    let pk = key_shares[0].public_key;
    verify_ecdsa::<C>(sig, &pk, &data_to_sign)
        .expect("ECDSA signature verification must succeed (full sign 8-round 3of3)");
}

// ===========================================================================
// OT-based sign tests (behind mta-ot feature)
// ===========================================================================

#[cfg(feature = "mta-ot")]
mod ot_sign_tests {
    use tecdsa_ln18::sign::{
        ln18_online_sign_parallel_ot, ln18_presign_parallel_ot, ln18_sign_parallel_ot,
        Ln18OtOnlineSignParams, Ln18OtPresignParams,
    };

    use super::*;

    fn build_ot_presign_params(
        key_shares: &[Ln18KeyShare<C>],
        init_outputs: &[InitOutput<C>],
        stored_x_inputs: &[InputOutput<C>],
        n: usize,
    ) -> Vec<Ln18OtPresignParams<C>> {
        let mut params = Vec::new();
        for i in 0..n {
            let ks = Ln18KeyShare {
                party_index: key_shares[i].party_index,
                secret_share: key_shares[i].secret_share,
                public_key: key_shares[i].public_key,
                elgamal_dk: init_outputs[i].d_i,
                elgamal_pk: init_outputs[i].elgamal_pk,
                elgamal_pk_shares: init_outputs[i].elgamal_pk_shares.clone(),
                n: key_shares[i].n,
                t: key_shares[i].t,
            };

            params.push(Ln18OtPresignParams {
                key_share: ks,
                init_output: init_outputs[i].clone(),
                stored_x_input: stored_x_inputs[i].clone(),
            });
        }
        params
    }

    // Presign-only OT test
    #[test]
    fn presign_ot_2of2() {
        let n = 2u16;
        let mut rng = Csprng::new();
        let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let init_outputs = run_init_direct(&parties, &mut rng);

        let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
        let stored_x_inputs =
            run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

        let params =
            build_ot_presign_params(&key_shares, &init_outputs, &stored_x_inputs, n as usize);

        let presigs = ln18_presign_parallel_ot(&params, &parties, &mut rng);
        assert_eq!(presigs.len(), n as usize);

        for i in 1..presigs.len() {
            assert_eq!(presigs[0].R, presigs[i].R, "all parties must agree on R");
            assert_eq!(presigs[0].r, presigs[i].r, "all parties must agree on r");
        }
    }

    // Online sign OT test (split)
    #[test]
    fn online_sign_ot_2of2() {
        let n = 2u16;
        let mut rng = Csprng::new();
        let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let init_outputs = run_init_direct(&parties, &mut rng);

        let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
        let stored_x_inputs =
            run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

        let params =
            build_ot_presign_params(&key_shares, &init_outputs, &stored_x_inputs, n as usize);

        let presigs = ln18_presign_parallel_ot(&params, &parties, &mut rng);

        let online_params: Vec<Ln18OtOnlineSignParams<C>> = presigs
            .into_iter()
            .map(|presig| Ln18OtOnlineSignParams {
                presignature: presig,
            })
            .collect();

        let message = b"OT split sign test";
        let m = hash_to_scalar(message);
        let data_to_sign = DataToSign::<C>::from_digest(m);

        let signatures = ln18_online_sign_parallel_ot(&online_params, &parties, &m, &mut rng);
        assert_eq!(signatures.len(), n as usize);

        for i in 1..signatures.len() {
            assert_eq!(signatures[0].r, signatures[i].r);
            assert_eq!(signatures[0].s, signatures[i].s);
        }

        let sig = &signatures[0];
        let pk = key_shares[0].public_key;
        verify_ecdsa::<C>(sig, &pk, &data_to_sign)
            .expect("ECDSA signature verification must succeed with OT MtA backend");
    }

    // Legacy combined OT sign tests
    #[test]
    fn sign_ot_2of2_verifies() {
        let n = 2u16;
        let mut rng = Csprng::new();
        let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let init_outputs = run_init_direct(&parties, &mut rng);

        let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
        let stored_x_inputs =
            run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

        let sign_params =
            build_ot_presign_params(&key_shares, &init_outputs, &stored_x_inputs, n as usize);

        let message = b"OT-based sign test";
        let m = hash_to_scalar(message);
        let data_to_sign = DataToSign::<C>::from_digest(m);

        let signatures = ln18_sign_parallel_ot(&sign_params, &parties, &m, &mut rng);
        assert_eq!(signatures.len(), n as usize);

        for i in 1..signatures.len() {
            assert_eq!(
                signatures[0].r, signatures[i].r,
                "all parties must agree on r"
            );
            assert_eq!(
                signatures[0].s, signatures[i].s,
                "all parties must agree on s"
            );
        }

        let sig = &signatures[0];
        let pk = key_shares[0].public_key;
        verify_ecdsa::<C>(sig, &pk, &data_to_sign)
            .expect("ECDSA signature verification must succeed with OT MtA backend");
    }

    #[test]
    #[ignore = "slow: larger/variant test"]
    fn sign_ot_3of3_verifies() {
        let n = 3u16;
        let mut rng = Csprng::new();
        let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let init_outputs = run_init_direct(&parties, &mut rng);

        let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
        let stored_x_inputs =
            run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

        let sign_params =
            build_ot_presign_params(&key_shares, &init_outputs, &stored_x_inputs, n as usize);

        let message = b"OT 3-of-3 threshold ECDSA";
        let m = hash_to_scalar(message);
        let data_to_sign = DataToSign::<C>::from_digest(m);

        let signatures = ln18_sign_parallel_ot(&sign_params, &parties, &m, &mut rng);
        assert_eq!(signatures.len(), n as usize);

        for i in 1..signatures.len() {
            assert_eq!(signatures[0].r, signatures[i].r);
            assert_eq!(signatures[0].s, signatures[i].s);
        }

        let sig = &signatures[0];
        let pk = key_shares[0].public_key;
        verify_ecdsa::<C>(sig, &pk, &data_to_sign)
            .expect("ECDSA signature verification must succeed with OT MtA backend");
    }

    // OT full-sign 8-round tests
    #[test]
    fn full_sign_ot_8rounds_2of2() {
        use tecdsa_ln18::sign::ln18_full_sign_parallel_ot;

        let n = 2u16;
        let mut rng = Csprng::new();
        let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let init_outputs = run_init_direct(&parties, &mut rng);

        let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
        let stored_x_inputs =
            run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

        let params =
            build_ot_presign_params(&key_shares, &init_outputs, &stored_x_inputs, n as usize);

        let message = b"OT full sign 8-round test";
        let m = hash_to_scalar(message);
        let data_to_sign = DataToSign::<C>::from_digest(m);

        let signatures = ln18_full_sign_parallel_ot(&params, &parties, &m, &mut rng);
        assert_eq!(signatures.len(), n as usize);

        for i in 1..signatures.len() {
            assert_eq!(
                signatures[0].r, signatures[i].r,
                "all parties must agree on r"
            );
            assert_eq!(
                signatures[0].s, signatures[i].s,
                "all parties must agree on s"
            );
        }

        let sig = &signatures[0];
        let pk = key_shares[0].public_key;
        verify_ecdsa::<C>(sig, &pk, &data_to_sign)
            .expect("ECDSA signature verification must succeed (OT full sign 8-round)");
    }

    #[test]
    #[ignore = "slow: larger/variant test"]
    fn full_sign_ot_8rounds_3of3() {
        use tecdsa_ln18::sign::ln18_full_sign_parallel_ot;

        let n = 3u16;
        let mut rng = Csprng::new();
        let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let init_outputs = run_init_direct(&parties, &mut rng);

        let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
        let stored_x_inputs =
            run_input_for_x(&parties, init_outputs[0].elgamal_pk, &x_shares, &mut rng);

        let params =
            build_ot_presign_params(&key_shares, &init_outputs, &stored_x_inputs, n as usize);

        let message = b"OT full sign 3-of-3 8-round";
        let m = hash_to_scalar(message);
        let data_to_sign = DataToSign::<C>::from_digest(m);

        let signatures = ln18_full_sign_parallel_ot(&params, &parties, &m, &mut rng);
        assert_eq!(signatures.len(), n as usize);

        for i in 1..signatures.len() {
            assert_eq!(signatures[0].r, signatures[i].r);
            assert_eq!(signatures[0].s, signatures[i].s);
        }

        let sig = &signatures[0];
        let pk = key_shares[0].public_key;
        verify_ecdsa::<C>(sig, &pk, &data_to_sign)
            .expect("ECDSA signature verification must succeed (OT full sign 8-round 3of3)");
    }
}

#[test]
fn protocol_metadata() {
    use tecdsa_ln18::Ln18;
    use tecdsa_protocol::Protocol;

    assert_eq!(Ln18::METADATA.name, "LN18");
    assert_eq!(Ln18::METADATA.version, "1.0");
    assert_eq!(Ln18::METADATA.primitive, "Threshold ECDSA");
    assert_eq!(Ln18::METADATA.signing_rounds_paper, 8);
    assert_eq!(Ln18::METADATA.signing_rounds_impl, 8);
    assert_eq!(
        Ln18::METADATA.security_model,
        "Simulation-based, malicious, dishonest majority"
    );
}
