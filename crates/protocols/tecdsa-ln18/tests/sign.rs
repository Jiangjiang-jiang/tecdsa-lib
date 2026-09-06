// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests for the LN18 signing protocol.
//!
//! Tests both the split (presign + online sign) and the legacy combined flow.
//! Keygen now produces Shamir shares via Feldman VSS DKG. For signing, a
//! per-session setup (Init + Input(w_i) + Paillier) is performed with
//! Lagrange-weighted shares for the signing subset.

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
        ln18_online_sign_parallel, ln18_presign_parallel, ln18_sign_parallel,
        Ln18LegacyOnlineSignParams, Ln18PresignParams,
    },
};
use tecdsa_paillier::{
    backend::Integer, zk::mta_range::NTildeParams, BigIntExt, DecryptionKey, EncryptionKey,
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
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    (1..=n)
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
    let n_tilde = Integer::from(&p * &q);

    let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);
    let phi_n = (&p - Integer::one()) * (&q - Integer::one());
    let lambda = phi_n.sample_below_ref(rng);
    let h2 = Integer::from(h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod defined"));

    NTildeParams {
        N_tilde: n_tilde,
        h1,
        h2,
    }
}

/// Run the input sub-protocol for weighted x_i shares to produce stored InputOutput
/// that will be reused in signing.
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

/// Build the per-session signing setup from keygen shares for a signer subset.
///
/// This encapsulates: Lagrange weighting + Init + Input(w_i) + Paillier.
fn build_signing_setup(
    key_shares: &[Ln18KeyShare<C>],
    signers: &[PartyId],
    rng: &mut impl CryptoRngCore,
) -> Vec<Ln18PresignParams<C>> {
    // 256-bit primes keep these tests fast. Production uses
    // `build_signing_setup`, which defaults to `NTILDE_PRIME_BITS` (1536).
    tecdsa_ln18::sign::build_signing_setup_with_ntilde_bits::<C>(key_shares, signers, 256, rng)
        .expect("LN18 signing setup")
}

// ===========================================================================
// Presign-only tests
// ===========================================================================

#[test]
fn presign_2of2() {
    let n = 2u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let presign_params = build_signing_setup(&key_shares, &parties, &mut rng);

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
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let presign_params = build_signing_setup(&key_shares, &parties, &mut rng);

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
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let presign_params = build_signing_setup(&key_shares, &parties, &mut rng);

    // Presign (offline)
    let presigs = ln18_presign_parallel(&presign_params, &parties, &mut rng);

    // Build online sign params
    let online_params: Vec<Ln18LegacyOnlineSignParams<C>> = presign_params
        .iter()
        .zip(presigs)
        .map(|(p, presig)| Ln18LegacyOnlineSignParams {
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
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let presign_params = build_signing_setup(&key_shares, &parties, &mut rng);

    let presigs = ln18_presign_parallel(&presign_params, &parties, &mut rng);

    let online_params: Vec<Ln18LegacyOnlineSignParams<C>> = presign_params
        .iter()
        .zip(presigs)
        .map(|(p, presig)| Ln18LegacyOnlineSignParams {
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
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let sign_params = build_signing_setup(&key_shares, &parties, &mut rng);

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
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let sign_params = build_signing_setup(&key_shares, &parties, &mut rng);

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
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let sign_params = build_signing_setup(&key_shares, &parties, &mut rng);

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
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let sign_params = build_signing_setup(&key_shares, &parties, &mut rng);

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
        signers: &[PartyId],
    ) -> Vec<Ln18OtPresignParams<C>> {
        let n = key_shares[0].n;
        let t = key_shares[0].t;
        let public_key = key_shares[0].public_key;

        signers
            .iter()
            .enumerate()
            .map(|(pos, &pid)| {
                let ks = Ln18KeyShare {
                    party_index: pid.0,
                    secret_share: key_shares[(pid.0 - 1) as usize].secret_share,
                    public_key,
                    public_shares: key_shares[0].public_shares.clone(),
                    n,
                    t,
                };

                Ln18OtPresignParams {
                    key_share: ks,
                    init_output: init_outputs[pos].clone(),
                    stored_x_input: stored_x_inputs[pos].clone(),
                }
            })
            .collect()
    }

    /// Build OT signing setup from keygen shares for a signer subset.
    fn build_ot_signing_setup(
        key_shares: &[Ln18KeyShare<C>],
        signers: &[PartyId],
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Ln18OtPresignParams<C>> {
        let signer_pts: Vec<u16> = signers.iter().map(|p| p.0).collect();
        let lagrange = tecdsa_vss::lagrange::coefficients::<C>(&signer_pts);
        let weighted: Vec<_> = signers
            .iter()
            .enumerate()
            .map(|(pos, pid)| key_shares[(pid.0 - 1) as usize].secret_share * lagrange[pos])
            .collect();

        let init_outputs = run_init_direct(signers, rng);
        let stored_x_inputs = run_input_for_x(signers, init_outputs[0].elgamal_pk, &weighted, rng);

        build_ot_presign_params(key_shares, &init_outputs, &stored_x_inputs, signers)
    }

    // Presign-only OT test
    #[test]
    fn presign_ot_2of2() {
        let n = 2u16;
        let mut rng = Csprng::new();
        let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let params = build_ot_signing_setup(&key_shares, &parties, &mut rng);

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
        let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let params = build_ot_signing_setup(&key_shares, &parties, &mut rng);

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
        let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let sign_params = build_ot_signing_setup(&key_shares, &parties, &mut rng);

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
        let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let sign_params = build_ot_signing_setup(&key_shares, &parties, &mut rng);

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
        let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let params = build_ot_signing_setup(&key_shares, &parties, &mut rng);

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
        let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let key_shares = run_keygen(n, n);
        let params = build_ot_signing_setup(&key_shares, &parties, &mut rng);

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

// ===========================================================================
// Orchestrator-based StateMachine tests
// ===========================================================================

/// Run a set of StateMachines through the Orchestrator to completion.
fn run_orchestrated<M>(machines: Vec<(PartyId, M)>, max_rounds: u16) -> Vec<M::Output>
where
    M: tecdsa_protocol::StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    tecdsa_testkit::Orchestrator::new(machines, max_rounds)
        .run()
        .expect("orchestrator must run")
        .outputs
        .into_iter()
        .map(|r| r.expect("party output must succeed"))
        .collect()
}

#[test]
fn state_machine_sign_2plus6_2of2_paillier_verifies() {
    use std::sync::Arc;

    use tecdsa_ln18::sign::{
        Ln18MtaBackend, Ln18MtaHybrid, Ln18OfflineSignMachine, Ln18OfflineSignParams,
        Ln18OnlineSignMachine, Ln18OnlineSignParams,
    };

    let n = 2u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let presign_params = build_signing_setup(&key_shares, &parties, &mut rng);

    // Shared MtA provider (Paillier backend)
    let mta = Arc::new(Ln18MtaHybrid::<C>::new(
        parties.clone(),
        Ln18MtaBackend::Paillier,
    ));

    // Build offline machines
    let offline_machines: Vec<(PartyId, Ln18OfflineSignMachine<C>)> = presign_params
        .into_iter()
        .enumerate()
        .map(|(i, base)| {
            let params = Ln18OfflineSignParams {
                base,
                signer_parties: parties.clone(),
                mta: Arc::clone(&mta),
            };
            (
                parties[i],
                Ln18OfflineSignMachine::new(parties[i], parties.clone(), params, &mut rng),
            )
        })
        .collect();

    // Run offline phase through Orchestrator (2 rounds)
    let offline_states = run_orchestrated(offline_machines, 2);

    // Build online machines from offline states
    let message = b"orchestrated sign test paillier";
    let m = hash_to_scalar(message);
    let data_to_sign = tecdsa_protocol::ecdsa::DataToSign::<C>::from_digest(m);

    let online_machines: Vec<(PartyId, Ln18OnlineSignMachine<C>)> = offline_states
        .into_iter()
        .enumerate()
        .map(|(i, offline_state)| {
            let params = Ln18OnlineSignParams {
                offline_state,
                message_digest: m,
            };
            (parties[i], Ln18OnlineSignMachine::new(params, &mut rng))
        })
        .collect();

    // Run online phase through Orchestrator. The distributed MtA model
    // requires extra iterations for tau/beta MtA resolution phases:
    // - 2 extra for tau MtA (phase 2 + phase 3 across parties)
    // - 2 extra for beta MtA (same pattern)
    // - 6 base rounds for the protocol
    // Use 15 to provide comfortable headroom.
    let signatures = run_orchestrated(online_machines, 15);
    assert_eq!(signatures.len(), n as usize);

    // All parties agree on r and s
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
    tecdsa_protocol::ecdsa::verify_ecdsa::<C>(sig, &pk, &data_to_sign)
        .expect("ECDSA signature verification must succeed (orchestrated Paillier)");
}

#[cfg(feature = "mta-ot")]
#[test]
fn state_machine_sign_2plus6_2of2_ot_verifies() {
    use std::sync::Arc;

    use tecdsa_ln18::sign::{
        Ln18MtaBackend, Ln18MtaHybrid, Ln18OfflineSignMachine, Ln18OfflineSignParams,
        Ln18OnlineSignMachine, Ln18OnlineSignParams,
    };

    let n = 2u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let presign_params = build_signing_setup(&key_shares, &parties, &mut rng);

    // Shared MtA provider (OT backend)
    let mta = Arc::new(Ln18MtaHybrid::<C>::new(parties.clone(), Ln18MtaBackend::Ot));

    // Build offline machines
    let offline_machines: Vec<(PartyId, Ln18OfflineSignMachine<C>)> = presign_params
        .into_iter()
        .enumerate()
        .map(|(i, base)| {
            let params = Ln18OfflineSignParams {
                base,
                signer_parties: parties.clone(),
                mta: Arc::clone(&mta),
            };
            (
                parties[i],
                Ln18OfflineSignMachine::new(parties[i], parties.clone(), params, &mut rng),
            )
        })
        .collect();

    // Run offline phase through Orchestrator (2 rounds)
    let offline_states = run_orchestrated(offline_machines, 2);

    // Build online machines from offline states
    let message = b"orchestrated sign test OT";
    let m = hash_to_scalar(message);
    let data_to_sign = tecdsa_protocol::ecdsa::DataToSign::<C>::from_digest(m);

    let online_machines: Vec<(PartyId, Ln18OnlineSignMachine<C>)> = offline_states
        .into_iter()
        .enumerate()
        .map(|(i, offline_state)| {
            let params = Ln18OnlineSignParams {
                offline_state,
                message_digest: m,
            };
            (parties[i], Ln18OnlineSignMachine::new(params, &mut rng))
        })
        .collect();

    // Run online phase through Orchestrator (6 rounds + 1 for beta MtA resolution)
    let signatures = run_orchestrated(online_machines, 7);
    assert_eq!(signatures.len(), n as usize);

    // All parties agree on r and s
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
    tecdsa_protocol::ecdsa::verify_ecdsa::<C>(sig, &pk, &data_to_sign)
        .expect("ECDSA signature verification must succeed (orchestrated OT)");
}

#[test]
fn offline_sign_rejects_duplicate_round1_message() {
    use std::sync::Arc;

    use tecdsa_ln18::sign::{
        Ln18MtaBackend, Ln18MtaHybrid, Ln18OfflineSignMachine, Ln18OfflineSignParams,
    };

    let n = 2u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let presign_params = build_signing_setup(&key_shares, &parties, &mut rng);

    let mta = Arc::new(Ln18MtaHybrid::<C>::new(
        parties.clone(),
        Ln18MtaBackend::Paillier,
    ));

    let mut machines: Vec<Ln18OfflineSignMachine<C>> = presign_params
        .into_iter()
        .enumerate()
        .map(|(i, base)| {
            let params = Ln18OfflineSignParams {
                base,
                signer_parties: parties.clone(),
                mta: Arc::clone(&mta),
            };
            Ln18OfflineSignMachine::new(parties[i], parties.clone(), params, &mut rng)
        })
        .collect();

    // Drain party 1's Round-1 message
    let party1_msgs = machines[0].drain_outgoing();
    assert!(
        !party1_msgs.is_empty(),
        "party 1 must have a Round-1 message"
    );

    let r1_msg = party1_msgs[0].msg.clone();

    // Deliver party 1's Round-1 message to party 2 -- first time should succeed
    machines[1]
        .handle(PartyId(1), r1_msg.clone())
        .expect("first delivery should succeed");

    // Deliver it again -- should be rejected as duplicate
    let result = machines[1].handle(PartyId(1), r1_msg);
    assert!(
        result.is_err(),
        "duplicate Round-1 message must be rejected"
    );
}

#[test]
fn offline_sign_rejects_out_of_round_message() {
    use std::sync::Arc;

    use tecdsa_ln18::sign::{
        Ln18MtaBackend, Ln18MtaHybrid, Ln18OfflineSignMachine, Ln18OfflineSignMsg,
        Ln18OfflineSignParams,
    };

    let n = 2u16;
    let mut rng = Csprng::new();
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let key_shares = run_keygen(n, n);
    let init_outputs = run_init_direct(&parties, &mut rng);
    let (dks, eks, ntilde_map) = gen_paillier_and_ntilde(&parties, &mut rng);

    let signer_pts: Vec<u16> = parties.iter().map(|p| p.0).collect();
    let lagrange = tecdsa_vss::lagrange::coefficients::<C>(&signer_pts);
    let weighted: Vec<_> = parties
        .iter()
        .enumerate()
        .map(|(pos, pid)| key_shares[(pid.0 - 1) as usize].secret_share * lagrange[pos])
        .collect();
    let stored_x_inputs =
        run_input_for_x(&parties, init_outputs[0].elgamal_pk, &weighted, &mut rng);

    let presign_params: Vec<Ln18PresignParams<C>> = parties
        .iter()
        .enumerate()
        .map(|(pos, &pid)| Ln18PresignParams {
            key_share: Ln18KeyShare {
                party_index: pid.0,
                secret_share: key_shares[(pid.0 - 1) as usize].secret_share,
                public_key: key_shares[0].public_key,
                public_shares: key_shares[0].public_shares.clone(),
                n: key_shares[0].n,
                t: key_shares[0].t,
            },
            paillier_dk: dks[pos].clone(),
            paillier_eks: eks.clone(),
            ntilde_params: ntilde_map.clone(),
            init_output: init_outputs[pos].clone(),
            stored_x_input: stored_x_inputs[pos].clone(),
        })
        .collect();

    let mta = Arc::new(Ln18MtaHybrid::<C>::new(
        parties.clone(),
        Ln18MtaBackend::Paillier,
    ));

    // Build offline machines; drain Round 1 messages but do NOT deliver them.
    let params0 = Ln18OfflineSignParams {
        base: presign_params.into_iter().next().unwrap(),
        signer_parties: parties.clone(),
        mta: Arc::clone(&mta),
    };
    let mut machine0 =
        Ln18OfflineSignMachine::<C>::new(PartyId(1), parties.clone(), params0, &mut rng);
    let _ = machine0.drain_outgoing(); // consume the initial Round-1 broadcast

    // Construct a synthetic Round2Input message to send to a machine in Round 1.
    use tecdsa_ln18::sign::msg::SerInputRound2;
    let dummy_r2 = SerInputRound2::<C> {
        from: 2,
        ct_a: init_outputs[0].elgamal_pk,
        ct_b: init_outputs[0].elgamal_pk,
        proof_commit_x: init_outputs[0].elgamal_pk,
        proof_commit_y: init_outputs[0].elgamal_pk,
        proof_z1: <C as elliptic_curve::CurveArithmetic>::Scalar::ONE,
        proof_z2: <C as elliptic_curve::CurveArithmetic>::Scalar::ONE,
        nonce: [0u8; 32],
    };

    // Machine is in Round 1. Sending a Round 2 message should fail.
    let wrong_round_msg = Ln18OfflineSignMsg::Round2Input {
        k: dummy_r2.clone(),
        rho: dummy_r2,
    };

    let result = machine0.handle(PartyId(2), wrong_round_msg);
    assert!(
        result.is_err(),
        "sending Round-2 message to a Round-1 machine must be rejected"
    );
}

/// t-of-n test: DKG produces Shamir shares for n=3, t=2, then 2
/// signers convert to additive via Lagrange and sign.
#[test]
fn state_machine_sign_2plus6_2of3_paillier_verifies() {
    use std::sync::Arc;

    use tecdsa_ln18::sign::{
        Ln18MtaBackend, Ln18MtaHybrid, Ln18OfflineSignMachine, Ln18OfflineSignParams,
        Ln18OnlineSignMachine, Ln18OnlineSignParams,
    };

    let n = 3u16;
    let t = 2u16;
    let mut rng = Csprng::new();
    let signers: Vec<PartyId> = vec![PartyId(1), PartyId(2)];

    // --- DKG: standard Feldman VSS produces Shamir shares ---
    let key_shares = run_keygen(n, t);
    let public_key = key_shares[0].public_key;

    // --- Per-session setup for signer subset {P1, P2} ---
    let presign_params = build_signing_setup(&key_shares, &signers, &mut rng);

    let mta = Arc::new(Ln18MtaHybrid::<C>::new(
        signers.clone(),
        Ln18MtaBackend::Paillier,
    ));
    let message = b"ln18 2-of-3 threshold test";
    let m = hash_to_scalar(message);
    let data_to_sign = DataToSign::<C>::from_digest(m);

    // Offline (2 rounds)
    let offline_machines: Vec<_> = presign_params
        .into_iter()
        .zip(signers.iter())
        .map(|(base, &pid)| {
            let params = Ln18OfflineSignParams {
                base,
                signer_parties: signers.clone(),
                mta: Arc::clone(&mta),
            };
            (
                pid,
                Ln18OfflineSignMachine::<C>::new(pid, signers.clone(), params, &mut rng),
            )
        })
        .collect();
    let offline_states = run_orchestrated(offline_machines, 4);

    // Online (6 rounds)
    let online_machines: Vec<_> = offline_states
        .into_iter()
        .map(|state| {
            let pid = state.my_id;
            (
                pid,
                Ln18OnlineSignMachine::<C>::new(
                    Ln18OnlineSignParams {
                        offline_state: state,
                        message_digest: m,
                    },
                    &mut rng,
                ),
            )
        })
        .collect();
    let signatures = run_orchestrated(online_machines, 15);
    assert_eq!(signatures.len(), t as usize);

    // Verify ECDSA with the JOINT public key from DKG
    tecdsa_protocol::ecdsa::verify_ecdsa::<C>(&signatures[0], &public_key, &data_to_sign)
        .expect("LN18 2-of-3 threshold signature must verify");
}

#[test]
fn public_build_signing_setup_uses_party_ids_not_key_share_order() {
    let key_shares = run_keygen(3, 2);
    let shuffled = vec![
        key_shares[2].clone(),
        key_shares[0].clone(),
        key_shares[1].clone(),
    ];
    let signers = vec![PartyId(1), PartyId(2)];
    let mut rng = Csprng::new();

    let params = tecdsa_ln18::sign::build_signing_setup::<C>(&shuffled, &signers, &mut rng)
        .expect("LN18 signing setup");

    for param in params {
        let expected = key_shares
            .iter()
            .find(|share| share.party_index == param.key_share.party_index)
            .expect("signer share must exist");
        assert_eq!(param.key_share.secret_share, expected.secret_share);
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
    assert_eq!(Ln18::METADATA.keygen_rounds, 3);
}
