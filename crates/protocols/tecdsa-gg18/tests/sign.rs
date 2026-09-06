// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the GG18 signing protocol.
//!
//! Tests keygen -> presign -> online_sign -> ECDSA verify end-to-end.

#![allow(non_snake_case)]

use elliptic_curve::PrimeField;
use rug::Integer;
use sha2::{Digest, Sha256};
use tecdsa_core::Csprng;
use tecdsa_gg18::{
    key_share::Gg18KeyShare,
    keygen::{generate_n_tilde, Gg18KeygenMachine, PaillierPrecomputed},
    presign::{Gg18PresignMachine, Gg18Presignature, PresignConfig},
    sign::{Gg18OnlineSignMachine, OnlineSignConfig},
};
use tecdsa_paillier::{BigIntExt, DecryptionKey};
use tecdsa_protocol::{
    verify_ecdsa, DataToSign, PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine,
};

type C = k256::Secp256k1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn test_paillier_dk(rng: &mut impl rand_core::CryptoRngCore) -> DecryptionKey {
    // Use 512-bit primes (N ~ 1024 bits) to ensure MtA correctness.
    let p = Integer::generate_safe_prime(rng, 512);
    let q = Integer::generate_safe_prime(rng, 512);
    DecryptionKey::from_primes(p, q).expect("valid primes")
}

fn test_precomputed(rng: &mut impl rand_core::CryptoRngCore) -> PaillierPrecomputed {
    let dk = test_paillier_dk(rng);
    let dk_tilde = test_paillier_dk(rng);
    let n_tilde_params = generate_n_tilde(&dk_tilde, rng);
    PaillierPrecomputed { dk, n_tilde_params }
}

/// Run keygen to produce key shares.
fn run_keygen(n: u16, t: u16) -> Vec<Gg18KeyShare<C>> {
    let configs = make_session_configs(n, t);
    let mut rng = Csprng::new();

    let mut machines: Vec<(PartyId, Gg18KeygenMachine<C>)> = configs
        .iter()
        .map(|cfg| {
            let precomputed = test_precomputed(&mut rng);
            (
                cfg.local_party.id,
                Gg18KeygenMachine::<C>::new_with_precomputed(cfg, precomputed, &mut rng),
            )
        })
        .collect();

    run_machines(&mut machines);

    machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("keygen must succeed"))
        .collect()
}

/// Generic round-loop runner for any StateMachine.
fn run_machines<M: StateMachine>(machines: &mut [(PartyId, M)])
where
    M::Outbound: Into<M::Inbound> + Clone,
{
    let max_rounds = 50u16;
    for _round in 0..max_rounds {
        if machines.iter().all(|(_, m)| m.is_done()) {
            break;
        }

        let mut pending = Vec::new();
        for (pid, machine) in machines.iter_mut() {
            for msg in machine.drain_outgoing() {
                pending.push((*pid, msg));
            }
        }

        for (from, outgoing) in pending {
            match outgoing.to {
                Recipient::Party(to) => {
                    if let Some((_, machine)) = machines.iter_mut().find(|(p, _)| *p == to) {
                        machine
                            .handle(from, outgoing.msg.into())
                            .unwrap_or_else(|e| panic!("handle error from {from} to {to}: {e}"));
                    }
                }
                Recipient::Broadcast => {
                    for (pid, machine) in machines.iter_mut() {
                        if *pid != from {
                            machine
                                .handle(from, outgoing.msg.clone().into())
                                .unwrap_or_else(|e| {
                                    panic!("handle error from {from} to {pid}: {e}")
                                });
                        }
                    }
                }
            }
        }
    }
}

/// Prepare a message digest for signing.
fn test_message_digest() -> DataToSign<C> {
    let hash = Sha256::digest(b"hello world");
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    let scalar = <C as elliptic_curve::CurveArithmetic>::Scalar::from_repr(
        elliptic_curve::FieldBytes::<C>::from(bytes),
    )
    .expect("hash must be valid scalar");
    DataToSign::from_digest(scalar)
}

/// Run the presigning protocol to completion.
fn run_presign(shares: &[Gg18KeyShare<C>], signer_indices: &[u16]) -> Vec<Gg18Presignature<C>> {
    let mut rng = Csprng::new();

    let mut machines: Vec<(PartyId, Gg18PresignMachine<C>)> = signer_indices
        .iter()
        .map(|&idx| {
            let share = shares[(idx - 1) as usize].clone();
            let pid = PartyId(idx);
            let config = PresignConfig {
                key_share: share,
                signers: signer_indices.to_vec(),
            };
            (pid, Gg18PresignMachine::new(config, &mut rng))
        })
        .collect();

    run_machines(&mut machines);

    assert!(
        machines.iter().all(|(_, m)| m.is_done()),
        "all presign machines must complete"
    );

    machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("presign must succeed"))
        .collect()
}

/// Run the online signing protocol to completion.
fn run_online_sign(
    presignatures: Vec<Gg18Presignature<C>>,
    message: DataToSign<C>,
) -> tecdsa_protocol::Signature<C> {
    let mut rng = Csprng::new();

    let mut machines: Vec<(PartyId, Gg18OnlineSignMachine<C>)> = presignatures
        .into_iter()
        .map(|presig| {
            let pid = presig.my_id;
            let config = OnlineSignConfig {
                presignature: presig,
                message,
            };
            (pid, Gg18OnlineSignMachine::new(config, &mut rng))
        })
        .collect();

    run_machines(&mut machines);

    assert!(
        machines.iter().all(|(_, m)| m.is_done()),
        "all online sign machines must complete"
    );

    // All machines should produce the same signature
    let sigs: Vec<_> = machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("online sign must succeed"))
        .collect();

    // Verify all signatures are identical
    for i in 1..sigs.len() {
        assert_eq!(sigs[i].r, sigs[0].r, "all signers must agree on r");
        assert_eq!(sigs[i].s, sigs[0].s, "all signers must agree on s");
    }

    sigs.into_iter().next().unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn presign_2of3_produces_valid_presignature() {
    let shares = run_keygen(3, 2);

    // Presign with parties [1, 2]
    let presigs = run_presign(&shares, &[1, 2]);
    assert_eq!(presigs.len(), 2);

    // Verify all presignatures agree on R and r
    assert_eq!(presigs[0].R, presigs[1].R, "all parties must agree on R");
    assert_eq!(presigs[0].r, presigs[1].r, "all parties must agree on r");
}

#[test]
fn sign_2of3_verifies() {
    let shares = run_keygen(3, 2);
    let message = test_message_digest();

    // Presign with parties [1, 2]
    let presigs = run_presign(&shares, &[1, 2]);

    // Online sign with the presignatures + message
    let sig = run_online_sign(presigs, message);

    // ECDSA verify
    verify_ecdsa::<C>(&sig, &shares[0].public_key, &message).expect("signature must verify");
}

#[test]
fn sign_3of5_verifies() {
    let shares = run_keygen(5, 3);
    let message = test_message_digest();

    // Presign with parties [1, 2, 3]
    let presigs = run_presign(&shares, &[1, 2, 3]);

    // Online sign with the presignatures + message
    let sig = run_online_sign(presigs, message);

    // ECDSA verify
    verify_ecdsa::<C>(&sig, &shares[0].public_key, &message).expect("signature must verify");
}

#[test]
fn presign_reuse_different_messages() {
    // Verify that the same keygen can produce different presignatures
    // and sign different messages
    let shares = run_keygen(3, 2);

    let msg1 = {
        let hash = Sha256::digest(b"message one");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        let scalar = <C as elliptic_curve::CurveArithmetic>::Scalar::from_repr(
            elliptic_curve::FieldBytes::<C>::from(bytes),
        )
        .expect("hash must be valid scalar");
        DataToSign::from_digest(scalar)
    };

    let msg2 = {
        let hash = Sha256::digest(b"message two");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        let scalar = <C as elliptic_curve::CurveArithmetic>::Scalar::from_repr(
            elliptic_curve::FieldBytes::<C>::from(bytes),
        )
        .expect("hash must be valid scalar");
        DataToSign::from_digest(scalar)
    };

    // Two independent presigning sessions
    let presigs1 = run_presign(&shares, &[1, 2]);
    let presigs2 = run_presign(&shares, &[1, 2]);

    // Sign different messages with different presignatures
    let sig1 = run_online_sign(presigs1, msg1);
    let sig2 = run_online_sign(presigs2, msg2);

    verify_ecdsa::<C>(&sig1, &shares[0].public_key, &msg1).expect("sig1 must verify");
    verify_ecdsa::<C>(&sig2, &shares[0].public_key, &msg2).expect("sig2 must verify");
}
