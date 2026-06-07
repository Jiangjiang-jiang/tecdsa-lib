// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_core::Csprng;
use tecdsa_curve::TecdsaCurve;
use tecdsa_gg18::keygen::{generate_n_tilde, Gg18KeygenMachine, PaillierPrecomputed};
use tecdsa_paillier::{backend::Integer, DecryptionKey};
use tecdsa_protocol::{PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine};
use tecdsa_vss::shamir::{self, Share};

type C = k256::Secp256k1;

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

/// Generate a small Paillier keypair for testing (256-bit primes).
fn test_paillier_dk(rng: &mut impl rand_core::CryptoRngCore) -> DecryptionKey {
    let p = Integer::generate_safe_prime(rng, 256);
    let q = Integer::generate_safe_prime(rng, 256);
    DecryptionKey::from_primes(p, q).expect("valid primes")
}

/// Generate precomputed Paillier keys + N_tilde params with small primes.
fn test_precomputed(rng: &mut impl rand_core::CryptoRngCore) -> PaillierPrecomputed {
    let dk = test_paillier_dk(rng);
    let dk_tilde = test_paillier_dk(rng);
    let n_tilde_params = generate_n_tilde(&dk_tilde, rng);
    PaillierPrecomputed { dk, n_tilde_params }
}

/// Run the GG18 keygen state machines to completion using a manual round loop.
fn run_keygen(n: u16, t: u16) -> Vec<tecdsa_gg18::key_share::Gg18KeyShare<C>> {
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

    let max_rounds = 10u16;
    for _round in 0..max_rounds {
        let all_done = machines.iter().all(|(_, m)| m.is_done());
        if all_done {
            break;
        }

        // Collect outgoing messages from every machine.
        let mut pending = Vec::new();
        for (pid, machine) in &mut machines {
            for msg in machine.drain_outgoing() {
                pending.push((*pid, msg));
            }
        }

        // Route each message to its recipients.
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

#[test]
fn keygen_2of3_produces_valid_shares() {
    let shares = run_keygen(3, 2);

    assert_eq!(shares.len(), 3);

    // All parties agree on the public key.
    let pk = shares[0].public_key;
    for s in &shares {
        assert_eq!(s.public_key, pk, "public keys must agree");
    }

    // All parties have n=3 public shares.
    for s in &shares {
        assert_eq!(s.public_shares.len(), 3);
    }

    // Public shares are consistent across all parties.
    for i in 1..shares.len() {
        assert_eq!(
            shares[i].public_shares, shares[0].public_shares,
            "public shares must be consistent"
        );
    }

    // VSS setup is correct.
    for s in &shares {
        assert_eq!(s.vss_setup.threshold, 2);
        assert_eq!(s.vss_setup.total, 3);
    }

    // Each party has the correct number of Paillier EKs and N_tilde params.
    for s in &shares {
        assert_eq!(s.paillier_eks.len(), 3);
        assert_eq!(s.n_tilde_params.len(), 3);
    }
}

#[test]
fn keygen_3of5_produces_valid_shares() {
    let shares = run_keygen(5, 3);

    assert_eq!(shares.len(), 5);

    // All parties agree on the public key.
    let pk = shares[0].public_key;
    for s in &shares {
        assert_eq!(s.public_key, pk, "public keys must agree");
    }

    // All parties have n=5 public shares.
    for s in &shares {
        assert_eq!(s.public_shares.len(), 5);
    }

    // Public shares are consistent across all parties.
    for i in 1..shares.len() {
        assert_eq!(
            shares[i].public_shares, shares[0].public_shares,
            "public shares must be consistent"
        );
    }

    // VSS setup is correct.
    for s in &shares {
        assert_eq!(s.vss_setup.threshold, 3);
        assert_eq!(s.vss_setup.total, 5);
    }

    // Each party has correct number of Paillier and N_tilde params.
    for s in &shares {
        assert_eq!(s.paillier_eks.len(), 5);
        assert_eq!(s.n_tilde_params.len(), 5);
    }
}

#[test]
fn keygen_2of3_shares_reconstruct_to_secret() {
    let shares = run_keygen(3, 2);

    // Take any 2 of 3 shares (party 0 and party 1).
    // Gg18KeyShare.party_index is 0-based; Share index must be 1-based.
    let subset: Vec<Share<C>> = shares[..2]
        .iter()
        .map(|s| Share {
            index: s.party_index + 1,
            value: s.secret_share,
        })
        .collect();

    let reconstructed = shamir::reconstruct::<C>(&subset);

    // Verify: secret * G == public_key
    let derived_pk = C::generator() * reconstructed;
    assert_eq!(
        derived_pk, shares[0].public_key,
        "reconstructed secret must match the joint public key"
    );
}
