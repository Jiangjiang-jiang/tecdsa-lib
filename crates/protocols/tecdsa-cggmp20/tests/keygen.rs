// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_cggmp20::keygen::Cggmp20KeygenMachine;
use tecdsa_core::Csprng;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine};
use tecdsa_vss::shamir::{self, Share};

type C = k256::Secp256k1;

fn make_session_configs(n: u16, corrupted_t: u16) -> Vec<SessionConfig> {
    let session_id = SessionId([0u8; 32]);
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    (1..=n)
        .map(|i| SessionConfig {
            session_id: session_id.clone(),
            local_party: PartyInfo {
                id: PartyId(i),
                index: i,
                total: n,
                threshold: corrupted_t + 1,
            },
            parties: parties.clone(),
        })
        .collect()
}

/// Run the keygen state machines to completion without the Orchestrator
/// (which requires serde bounds that `ProjectivePoint` does not satisfy).
fn run_keygen(n: u16, corrupted_t: u16) -> Vec<tecdsa_cggmp20::key_share::Cggmp20CoreKeyShare<C>> {
    let configs = make_session_configs(n, corrupted_t);
    let mut rng = Csprng::new();

    let mut machines: Vec<(PartyId, Cggmp20KeygenMachine<C>)> = configs
        .iter()
        .map(|cfg| {
            (
                cfg.local_party.id,
                Cggmp20KeygenMachine::<C>::new(cfg, &mut rng),
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
                        let _ = machine.handle(from, outgoing.msg);
                    }
                }
                Recipient::Broadcast => {
                    for (pid, machine) in &mut machines {
                        if *pid != from {
                            let _ = machine.handle(from, outgoing.msg.clone());
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
    let shares = run_keygen(3, 1);

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
}

#[test]
#[ignore = "slow: larger threshold variant"]
fn keygen_3of5_produces_valid_shares() {
    let shares = run_keygen(5, 2);

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
}

#[test]
#[ignore = "slow: reconstruction test"]
fn keygen_2of3_shares_reconstruct_to_secret() {
    let shares = run_keygen(3, 1);

    // Take any 2 of 3 shares (party 0 and party 1).
    // Cggmp20CoreKeyShare.party_index is 0-based; Share index must be 1-based.
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
