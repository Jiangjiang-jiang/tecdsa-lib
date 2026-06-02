// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_core::Csprng;
use tecdsa_curve::TecdsaCurve;
use tecdsa_ln18::keygen::Ln18KeygenMachine;
use tecdsa_protocol::{PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine};

type C = k256::Secp256k1;

fn make_session_configs(n: u16, corrupted_t: u16) -> Vec<SessionConfig> {
    let session_id = SessionId([0u8; 32]);
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();
    (0..n)
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

/// Run the LN18 keygen state machines to completion using a manual round loop.
fn run_keygen(n: u16, corrupted_t: u16) -> Vec<tecdsa_ln18::key_share::Ln18KeyShare<C>> {
    let configs = make_session_configs(n, corrupted_t);
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
fn keygen_2of2() {
    let shares = run_keygen(2, 1);
    assert_eq!(shares.len(), 2);

    // All parties agree on the public key.
    let pk = shares[0].public_key;
    for s in &shares {
        assert_eq!(s.public_key, pk, "public keys must agree");
    }

    // All parties agree on the ElGamal public key.
    let eg_pk = shares[0].elgamal_pk;
    for s in &shares {
        assert_eq!(s.elgamal_pk, eg_pk, "ElGamal public keys must agree");
    }

    // Verify: Q = sum(x_i) * G
    let sum_x: <C as elliptic_curve::CurveArithmetic>::Scalar = shares
        .iter()
        .map(|s| s.secret_share)
        .reduce(|acc, x| acc + x)
        .unwrap();
    let expected_pk = C::generator() * sum_x;
    assert_eq!(pk, expected_pk, "Q must equal sum(x_i) * G");

    // Verify: ElGamal PK = sum(d_i) * G
    let sum_d: <C as elliptic_curve::CurveArithmetic>::Scalar = shares
        .iter()
        .map(|s| s.elgamal_dk)
        .reduce(|acc, d| acc + d)
        .unwrap();
    let expected_eg_pk = C::generator() * sum_d;
    assert_eq!(eg_pk, expected_eg_pk, "ElGamal PK must equal sum(d_i) * G");

    // Verify: ElGamal pk_shares are consistent across parties.
    for s in &shares {
        assert_eq!(
            s.elgamal_pk_shares.len(),
            2,
            "should have n ElGamal pk shares"
        );
    }
    assert_eq!(
        shares[0].elgamal_pk_shares, shares[1].elgamal_pk_shares,
        "ElGamal pk_shares must be consistent"
    );

    // Verify: n and t are correct.
    for s in &shares {
        assert_eq!(s.n, 2);
        assert_eq!(s.t, 2);
    }
}

#[test]
fn keygen_3of3() {
    let shares = run_keygen(3, 2);
    assert_eq!(shares.len(), 3);

    // All parties agree on the public key.
    let pk = shares[0].public_key;
    for s in &shares {
        assert_eq!(s.public_key, pk, "public keys must agree");
    }

    // All parties agree on the ElGamal public key.
    let eg_pk = shares[0].elgamal_pk;
    for s in &shares {
        assert_eq!(s.elgamal_pk, eg_pk, "ElGamal public keys must agree");
    }

    // Verify: Q = sum(x_i) * G
    let sum_x: <C as elliptic_curve::CurveArithmetic>::Scalar = shares
        .iter()
        .map(|s| s.secret_share)
        .reduce(|acc, x| acc + x)
        .unwrap();
    let expected_pk = C::generator() * sum_x;
    assert_eq!(pk, expected_pk, "Q must equal sum(x_i) * G");

    // Verify: ElGamal pk_shares are consistent across all parties.
    for i in 1..shares.len() {
        assert_eq!(
            shares[i].elgamal_pk_shares, shares[0].elgamal_pk_shares,
            "ElGamal pk_shares must be consistent"
        );
    }

    // Verify: all parties have correct n and t.
    for s in &shares {
        assert_eq!(s.n, 3);
        assert_eq!(s.t, 3);
    }
}

#[test]
#[ignore = "slow: larger/variant test"]
fn keygen_5of5() {
    let shares = run_keygen(5, 4);
    assert_eq!(shares.len(), 5);

    // All parties agree on the public key.
    let pk = shares[0].public_key;
    for s in &shares {
        assert_eq!(s.public_key, pk, "public keys must agree");
    }

    // Verify: Q = sum(x_i) * G
    let sum_x: <C as elliptic_curve::CurveArithmetic>::Scalar = shares
        .iter()
        .map(|s| s.secret_share)
        .reduce(|acc, x| acc + x)
        .unwrap();
    let expected_pk = C::generator() * sum_x;
    assert_eq!(pk, expected_pk, "Q must equal sum(x_i) * G");
}
