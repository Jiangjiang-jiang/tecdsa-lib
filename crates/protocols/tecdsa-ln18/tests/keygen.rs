use tecdsa_core::Csprng;
use tecdsa_curve::TecdsaCurve;
use tecdsa_ln18::keygen::Ln18KeygenMachine;
use tecdsa_protocol::{PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine};

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

fn run_keygen(n: u16, t: u16) -> Vec<tecdsa_ln18::key_share::Ln18KeyShare<C>> {
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

#[test]
fn keygen_2of2() {
    let shares = run_keygen(2, 2);
    assert_eq!(shares.len(), 2);

    let pk = shares[0].public_key;
    for s in &shares {
        assert_eq!(s.public_key, pk, "public keys must agree");
    }

    assert_eq!(
        shares[0].public_shares, shares[1].public_shares,
        "public_shares must be consistent"
    );

    let signer_pts: Vec<u16> = (1..=2).collect();
    let lagrange = tecdsa_vss::lagrange::coefficients::<C>(&signer_pts);
    let reconstructed_x: <C as elliptic_curve::CurveArithmetic>::Scalar = shares
        .iter()
        .zip(lagrange.iter())
        .map(|(s, l)| s.secret_share * l)
        .reduce(|acc, x| acc + x)
        .unwrap();
    let expected_pk = C::generator() * reconstructed_x;
    assert_eq!(pk, expected_pk, "Q must equal reconstructed_x * G");

    for (i, s) in shares.iter().enumerate() {
        let expected = C::generator() * s.secret_share;
        assert_eq!(
            s.public_shares[i], expected,
            "public_shares[{i}] must equal secret_share * G"
        );
    }

    for s in &shares {
        assert_eq!(s.n, 2);
        assert_eq!(s.t, 2);
    }
}

#[test]
fn keygen_2of3() {
    let shares = run_keygen(3, 2);
    assert_eq!(shares.len(), 3);

    let pk = shares[0].public_key;
    for s in &shares {
        assert_eq!(s.public_key, pk, "public keys must agree");
    }

    for i in 1..shares.len() {
        assert_eq!(
            shares[i].public_shares, shares[0].public_shares,
            "public_shares must be consistent"
        );
    }

    for subset in &[[1u16, 2], [1, 3], [2, 3]] {
        let lagrange = tecdsa_vss::lagrange::coefficients::<C>(subset);
        let reconstructed: <C as elliptic_curve::CurveArithmetic>::Scalar = subset
            .iter()
            .zip(lagrange.iter())
            .map(|(&idx, l)| shares[(idx - 1) as usize].secret_share * l)
            .reduce(|acc, x| acc + x)
            .unwrap();
        let expected_pk = C::generator() * reconstructed;
        assert_eq!(
            pk, expected_pk,
            "Q must equal reconstructed x * G for subset {subset:?}"
        );
    }

    for (i, s) in shares.iter().enumerate() {
        let expected = C::generator() * s.secret_share;
        assert_eq!(
            s.public_shares[i], expected,
            "public_shares[{i}] must equal secret_share * G"
        );
    }

    for s in &shares {
        assert_eq!(s.n, 3);
        assert_eq!(s.t, 2);
    }
}

#[test]
fn keygen_3of3() {
    let shares = run_keygen(3, 3);
    assert_eq!(shares.len(), 3);

    let pk = shares[0].public_key;
    for s in &shares {
        assert_eq!(s.public_key, pk, "public keys must agree");
    }

    for i in 1..shares.len() {
        assert_eq!(
            shares[i].public_shares, shares[0].public_shares,
            "public_shares must be consistent"
        );
    }

    let signer_pts: Vec<u16> = (1..=3).collect();
    let lagrange = tecdsa_vss::lagrange::coefficients::<C>(&signer_pts);
    let reconstructed: <C as elliptic_curve::CurveArithmetic>::Scalar = shares
        .iter()
        .zip(lagrange.iter())
        .map(|(s, l)| s.secret_share * l)
        .reduce(|acc, x| acc + x)
        .unwrap();
    let expected_pk = C::generator() * reconstructed;
    assert_eq!(pk, expected_pk, "Q must equal sum(lambda_i * x_i) * G");

    for (i, s) in shares.iter().enumerate() {
        let expected = C::generator() * s.secret_share;
        assert_eq!(s.public_shares[i], expected);
    }

    for s in &shares {
        assert_eq!(s.n, 3);
        assert_eq!(s.t, 3);
    }
}

#[test]
#[ignore = "slow: larger/variant test"]
fn keygen_5of5() {
    let shares = run_keygen(5, 5);
    assert_eq!(shares.len(), 5);

    let pk = shares[0].public_key;
    for s in &shares {
        assert_eq!(s.public_key, pk, "public keys must agree");
    }

    let signer_pts: Vec<u16> = (1..=5).collect();
    let lagrange = tecdsa_vss::lagrange::coefficients::<C>(&signer_pts);
    let reconstructed: <C as elliptic_curve::CurveArithmetic>::Scalar = shares
        .iter()
        .zip(lagrange.iter())
        .map(|(s, l)| s.secret_share * l)
        .reduce(|acc, x| acc + x)
        .unwrap();
    let expected_pk = C::generator() * reconstructed;
    assert_eq!(pk, expected_pk, "Q must equal sum(lambda_i * x_i) * G");
}
