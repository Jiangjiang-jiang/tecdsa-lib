#![allow(non_snake_case)]

use elliptic_curve::CurveArithmetic;
use tecdsa_class_group::cl::ClSetup;
use tecdsa_protocol::{
    ecdsa::{verify_ecdsa, DataToSign, Signature},
    Outgoing, PartyId, Recipient, StateMachine,
};
use tecdsa_tx25::{
    keygen::Tx25KeygenMachine,
    presign::{Tx25PresignMachine, Tx25Presignature},
    sign::{Tx25OnlineSignMachine, Tx25OnlineSignMsg},
    Tx25KeyShare,
};

fn run_protocol<M>(machines: Vec<(PartyId, M)>, max_rounds: u16) -> Vec<M::Output>
where
    M: StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    let orchestrator = tecdsa_testkit::Orchestrator::new(machines, max_rounds);
    let results = orchestrator.run().expect("orchestrator must succeed");
    results
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.unwrap_or_else(|e| panic!("party {i} finish() failed: {e}")))
        .collect()
}

fn run_single_round(machines: &mut [(PartyId, Tx25OnlineSignMachine)]) {
    let mut pending: Vec<(PartyId, Outgoing<Tx25OnlineSignMsg>)> = Vec::new();
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
                        .handle(from, outgoing.msg)
                        .unwrap_or_else(|e| panic!("handle from {from} to {to} failed: {e}"));
                }
            }
            Recipient::Broadcast => {
                for (pid, machine) in machines.iter_mut() {
                    if *pid != from {
                        machine
                            .handle(from, outgoing.msg.clone())
                            .unwrap_or_else(|e| panic!("handle from {from} to {pid} failed: {e}"));
                    }
                }
            }
        }
    }
}

#[test]
fn test_tx25_full_protocol_5_of_3() {
    let n = 5usize;
    let t = 3u16;
    let seed = "90001";
    let use_128bit_security = false;

    let party_ids: Vec<PartyId> = (1..=n as u16).map(PartyId).collect();

    let keygen_machines: Vec<(PartyId, Tx25KeygenMachine)> = party_ids
        .iter()
        .map(|&pid| {
            let machine =
                Tx25KeygenMachine::new(pid, party_ids.clone(), t, seed, use_128bit_security)
                    .unwrap_or_else(|e| panic!("keygen new() failed for party {pid}: {e}"));
            (pid, machine)
        })
        .collect();

    let key_shares: Vec<Tx25KeyShare> = run_protocol(keygen_machines, 10);

    let public_key = key_shares[0].public_key;
    for (i, share) in key_shares.iter().enumerate() {
        assert_eq!(
            public_key, share.public_key,
            "party {i} disagrees on joint public key"
        );
    }

    for i in 0..n {
        for j in (i + 1)..n {
            assert_ne!(
                key_shares[i].secret_share, key_shares[j].secret_share,
                "parties {i} and {j} have identical secret shares"
            );
        }
    }

    for share in &key_shares {
        let expected =
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * share.secret_share;
        let my_idx = (share.party_index - 1) as usize;
        assert_eq!(
            share.public_shares[my_idx], expected,
            "public_share mismatch for party {}",
            share.party_index
        );
    }

    let indices: Vec<u16> = (1..=n as u16).collect();
    let lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
    let reconstructed_pk = key_shares[0].public_shares.iter().zip(lambdas.iter()).fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, (x_j, l_j)| acc + *x_j * l_j,
    );
    assert_eq!(
        public_key, reconstructed_pk,
        "Lagrange reconstruction must match joint PK"
    );

    println!("KeyGen OK: n={n}, t={t}, all parties agree on joint public key");

    let presign_machines: Vec<(PartyId, Tx25PresignMachine)> = party_ids
        .iter()
        .enumerate()
        .map(|(i, &pid)| {
            let setup = if use_128bit_security {
                ClSetup::new_secp256k1_128bit(seed)
            } else {
                ClSetup::new_secp256k1(seed)
            }
            .unwrap_or_else(|e| panic!("ClSetup creation failed for party {i}: {e}"));

            let machine = Tx25PresignMachine::new(pid, party_ids.clone(), &key_shares[i], setup)
                .unwrap_or_else(|e| panic!("presign new() failed for party {pid}: {e}"));
            (pid, machine)
        })
        .collect();

    let presignatures: Vec<Tx25Presignature> = run_protocol(presign_machines, 10);

    let r_point = presignatures[0].r_point;
    let r_x = presignatures[0].r_x;
    for (i, presig) in presignatures.iter().enumerate() {
        assert_eq!(r_point, presig.r_point, "party {i} disagrees on R point");
        assert_eq!(r_x, presig.r_x, "party {i} disagrees on r_x");
    }

    for i in 0..n {
        for j in (i + 1)..n {
            assert_ne!(
                presignatures[i].k_share, presignatures[j].k_share,
                "parties {i} and {j} have identical k_share"
            );
        }
    }

    println!("Presign OK: all parties agree on R point and r_x");

    let message = b"test message for TX25 signing";

    let mut sign_machines: Vec<(PartyId, Tx25OnlineSignMachine)> = party_ids
        .iter()
        .enumerate()
        .map(|(i, &pid)| {
            let machine = Tx25OnlineSignMachine::new(
                pid,
                party_ids.clone(),
                presignatures[i].clone(),
                message,
                public_key,
            )
            .unwrap_or_else(|e| panic!("online sign new() failed for party {pid}: {e}"));
            (pid, machine)
        })
        .collect();

    run_single_round(&mut sign_machines);

    for (pid, machine) in &sign_machines {
        assert!(
            machine.is_done(),
            "online sign machine for party {pid} should be done"
        );
    }

    let signatures: Vec<Signature<k256::Secp256k1>> = sign_machines
        .into_iter()
        .map(|(pid, m)| {
            m.finish()
                .unwrap_or_else(|e| panic!("finish() failed for party {pid}: {e}"))
        })
        .collect();

    for (i, sig) in signatures.iter().enumerate().skip(1) {
        assert_eq!(signatures[0].r, sig.r, "party {i} produced different r");
        assert_eq!(signatures[0].s, sig.s, "party {i} produced different s");
    }

    let m = {
        use elliptic_curve::PrimeField;
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(message).into();
        let mut repr = k256::FieldBytes::default();
        repr.copy_from_slice(&hash);
        if let Some(s) = Option::from(k256::Scalar::from_repr(repr)) {
            s
        } else {
            repr[0] &= 0x7F;
            Option::from(k256::Scalar::from_repr(repr))
                .expect("scalar reduction must succeed after clearing top bit")
        }
    };

    let data_to_sign = DataToSign::<k256::Secp256k1>::from_digest(m);

    verify_ecdsa::<k256::Secp256k1>(&signatures[0], &public_key, &data_to_sign)
        .expect("ECDSA signature verification must pass");

    println!("Online Sign + Verify OK: valid ECDSA signature produced by {n} parties (t={t})");
    println!("  r = {:?}", signatures[0].r);
    println!("  s = {:?}", signatures[0].s);
}
