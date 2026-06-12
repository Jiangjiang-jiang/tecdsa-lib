use tecdsa_cggmp20::{aux_info::AuxInfoMachine, security_level::Cggmp20SecurityParams};
use tecdsa_core::Csprng;
use tecdsa_paillier::backend::Integer;
use tecdsa_protocol::{PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine};

#[derive(Debug, Clone, Copy)]
struct TestLevel;

impl Cggmp20SecurityParams for TestLevel {
    const RSA_PRIME_BITS: u32 = 256;
    const RSA_MODULUS_BITS: u32 = 511;
    const EPSILON: usize = 128;
    const ELL: usize = 64;
    const ELL_PRIME: usize = 128;
    const KAPPA: usize = 128;
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

fn run_auxinfo(n: u16, t: u16) -> Vec<tecdsa_cggmp20::key_share::AuxInfo> {
    let configs = make_session_configs(n, t);
    let mut rng = Csprng::new();

    let mut machines: Vec<(PartyId, AuxInfoMachine<TestLevel>)> = configs
        .iter()
        .map(|cfg| {
            (
                cfg.local_party.id,
                AuxInfoMachine::<TestLevel>::new(cfg, &mut rng),
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
        .map(|(_, m)| m.finish().expect("auxinfo must succeed"))
        .collect()
}

#[test]
#[ignore = "slow: 3-party auxinfo"]
fn auxinfo_3_parties() {
    let results = run_auxinfo(3, 2);

    assert_eq!(results.len(), 3);

    for r in &results {
        assert_eq!(r.paillier_eks.len(), 3);
        assert_eq!(r.pedersen_params.len(), 3);
    }

    for i in 0..3 {
        for j in 0..3 {
            assert_eq!(
                results[0].paillier_eks[i].n().to_bytes_msf(),
                results[j].paillier_eks[i].n().to_bytes_msf(),
                "party {j} must agree on ek[{i}]"
            );
        }
    }

    for i in 0..3 {
        for j in 0..3 {
            assert_eq!(
                results[0].pedersen_params[i].n, results[j].pedersen_params[i].n,
                "party {j} must agree on pedersen[{i}].n"
            );
            assert_eq!(
                results[0].pedersen_params[i].s, results[j].pedersen_params[i].s,
                "party {j} must agree on pedersen[{i}].s"
            );
            assert_eq!(
                results[0].pedersen_params[i].t, results[j].pedersen_params[i].t,
                "party {j} must agree on pedersen[{i}].t"
            );
        }
    }

    for r in &results {
        let ek = &r.paillier_eks[r.party_index as usize];
        let plaintext = Integer::from(42);
        let (ciphertext, _nonce) = ek
            .encrypt_with_random(&mut Csprng::new(), &plaintext)
            .expect("encryption must succeed");
        let decrypted = r.dk.decrypt(&ciphertext).expect("decryption must succeed");
        assert_eq!(decrypted, plaintext, "decryption must recover plaintext");
    }

    for r in &results {
        let own_ek = &r.paillier_eks[r.party_index as usize];
        assert_eq!(
            r.dk.encryption_key().n().to_bytes_msf(),
            own_ek.n().to_bytes_msf(),
            "dk and ek must have matching N"
        );
    }

    for (i, r) in results.iter().enumerate() {
        assert_eq!(r.party_index, i as u16, "party_index must be 0-based");
    }
}

#[test]
fn auxinfo_2_parties() {
    let results = run_auxinfo(2, 2);

    assert_eq!(results.len(), 2);

    for r in &results {
        assert_eq!(r.paillier_eks.len(), 2);
        assert_eq!(r.pedersen_params.len(), 2);
    }

    for i in 0..2 {
        assert_eq!(
            results[0].paillier_eks[i].n().to_bytes_msf(),
            results[1].paillier_eks[i].n().to_bytes_msf(),
        );
    }
}
