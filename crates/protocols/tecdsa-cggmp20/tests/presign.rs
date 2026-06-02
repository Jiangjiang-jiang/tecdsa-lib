// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_cggmp20::aux_info::AuxInfoMachine;
use tecdsa_cggmp20::key_share::{AuxInfo, Cggmp20CoreKeyShare};
use tecdsa_cggmp20::keygen::Cggmp20KeygenMachine;
use tecdsa_cggmp20::presign::Cggmp20PresignMachine;
use tecdsa_cggmp20::security_level::Cggmp20SecurityParams;
use tecdsa_cggmp20::sign::types::{Presignature, PresignaturePublicData};
use tecdsa_core::Csprng;
use tecdsa_protocol::{PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine};

type C = k256::Secp256k1;

/// Test-only security level with small primes for fast tests.
#[derive(Debug, Clone, Copy)]
struct TestLevel;

impl Cggmp20SecurityParams for TestLevel {
    const RSA_PRIME_BITS: u32 = 513;
    const RSA_MODULUS_BITS: u32 = 1025;
    const EPSILON: usize = 512;
    const ELL: usize = 256;
    const ELL_PRIME: usize = 256;
    const KAPPA: usize = 128;
}

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

/// Make session configs for only the signing subset.
fn make_signer_configs(signers: &[u16], n: u16, corrupted_t: u16) -> Vec<SessionConfig> {
    let session_id = SessionId([1u8; 32]); // different session id for presign
    let parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
    signers
        .iter()
        .map(|&i| SessionConfig {
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

/// Run keygen and return CoreKeyShares.
fn run_keygen(n: u16, corrupted_t: u16) -> Vec<Cggmp20CoreKeyShare<C>> {
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

    for _round in 0..10u16 {
        if machines.iter().all(|(_, m)| m.is_done()) {
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
        .map(|(_, m)| m.finish().expect("keygen must succeed"))
        .collect()
}

/// Run aux-info and return AuxInfos.
fn run_aux_info(n: u16) -> Vec<AuxInfo> {
    let configs = make_session_configs(n, 1); // threshold doesn't matter for aux_info
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

    for _round in 0..10u16 {
        if machines.iter().all(|(_, m)| m.is_done()) {
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

/// Run presign given core shares and aux info for the signing subset.
fn run_presign(
    core_shares: &[Cggmp20CoreKeyShare<C>],
    aux_infos: &[AuxInfo],
    signers: &[u16],
) -> Vec<(Presignature<C>, PresignaturePublicData<C>)> {
    let n = core_shares.len() as u16;
    let corrupted_t = core_shares[0].vss_setup.threshold - 1;
    let signer_configs = make_signer_configs(signers, n, corrupted_t);
    let mut rng = Csprng::new();

    // Build machines only for the signing parties
    let mut machines: Vec<(PartyId, Cggmp20PresignMachine<C>)> = signers
        .iter()
        .enumerate()
        .map(|(idx, &signer_1based)| {
            let party_0based = (signer_1based - 1) as usize;
            let pid = PartyId(signer_1based);
            let machine = Cggmp20PresignMachine::<C>::with_security::<TestLevel>(
                &signer_configs[idx],
                &core_shares[party_0based],
                &aux_infos[party_0based],
                signers,
                &mut rng,
            );
            (pid, machine)
        })
        .collect();

    for round_num in 0..10u16 {
        if machines.iter().all(|(_, m)| m.is_done()) {
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
                        machine.handle(from, outgoing.msg).unwrap_or_else(|e| {
                            panic!("round {round_num}: P2P {}->{}: {e}", from.0, to.0)
                        });
                    }
                }
                Recipient::Broadcast => {
                    for (pid, machine) in &mut machines {
                        if *pid != from {
                            machine
                                .handle(from, outgoing.msg.clone())
                                .unwrap_or_else(|e| {
                                    panic!(
                                        "round {round_num}: broadcast {}->{}:  {e}",
                                        from.0, pid.0
                                    )
                                });
                        }
                    }
                }
            }
        }
    }

    machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("presign must succeed"))
        .collect()
}

#[test]
fn presign_2of3() {
    let core_shares = run_keygen(3, 1);
    let aux_infos = run_aux_info(3);
    let signers = vec![1u16, 2];
    let presigs = run_presign(&core_shares, &aux_infos, &signers);

    assert_eq!(presigs.len(), 2);

    // All signing parties agree on R.
    let r0 = presigs[0].1.big_r;
    for (_, pub_data) in &presigs {
        assert_eq!(pub_data.big_r, r0, "all parties must agree on R");
    }

    // The presignature R must not be the identity point.
    assert_ne!(
        r0,
        <C as elliptic_curve::CurveArithmetic>::ProjectivePoint::default(),
        "R must not be identity"
    );
}

#[test]
#[ignore = "slow: 3-of-3 variant"]
fn presign_3of3() {
    let core_shares = run_keygen(3, 1);
    let aux_infos = run_aux_info(3);
    let signers = vec![1u16, 2, 3];
    let presigs = run_presign(&core_shares, &aux_infos, &signers);

    assert_eq!(presigs.len(), 3);

    // All parties agree on R.
    let r0 = presigs[0].1.big_r;
    for (_, pub_data) in &presigs {
        assert_eq!(pub_data.big_r, r0, "all parties must agree on R");
    }
}

#[test]
#[ignore = "slow: subset variant"]
fn presign_different_signer_subsets_produce_different_r() {
    let core_shares = run_keygen(3, 1);
    let aux_infos = run_aux_info(3);

    let presigs_12 = run_presign(&core_shares, &aux_infos, &[1, 2]);
    let presigs_13 = run_presign(&core_shares, &aux_infos, &[1, 3]);

    // Different signing subsets should (with overwhelming probability)
    // produce different R values since k_i are freshly sampled.
    assert_ne!(
        presigs_12[0].1.big_r, presigs_13[0].1.big_r,
        "different presign sessions should produce different R"
    );
}
