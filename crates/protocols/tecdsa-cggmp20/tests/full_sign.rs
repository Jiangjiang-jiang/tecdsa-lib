// SPDX-License-Identifier: MIT OR Apache-2.0
use elliptic_curve::ops::{LinearCombination, Reduce};
use sha2::{Digest, Sha256};
use tecdsa_cggmp20::{
    aux_info::AuxInfoMachine,
    full_sign::FullSignMachine,
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    keygen::Cggmp20KeygenMachine,
    security_level::Cggmp20SecurityParams,
    sign::types::DataToSign,
};
use tecdsa_core::Csprng;
use tecdsa_curve::TecdsaCurve;
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

fn make_signer_configs(signers: &[u16], n: u16, t: u16) -> Vec<SessionConfig> {
    let session_id = SessionId([1u8; 32]);
    let parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
    signers
        .iter()
        .map(|&i| SessionConfig {
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

fn run_keygen(n: u16, t: u16) -> Vec<Cggmp20CoreKeyShare<C>> {
    let configs = make_session_configs(n, t);
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

fn run_aux_info(n: u16) -> Vec<AuxInfo> {
    let configs = make_session_configs(n, 2);
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

/// Build a DataToSign from a message by SHA-256 hashing and reducing mod q.
fn make_data_to_sign(message: &[u8]) -> DataToSign<C> {
    let hash_bytes: [u8; 32] = Sha256::digest(message).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    DataToSign::from_digest(scalar)
}

/// Manual ECDSA verify: check s^{-1}*(m*G + r*PK) has x-coordinate equal to r.
fn verify_signature(
    sig_r: k256::Scalar,
    sig_s: k256::Scalar,
    message: &DataToSign<C>,
    public_key: &<C as elliptic_curve::CurveArithmetic>::ProjectivePoint,
) {
    let m = *message.digest();
    let r = sig_r;
    let s_inv = sig_s.invert().into_option().expect("s must not be zero");
    let u1 = m * s_inv;
    let u2 = r * s_inv;
    let check_point = <C as elliptic_curve::CurveArithmetic>::ProjectivePoint::lincomb(&[
        (C::generator(), u1),
        (*public_key, u2),
    ]);
    let check_r = C::xcoord_mod_q(&check_point.to_affine());
    assert_eq!(check_r, r, "manual ECDSA verification must succeed");
}

/// Run the full-signing protocol for the given signing subset and return the signature.
fn run_full_sign(
    core_shares: &[Cggmp20CoreKeyShare<C>],
    aux_infos: &[AuxInfo],
    signers: &[u16],
    message: &[u8],
) -> tecdsa_cggmp20::sign::types::Signature<C> {
    let n = core_shares.len() as u16;
    let t = core_shares[0].vss_setup.threshold;
    let signer_configs = make_signer_configs(signers, n, t);
    let mut rng = Csprng::new();

    let data_to_sign = make_data_to_sign(message);

    let mut machines: Vec<(PartyId, FullSignMachine<C>)> = signers
        .iter()
        .enumerate()
        .map(|(idx, &signer_1based)| {
            let party_0based = (signer_1based - 1) as usize;
            let pid = PartyId(signer_1based);
            let machine = FullSignMachine::<C>::with_security::<TestLevel>(
                &signer_configs[idx],
                &core_shares[party_0based],
                &aux_infos[party_0based],
                signers,
                data_to_sign,
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

    assert!(
        machines.iter().all(|(_, m)| m.is_done()),
        "all machines must be done after the loop"
    );

    // All parties should produce the same signature; return the first one.
    let sigs: Vec<_> = machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("full_sign must succeed"))
        .collect();

    // Check all parties agree on the signature.
    let r0 = sigs[0].r;
    let s0 = sigs[0].s;
    for sig in &sigs {
        assert_eq!(sig.r, r0, "all parties must agree on r");
        assert_eq!(sig.s, s0, "all parties must agree on s");
    }

    sigs.into_iter().next().unwrap()
}

#[test]
#[ignore = "slow: full keygen + auxinfo + presign + sign (~10 min in debug)"]
fn full_sign_2of3() {
    let core_shares = run_keygen(3, 2);
    let aux_infos = run_aux_info(3);
    let signers = [1u16, 2];

    let data_to_sign = make_data_to_sign(b"test message");
    let sig = run_full_sign(&core_shares, &aux_infos, &signers, b"test message");

    // Verify the signature is valid.
    let public_key = &core_shares[0].public_key;
    verify_signature(sig.r, sig.s, &data_to_sign, public_key);
}

#[test]
#[ignore = "slow: full keygen + auxinfo + presign + sign (~10 min in debug)"]
fn full_sign_3of3() {
    let core_shares = run_keygen(3, 2);
    let aux_infos = run_aux_info(3);
    let signers = [1u16, 2, 3];

    let data_to_sign = make_data_to_sign(b"test message");
    let sig = run_full_sign(&core_shares, &aux_infos, &signers, b"test message");

    // Verify the signature is valid.
    let public_key = &core_shares[0].public_key;
    verify_signature(sig.r, sig.s, &data_to_sign, public_key);
}
