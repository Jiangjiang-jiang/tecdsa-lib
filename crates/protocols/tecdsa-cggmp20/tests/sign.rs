// SPDX-License-Identifier: MIT OR Apache-2.0
use elliptic_curve::ops::{LinearCombination, Reduce};
use sha2::{Digest, Sha256};
use tecdsa_cggmp20::{
    aux_info::AuxInfoMachine,
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    keygen::Cggmp20KeygenMachine,
    presign::Cggmp20PresignMachine,
    security_level::Cggmp20SecurityParams,
    sign::types::{DataToSign, PartialSignature, Presignature, PresignaturePublicData},
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

fn make_signer_configs(signers: &[u16], n: u16, corrupted_t: u16) -> Vec<SessionConfig> {
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
                threshold: corrupted_t + 1,
            },
            parties: parties.clone(),
        })
        .collect()
}

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

fn run_aux_info(n: u16) -> Vec<AuxInfo> {
    let configs = make_session_configs(n, 1);
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

fn run_presign(
    core_shares: &[Cggmp20CoreKeyShare<C>],
    aux_infos: &[AuxInfo],
    signers: &[u16],
) -> Vec<(Presignature<C>, PresignaturePublicData<C>)> {
    let n = core_shares.len() as u16;
    let corrupted_t = core_shares[0].vss_setup.threshold - 1;
    let signer_configs = make_signer_configs(signers, n, corrupted_t);
    let mut rng = Csprng::new();

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

/// Build a DataToSign from a message by SHA-256 hashing and reducing mod q.
fn make_data_to_sign(message: &[u8]) -> DataToSign<C> {
    let hash_bytes: [u8; 32] = Sha256::digest(message).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    DataToSign::from_digest(scalar)
}

/// Manual ECDSA verify: check s^{-1}*(m*G + r*PK) has x-coordinate equal to r.
///
/// This uses the CGGMP20 convention where r = xcoord(Gamma), not xcoord(k*G).
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

#[test]
fn sign_2of3_verifies() {
    let core_shares = run_keygen(3, 1);
    let aux_infos = run_aux_info(3);
    let signers = [1u16, 2];
    let presigs = run_presign(&core_shares, &aux_infos, &signers);

    assert_eq!(presigs.len(), 2);

    let data_to_sign = make_data_to_sign(b"hello world");

    // Each signer computes a partial signature.
    let partials: Vec<_> = presigs
        .iter()
        .map(|(presig, _)| presig.partial_sign(&data_to_sign))
        .collect();

    // Combine partial signatures into a full ECDSA signature.
    // combine() internally verifies the signature — if it returns Ok, the sig is valid.
    let pub_data = &presigs[0].1;
    let public_key = &core_shares[0].public_key;
    let sig = PartialSignature::combine(&partials, pub_data, public_key, &data_to_sign)
        .expect("combine must succeed");

    // Additionally verify via the standard ECDSA scalar check.
    verify_signature(sig.r, sig.s, &data_to_sign, public_key);
}

#[test]
#[ignore = "slow: multiple message variant"]
fn sign_different_messages_produce_different_signatures() {
    let core_shares = run_keygen(3, 1);
    let aux_infos = run_aux_info(3);
    let signers = [1u16, 2];

    // First signing session.
    let presigs_1 = run_presign(&core_shares, &aux_infos, &signers);
    let data1 = make_data_to_sign(b"hello world");
    let partials_1: Vec<_> = presigs_1
        .iter()
        .map(|(p, _)| p.partial_sign(&data1))
        .collect();
    let sig1 = PartialSignature::combine(
        &partials_1,
        &presigs_1[0].1,
        &core_shares[0].public_key,
        &data1,
    )
    .expect("combine must succeed");

    // Second signing session with a different message.
    let presigs_2 = run_presign(&core_shares, &aux_infos, &signers);
    let data2 = make_data_to_sign(b"different message");
    let partials_2: Vec<_> = presigs_2
        .iter()
        .map(|(p, _)| p.partial_sign(&data2))
        .collect();
    let sig2 = PartialSignature::combine(
        &partials_2,
        &presigs_2[0].1,
        &core_shares[0].public_key,
        &data2,
    )
    .expect("combine must succeed");

    // Different messages must produce different signatures (with overwhelming probability).
    assert_ne!(
        sig1.r, sig2.r,
        "different messages should produce different r"
    );
    assert_ne!(
        sig1.s, sig2.s,
        "different messages should produce different s"
    );
}
