// SPDX-License-Identifier: MIT OR Apache-2.0
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use tecdsa_cggmp20::{
    aux_info::AuxInfoMachine,
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    keygen::{msg::KeygenMsg, Cggmp20KeygenMachine},
    presign::{msg::PresignMsg, Cggmp20PresignMachine},
    security_level::Cggmp20SecurityParams,
};
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

/// Test that a tampered Round 2 decommitment nonce causes keygen to abort.
///
/// Party 1 sends a broadcast in Round 2 with a garbage decommit_nonce.  When
/// the other parties try to advance from Round 2 → Round 3 they must verify the
/// hash commitment against the decommitment data; the wrong nonce fails that
/// check and `handle()` must return `Err`.
#[test]
fn keygen_invalid_commitment_aborts() {
    let n: u16 = 3;
    let corrupted_t: u16 = 1;
    let configs = make_session_configs(n, corrupted_t);
    let mut rng = Csprng::new();

    // Create machines for all parties.
    let mut machines: Vec<(PartyId, Cggmp20KeygenMachine<C>)> = configs
        .iter()
        .map(|cfg| {
            (
                cfg.local_party.id,
                Cggmp20KeygenMachine::<C>::new(cfg, &mut rng),
            )
        })
        .collect();

    // --- Round 1: deliver all Round1 commitments normally. ---
    let mut round1_pending = Vec::new();
    for (pid, machine) in &mut machines {
        for msg in machine.drain_outgoing() {
            round1_pending.push((*pid, msg));
        }
    }
    for (from, outgoing) in round1_pending {
        match outgoing.to {
            Recipient::Broadcast => {
                for (pid, machine) in &mut machines {
                    if *pid != from {
                        machine
                            .handle(from, outgoing.msg.clone())
                            .expect("Round 1 handle must succeed");
                    }
                }
            }
            Recipient::Party(to) => {
                if let Some((_, machine)) = machines.iter_mut().find(|(p, _)| *p == to) {
                    machine
                        .handle(from, outgoing.msg)
                        .expect("Round 1 P2P handle must succeed");
                }
            }
        }
    }

    // --- Round 2: collect all outgoing, then tamper Party 1's Round2Broad. ---
    let party1 = PartyId(1);
    let mut round2_pending = Vec::new();
    for (pid, machine) in &mut machines {
        for msg in machine.drain_outgoing() {
            round2_pending.push((*pid, msg));
        }
    }

    // Tamper: replace decommit_nonce in Party 1's Round2Broad with random bytes.
    let round2_pending: Vec<_> = round2_pending
        .into_iter()
        .map(|(from, outgoing)| {
            if from == party1 {
                if let KeygenMsg::Round2Broad(mut broad) = outgoing.msg {
                    // Overwrite the decommit nonce with garbage.
                    rng.fill_bytes(&mut broad.decommit_nonce);
                    (
                        from,
                        tecdsa_protocol::state_machine::Outgoing {
                            to: outgoing.to,
                            msg: KeygenMsg::Round2Broad(broad),
                        },
                    )
                } else {
                    (from, outgoing)
                }
            } else {
                (from, outgoing)
            }
        })
        .collect();

    // Deliver Round 2 messages.  The commitment verification runs inside
    // advance() which is triggered when is_ready() fires (after the last
    // Round2Broad/Uni pair arrives).  The error surfaces from the handle()
    // call that triggers the advance — not necessarily from Party 1's message.
    let mut saw_error = false;
    for (from, outgoing) in round2_pending {
        match outgoing.to {
            Recipient::Broadcast => {
                for (pid, machine) in &mut machines {
                    if *pid != from {
                        let result = machine.handle(from, outgoing.msg.clone());
                        if result.is_err() {
                            saw_error = true;
                        }
                    }
                }
            }
            Recipient::Party(to) => {
                if let Some((_, machine)) = machines.iter_mut().find(|(p, _)| *p == to) {
                    let result = machine.handle(from, outgoing.msg);
                    if result.is_err() {
                        saw_error = true;
                    }
                }
            }
        }
    }

    assert!(
        saw_error,
        "at least one party must reject the tampered Round 2 commitment"
    );
}

/// Test that a tampered `delta` in Presign Round 3 causes the protocol to abort.
///
/// Party 1's Round 3 broadcast has its `delta` field replaced with a random
/// scalar.  When Party 2 receives this, after collecting all Round 3 messages
/// it calls `finish()` internally.  The consistency check `delta * G == sum(Delta_i)`
/// will fail because the tampered delta shifts the scalar sum away from the
/// committed curve-point sum.
#[test]
fn presign_wrong_delta_aborts() {
    // Run keygen and aux-info normally.
    let core_shares = run_keygen(3, 1);
    let aux_infos = run_aux_info(3);

    let signers = [1u16, 2u16];
    let n = core_shares.len() as u16;
    let corrupted_t = core_shares[0].vss_setup.threshold - 1;
    let signer_configs = make_signer_configs(&signers, n, corrupted_t);
    let mut rng = Csprng::new();

    // Create presign machines for the signing subset.
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
                &signers,
                &mut rng,
            );
            (pid, machine)
        })
        .collect();

    // Run Rounds 1-2 normally.
    for round_num in 1u16..=2 {
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
                        machine
                            .handle(from, outgoing.msg)
                            .unwrap_or_else(|e| panic!("presign round {round_num} P2P: {e}"));
                    }
                }
                Recipient::Broadcast => {
                    for (pid, machine) in &mut machines {
                        if *pid != from {
                            machine
                                .handle(from, outgoing.msg.clone())
                                .unwrap_or_else(|e| {
                                    panic!("presign round {round_num} broadcast: {e}")
                                });
                        }
                    }
                }
            }
        }
    }

    // --- Round 3: collect, tamper Party 1's delta, then deliver. ---
    let party1 = PartyId(1);
    let mut round3_pending = Vec::new();
    for (pid, machine) in &mut machines {
        for msg in machine.drain_outgoing() {
            round3_pending.push((*pid, msg));
        }
    }

    // Generate a random scalar to use as the tampered delta.
    // Fill random bytes, hash them, convert to a field element (same pattern as sign.rs).
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let hash_bytes: [u8; 32] = Sha256::digest(random_bytes).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    use elliptic_curve::ops::Reduce;
    let tampered_delta = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);

    // Tamper: replace delta in Party 1's Round3 broadcast.
    let round3_pending: Vec<_> = round3_pending
        .into_iter()
        .map(|(from, outgoing)| {
            if from == party1 {
                if let PresignMsg::Round3(mut r3) = outgoing.msg {
                    r3.delta = tampered_delta;
                    (
                        from,
                        tecdsa_protocol::state_machine::Outgoing {
                            to: outgoing.to,
                            msg: PresignMsg::Round3(r3),
                        },
                    )
                } else {
                    (from, outgoing)
                }
            } else {
                (from, outgoing)
            }
        })
        .collect();

    // Deliver Round 3 messages. When Party 2 receives Party 1's tampered
    // message and becomes ready, handle() will call finish() internally.
    // The delta consistency check must fail and propagate as Err.
    let mut saw_error = false;
    for (from, outgoing) in round3_pending {
        match outgoing.to {
            Recipient::Broadcast => {
                for (pid, machine) in &mut machines {
                    if *pid != from {
                        let result = machine.handle(from, outgoing.msg.clone());
                        if from == party1 && result.is_err() {
                            saw_error = true;
                        }
                    }
                }
            }
            Recipient::Party(to) => {
                if let Some((_, machine)) = machines.iter_mut().find(|(p, _)| *p == to) {
                    let _ = machine.handle(from, outgoing.msg);
                }
            }
        }
    }

    assert!(
        saw_error,
        "at least one party must reject the tampered delta in Round 3"
    );
}
