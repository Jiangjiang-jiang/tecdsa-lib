use elliptic_curve::ops::Reduce;
use sha2::{Digest, Sha256};
use tecdsa_cggmp20::{
    aux_info::AuxInfoMachine,
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    keygen::Cggmp20KeygenMachine,
    presign::Cggmp20PresignMachine,
    security_level::Cggmp20SecurityParams,
    sign::types::{DataToSign, PartialSignature},
};
use tecdsa_core::Csprng;
use tecdsa_protocol::{
    verify_ecdsa, PartyId, PartyInfo, Recipient, SessionConfig, SessionId, StateMachine,
};

type C = k256::Secp256k1;

#[derive(Debug, Clone, Copy)]
struct DemoLevel;

impl Cggmp20SecurityParams for DemoLevel {
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

fn run_protocol<M: StateMachine>(machines: &mut [(PartyId, M)], max_rounds: u16)
where
    M::Outbound: Clone + Into<M::Inbound>,
{
    for _round in 0..max_rounds {
        if machines.iter().all(|(_, m)| m.is_done()) {
            break;
        }

        let mut pending = Vec::new();
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
                            .handle(from, outgoing.msg.into())
                            .expect("handle should succeed");
                    }
                }
                Recipient::Broadcast => {
                    for (pid, machine) in machines.iter_mut() {
                        if *pid != from {
                            machine
                                .handle(from, outgoing.msg.clone().into())
                                .expect("handle should succeed");
                        }
                    }
                }
            }
        }
    }
}

fn hash_message(message: &[u8]) -> DataToSign<C> {
    let hash_bytes: [u8; 32] = Sha256::digest(message).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    DataToSign::from_digest(scalar)
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

    run_protocol(&mut machines, 10);

    machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("keygen must succeed"))
        .collect()
}

fn run_aux_info(n: u16) -> Vec<AuxInfo> {
    let configs = make_session_configs(n, 2);
    let mut rng = Csprng::new();

    let mut machines: Vec<(PartyId, AuxInfoMachine<DemoLevel>)> = configs
        .iter()
        .map(|cfg| {
            (
                cfg.local_party.id,
                AuxInfoMachine::<DemoLevel>::new(cfg, &mut rng),
            )
        })
        .collect();

    run_protocol(&mut machines, 10);

    machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("aux-info must succeed"))
        .collect()
}

fn run_presign(
    core_shares: &[Cggmp20CoreKeyShare<C>],
    aux_infos: &[AuxInfo],
    signers: &[u16],
) -> Vec<(
    tecdsa_cggmp20::sign::types::Presignature<C>,
    tecdsa_cggmp20::sign::types::PresignaturePublicData<C>,
)> {
    #[allow(clippy::cast_possible_truncation)]
    let n = core_shares.len() as u16;
    let t = core_shares[0].vss_setup.threshold;
    let signer_configs = make_signer_configs(signers, n, t);
    let mut rng = Csprng::new();

    let mut machines: Vec<(PartyId, Cggmp20PresignMachine<C>)> = signers
        .iter()
        .enumerate()
        .map(|(idx, &signer_1based)| {
            let party_0based = (signer_1based - 1) as usize;
            let pid = PartyId(signer_1based);
            let machine = Cggmp20PresignMachine::<C>::with_security::<DemoLevel>(
                &signer_configs[idx],
                &core_shares[party_0based],
                &aux_infos[party_0based],
                signers,
                &mut rng,
            );
            (pid, machine)
        })
        .collect();

    run_protocol(&mut machines, 10);

    machines
        .into_iter()
        .map(|(_, m)| m.finish().expect("presign must succeed"))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CGGMP20 Threshold ECDSA Example");
    println!("================================");
    println!("Configuration: 2-of-3 threshold, secp256k1");
    println!();

    println!("[1/4] Running distributed key generation (3 parties, 2-of-3 signing)...");
    let core_shares = run_keygen(3, 2);
    let public_key = core_shares[0].public_key;
    println!("  Key generation complete.");
    println!("  All 3 parties agree on the joint ECDSA public key.");
    println!();

    println!("[2/4] Generating auxiliary info (Paillier keys + ring-Pedersen params)...");
    let aux_infos = run_aux_info(3);
    let aux_count = aux_infos.len();
    println!("  Auxiliary info generation complete ({aux_count} parties).");
    println!();

    let signers = [1u16, 2];
    println!("[3/4] Running presigning protocol (signers: {signers:?})...");
    let presigs = run_presign(&core_shares, &aux_infos, &signers);
    let presig_count = presigs.len();
    println!("  Presigning complete. {presig_count} presignatures produced.");
    println!();

    let message = b"Hello, threshold ECDSA!";
    println!(
        "[4/4] Signing message: \"{}\"",
        std::str::from_utf8(message).unwrap()
    );

    let data_to_sign = hash_message(message);
    let partials: Vec<_> = presigs
        .iter()
        .map(|(presig, _)| presig.partial_sign(&data_to_sign))
        .collect();

    let pub_data = &presigs[0].1;
    let sig = PartialSignature::combine(&partials, pub_data, &public_key, &data_to_sign)
        .expect("combine must succeed");

    println!("  Signature produced:");
    println!("    r = {:?}", sig.r);
    println!("    s = {:?}", sig.s);
    println!();

    let protocol_sig = tecdsa_protocol::Signature { r: sig.r, s: sig.s };
    verify_ecdsa::<C>(&protocol_sig, &public_key, &data_to_sign)?;
    println!("  ECDSA signature verification: PASSED");
    println!();
    println!("Done.");

    Ok(())
}
