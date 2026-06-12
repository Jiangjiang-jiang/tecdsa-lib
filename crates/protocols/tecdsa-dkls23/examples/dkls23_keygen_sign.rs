use elliptic_curve::PrimeField;
use sha2::{Digest as _, Sha256};
use tecdsa_dkls23::{
    key_share::Dkls23KeyShare,
    keygen::Dkls23KeygenMachine,
    presign::{Dkls23PresignMachine, PresignConfig},
    sign::{Dkls23OnlineSignMachine, OnlineSignConfig},
};
use tecdsa_protocol::{verify_ecdsa, DataToSign, PartyId};
use tecdsa_testkit::Orchestrator;

type C = k256::Secp256k1;

fn hash_message(msg: &[u8]) -> DataToSign<C> {
    let hash = Sha256::digest(msg);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    let scalar = <C as elliptic_curve::CurveArithmetic>::Scalar::from_repr(
        elliptic_curve::FieldBytes::<C>::from(bytes),
    )
    .expect("SHA-256 output must be a valid scalar");
    DataToSign::from_digest(scalar)
}

fn run_keygen(n: u16, t: u16) -> Vec<Dkls23KeyShare<C>> {
    let mut rng = rand::thread_rng();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let machines: Vec<(PartyId, Dkls23KeygenMachine<C>)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Dkls23KeygenMachine::new(pid, all_parties.clone(), t, &mut rng);
            (pid, machine)
        })
        .collect();

    let results = Orchestrator::new(machines, 10)
        .run()
        .expect("orchestrator must succeed");
    results
        .into_iter()
        .map(|r| r.expect("keygen should succeed"))
        .collect()
}

fn run_presign(
    shares: &[Dkls23KeyShare<C>],
    signer_indices: &[u16],
) -> Vec<tecdsa_dkls23::presign::Dkls23Presignature<C>> {
    let signer_parties: Vec<PartyId> = signer_indices.iter().map(|&i| PartyId(i)).collect();

    let machines: Vec<(PartyId, Dkls23PresignMachine<C>)> = signer_indices
        .iter()
        .map(|&idx| {
            let share = shares[(idx - 1) as usize].clone();
            let pid = PartyId(idx);
            let config = PresignConfig {
                key_share: share,
                my_id: pid,
                signer_parties: signer_parties.clone(),
            };
            (pid, Dkls23PresignMachine::new(config, rand_core::OsRng))
        })
        .collect();

    let results = Orchestrator::new(machines, 20)
        .run()
        .expect("orchestrator must succeed");
    results
        .into_iter()
        .map(|r| r.expect("presign should succeed"))
        .collect()
}

fn run_online_sign(
    presignatures: Vec<tecdsa_dkls23::presign::Dkls23Presignature<C>>,
    message: DataToSign<C>,
) -> tecdsa_protocol::Signature<C> {
    let machines: Vec<(PartyId, Dkls23OnlineSignMachine<C>)> = presignatures
        .into_iter()
        .map(|presig| {
            let pid = presig.my_id;
            let config = OnlineSignConfig {
                presignature: presig,
                message,
            };
            (pid, Dkls23OnlineSignMachine::new(config))
        })
        .collect();

    let results = Orchestrator::new(machines, 10)
        .run()
        .expect("orchestrator must succeed");
    let sigs: Vec<_> = results
        .into_iter()
        .map(|r| r.expect("online sign should succeed"))
        .collect();

    for i in 1..sigs.len() {
        assert_eq!(sigs[i].r, sigs[0].r, "all signers must agree on r");
        assert_eq!(sigs[i].s, sigs[0].s, "all signers must agree on s");
    }

    sigs.into_iter().next().unwrap()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("DKLs23 Threshold ECDSA Example");
    println!("===============================");
    println!("Configuration: 2-of-3 threshold, secp256k1");
    println!();

    println!("[1/3] Running distributed key generation (3 parties, 2-of-3 signing)...");
    let shares = run_keygen(3, 2);
    let public_key = shares[0].public_key;
    println!("  Key generation complete.");
    println!("  All 3 parties agree on the joint ECDSA public key.");
    println!();

    let signer_indices = &[1u16, 2];
    println!("[2/3] Running presigning protocol (signers: {signer_indices:?}, 3 rounds with real RVOLE)...");
    let presigs = run_presign(&shares, signer_indices);
    let presig_count = presigs.len();
    println!("  Presigning complete. {presig_count} presignatures produced.");
    println!();

    let message = b"Hello, threshold ECDSA with DKLs23!";
    println!(
        "[3/3] Online signing (1 round): \"{}\"",
        std::str::from_utf8(message).unwrap()
    );
    let data_to_sign = hash_message(message);
    let sig = run_online_sign(presigs, data_to_sign);

    println!("  Signature produced:");
    println!("    r = {:?}", sig.r);
    println!("    s = {:?}", sig.s);
    println!();

    verify_ecdsa::<C>(&sig, &public_key, &data_to_sign)?;
    println!("  ECDSA signature verification: PASSED");
    println!();
    println!("Done.");

    Ok(())
}
