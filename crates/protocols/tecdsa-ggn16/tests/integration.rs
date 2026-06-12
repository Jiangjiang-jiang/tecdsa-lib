#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, PrimeField};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use tecdsa_ggn16::{
    key_share::Ggn16KeyShare, keygen::Ggn16KeygenMachine, presign::Ggn16PresignMachine,
    sign::Ggn16OnlineSignMachine,
};
use tecdsa_paillier::{backend::Integer, threshold::trusted_dealer_setup};
use tecdsa_protocol::{verify_ecdsa, DataToSign, PartyId};
use tecdsa_testkit::Orchestrator;

type TestCurve = k256::Secp256k1;

fn generate_ring_pedersen(rng: &mut impl CryptoRngCore) -> (Integer, Integer, Integer) {
    let p = Integer::generate_safe_prime(rng, 256);
    let q = Integer::generate_safe_prime(rng, 256);
    let n_tilde = &p * &q;

    let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);
    let xhi_bound = Integer::one() << 256u32;
    let xhi = xhi_bound.random_below_ref(rng);
    let h1_xhi = h1
        .pow_mod_ref(&xhi, &n_tilde)
        .expect("pow_mod must succeed");
    let h2 = h1_xhi
        .invert_ref(&n_tilde)
        .expect("h1^xhi must be invertible mod N_tilde");

    (n_tilde, h1, h2)
}

fn run_keygen(n: u16, t: u16, rng: &mut impl CryptoRngCore) -> Vec<Ggn16KeyShare<TestCurve>> {
    let corruption_t = t - 1;
    let (setup, dec_shares) =
        trusted_dealer_setup(corruption_t, n, rng).expect("trusted dealer setup should succeed");
    let (n_tilde, h1, h2) = generate_ring_pedersen(rng);
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let mut machines: Vec<(PartyId, Ggn16KeygenMachine<TestCurve>)> = Vec::new();
    for (i, dec_share) in dec_shares.into_iter().enumerate() {
        let pid = all_parties[i];
        let machine = Ggn16KeygenMachine::new(
            pid,
            all_parties.clone(),
            t,
            setup.clone(),
            dec_share,
            h1.clone(),
            h2.clone(),
            n_tilde.clone(),
            rng,
        );
        machines.push((pid, machine));
    }

    let results = Orchestrator::new(machines, 10)
        .run()
        .expect("orchestrator must succeed");
    results
        .into_iter()
        .map(|r| r.expect("keygen should succeed"))
        .collect()
}

fn make_message_hash(msg: &str) -> DataToSign<TestCurve> {
    let hash = Sha256::digest(msg.as_bytes());
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash);
    let scalar = <k256::Scalar as PrimeField>::from_repr(k256::FieldBytes::from(scalar_bytes))
        .expect("SHA-256 output must be a valid scalar for secp256k1");
    DataToSign::from_digest(scalar)
}

#[test]
fn ggn16_full_sign_3_of_3() {
    let mut rng = rand::thread_rng();
    let t = 3u16;
    let n = 3u16;

    let shares = run_keygen(n, t, &mut rng);

    let pk0_bytes = shares[0].public_key.to_bytes();
    for share in &shares[1..] {
        assert_eq!(
            share.public_key.to_bytes(),
            pk0_bytes,
            "all parties should agree on public key"
        );
    }

    let signer_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    let mut presign_machines: Vec<(PartyId, Ggn16PresignMachine<TestCurve>)> = Vec::new();
    for share in &shares {
        let pid = PartyId(share.party_index);
        let machine =
            Ggn16PresignMachine::new(share.clone(), pid, signer_parties.clone(), &mut rng);
        presign_machines.push((pid, machine));
    }

    let presign_results = Orchestrator::new(presign_machines, 20)
        .run()
        .expect("orchestrator must succeed");
    let presignatures: Vec<_> = presign_results
        .into_iter()
        .map(|r| r.expect("presign should succeed"))
        .collect();

    let R0_bytes = presignatures[0].R.to_bytes();
    let r0 = presignatures[0].r;
    for (i, presig) in presignatures.iter().enumerate().skip(1) {
        assert_eq!(presig.R.to_bytes(), R0_bytes, "party {i} disagrees on R");
        assert_eq!(presig.r, r0, "party {i} disagrees on r");
    }

    let psi0 = presignatures[0].psi;
    for (i, presig) in presignatures.iter().enumerate().skip(1) {
        assert_eq!(presig.psi, psi0, "party {i} disagrees on psi");
    }

    let message = make_message_hash("hello threshold ECDSA");

    let mut sign_machines: Vec<(PartyId, Ggn16OnlineSignMachine<TestCurve>)> = Vec::new();
    for presig in presignatures {
        let pid = presig.my_id;
        let machine = Ggn16OnlineSignMachine::new(presig, message)
            .expect("online sign machine creation should succeed");
        sign_machines.push((pid, machine));
    }

    let sign_results = Orchestrator::new(sign_machines, 10)
        .run()
        .expect("orchestrator must succeed");
    let signatures: Vec<_> = sign_results
        .into_iter()
        .map(|r| r.expect("online sign should succeed"))
        .collect();

    for (i, sig) in signatures.iter().enumerate().skip(1) {
        assert_eq!(sig.r, signatures[0].r, "party {i} has different r");
        assert_eq!(sig.s, signatures[0].s, "party {i} has different s");
    }

    verify_ecdsa::<TestCurve>(&signatures[0], &shares[0].public_key, &message)
        .expect("ECDSA verification should pass");
}

#[test]
fn ggn16_full_sign_2_of_2() {
    let mut rng = rand::thread_rng();
    let t = 2u16;
    let n = 2u16;

    let shares = run_keygen(n, t, &mut rng);

    let signer_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    let mut presign_machines: Vec<(PartyId, Ggn16PresignMachine<TestCurve>)> = Vec::new();
    for share in &shares {
        let pid = PartyId(share.party_index);
        let machine =
            Ggn16PresignMachine::new(share.clone(), pid, signer_parties.clone(), &mut rng);
        presign_machines.push((pid, machine));
    }

    let presign_results = Orchestrator::new(presign_machines, 20)
        .run()
        .expect("orchestrator must succeed");
    let presignatures: Vec<_> = presign_results
        .into_iter()
        .map(|r| r.expect("presign should succeed"))
        .collect();

    let message = make_message_hash("2-of-2 signing test");

    let mut sign_machines: Vec<(PartyId, Ggn16OnlineSignMachine<TestCurve>)> = Vec::new();
    for presig in presignatures {
        let pid = presig.my_id;
        let machine = Ggn16OnlineSignMachine::new(presig, message)
            .expect("online sign machine creation should succeed");
        sign_machines.push((pid, machine));
    }

    let sign_results = Orchestrator::new(sign_machines, 10)
        .run()
        .expect("orchestrator must succeed");
    let signatures: Vec<_> = sign_results
        .into_iter()
        .map(|r| r.expect("online sign should succeed"))
        .collect();

    assert_eq!(signatures[0].r, signatures[1].r, "r values should match");
    assert_eq!(signatures[0].s, signatures[1].s, "s values should match");

    verify_ecdsa::<TestCurve>(&signatures[0], &shares[0].public_key, &message)
        .expect("ECDSA verification should pass");
}

#[test]
fn ggn16_full_sign_2_of_3() {
    let mut rng = rand::thread_rng();
    let t = 2u16;
    let n = 3u16;

    let shares = run_keygen(n, t, &mut rng);

    let signer_parties: Vec<PartyId> = vec![PartyId(1), PartyId(2)];
    let mut presign_machines: Vec<(PartyId, Ggn16PresignMachine<TestCurve>)> = Vec::new();
    for &pid in &signer_parties {
        let share = &shares[(pid.0 - 1) as usize];
        let machine =
            Ggn16PresignMachine::new(share.clone(), pid, signer_parties.clone(), &mut rng);
        presign_machines.push((pid, machine));
    }

    let presign_results = Orchestrator::new(presign_machines, 20)
        .run()
        .expect("orchestrator must succeed");
    let presignatures: Vec<_> = presign_results
        .into_iter()
        .map(|r| r.expect("presign should succeed"))
        .collect();

    let message = make_message_hash("2-of-3 subset signing");

    let mut sign_machines: Vec<(PartyId, Ggn16OnlineSignMachine<TestCurve>)> = Vec::new();
    for presig in presignatures {
        let pid = presig.my_id;
        let machine = Ggn16OnlineSignMachine::new(presig, message)
            .expect("online sign machine creation should succeed");
        sign_machines.push((pid, machine));
    }

    let sign_results = Orchestrator::new(sign_machines, 10)
        .run()
        .expect("orchestrator must succeed");
    let signatures: Vec<_> = sign_results
        .into_iter()
        .map(|r| r.expect("online sign should succeed"))
        .collect();

    assert_eq!(signatures[0].r, signatures[1].r, "r values should match");
    assert_eq!(signatures[0].s, signatures[1].s, "s values should match");

    verify_ecdsa::<TestCurve>(&signatures[0], &shares[0].public_key, &message)
        .expect("ECDSA verification should pass");
}

#[test]
fn ggn16_two_signatures_differ() {
    let mut rng = rand::thread_rng();
    let t = 2u16;
    let n = 2u16;

    let shares = run_keygen(n, t, &mut rng);

    let signer_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let mut machines1: Vec<(PartyId, Ggn16PresignMachine<TestCurve>)> = Vec::new();
    for share in &shares {
        let pid = PartyId(share.party_index);
        let machine =
            Ggn16PresignMachine::new(share.clone(), pid, signer_parties.clone(), &mut rng);
        machines1.push((pid, machine));
    }
    let presigs1: Vec<_> = Orchestrator::new(machines1, 20)
        .run()
        .expect("orchestrator must succeed")
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let msg1 = make_message_hash("message 1");
    let mut sign1: Vec<(PartyId, Ggn16OnlineSignMachine<TestCurve>)> = Vec::new();
    for presig in presigs1 {
        let pid = presig.my_id;
        sign1.push((pid, Ggn16OnlineSignMachine::new(presig, msg1).unwrap()));
    }
    let sigs1: Vec<_> = Orchestrator::new(sign1, 10)
        .run()
        .expect("orchestrator must succeed")
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let mut machines2: Vec<(PartyId, Ggn16PresignMachine<TestCurve>)> = Vec::new();
    for share in &shares {
        let pid = PartyId(share.party_index);
        let machine =
            Ggn16PresignMachine::new(share.clone(), pid, signer_parties.clone(), &mut rng);
        machines2.push((pid, machine));
    }
    let presigs2: Vec<_> = Orchestrator::new(machines2, 20)
        .run()
        .expect("orchestrator must succeed")
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    let msg2 = make_message_hash("message 2");
    let mut sign2: Vec<(PartyId, Ggn16OnlineSignMachine<TestCurve>)> = Vec::new();
    for presig in presigs2 {
        let pid = presig.my_id;
        sign2.push((pid, Ggn16OnlineSignMachine::new(presig, msg2).unwrap()));
    }
    let sigs2: Vec<_> = Orchestrator::new(sign2, 10)
        .run()
        .expect("orchestrator must succeed")
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    assert!(
        sigs1[0].r != sigs2[0].r || sigs1[0].s != sigs2[0].s,
        "signatures for different messages should differ"
    );

    verify_ecdsa::<TestCurve>(&sigs1[0], &shares[0].public_key, &msg1)
        .expect("first signature should verify");
    verify_ecdsa::<TestCurve>(&sigs2[0], &shares[0].public_key, &msg2)
        .expect("second signature should verify");
}
