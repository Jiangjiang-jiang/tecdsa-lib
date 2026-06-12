#![allow(non_snake_case)]

use tecdsa_protocol::{PartyId, PartyInfo, SessionConfig, SessionId};
use tecdsa_testkit::WireOrchestrator;

fn session_configs(n: u16, t: u16) -> Vec<SessionConfig> {
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

fn assert_all_ok<T>(results: &[tecdsa_core::Result<T>], protocol: &str) {
    for (i, res) in results.iter().enumerate() {
        assert!(
            res.is_ok(),
            "{protocol}: party {i} failed via WireOrchestrator: {}",
            res.as_ref()
                .err()
                .map_or("unknown".to_string(), |e| format!("{e}"))
        );
    }
}

#[test]
fn wire_cggmp20_keygen() {
    use tecdsa_cggmp20::keygen::Cggmp20KeygenMachine;
    use tecdsa_core::Csprng;

    let n = 3u16;
    let t = 2u16;
    let configs = session_configs(n, t);
    let mut rng = Csprng::new();

    let machines: Vec<(PartyId, Cggmp20KeygenMachine<k256::Secp256k1>)> = configs
        .iter()
        .map(|cfg| (cfg.local_party.id, Cggmp20KeygenMachine::new(cfg, &mut rng)))
        .collect();

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "CGGMP20");
}

#[test]
fn wire_dkls23_keygen() {
    use tecdsa_dkls23::keygen::Dkls23KeygenMachine;

    let n = 3u16;
    let t = 2u16;
    let mut rng = rand::thread_rng();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let machines: Vec<(PartyId, Dkls23KeygenMachine<k256::Secp256k1>)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Dkls23KeygenMachine::new(pid, all_parties.clone(), t, &mut rng);
            (pid, machine)
        })
        .collect();

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "DKLs23");
}

#[test]
fn wire_gg18_keygen() {
    use tecdsa_core::Csprng;
    use tecdsa_gg18::keygen::{generate_n_tilde, Gg18KeygenMachine, PaillierPrecomputed};
    use tecdsa_paillier::{backend::Integer, DecryptionKey};

    let n = 3u16;
    let t = 2u16;
    let configs = session_configs(n, t);
    let mut rng = Csprng::new();

    let machines: Vec<(PartyId, Gg18KeygenMachine<k256::Secp256k1>)> = configs
        .iter()
        .map(|cfg| {
            let p = Integer::generate_safe_prime(&mut rng, 256);
            let q = Integer::generate_safe_prime(&mut rng, 256);
            let dk = DecryptionKey::from_primes(p, q).expect("valid primes");
            let dk_tilde = {
                let p2 = Integer::generate_safe_prime(&mut rng, 256);
                let q2 = Integer::generate_safe_prime(&mut rng, 256);
                DecryptionKey::from_primes(p2, q2).expect("valid primes")
            };
            let n_tilde_params = generate_n_tilde(&dk_tilde, &mut rng);
            let precomputed = PaillierPrecomputed { dk, n_tilde_params };

            (
                cfg.local_party.id,
                Gg18KeygenMachine::new_with_precomputed(cfg, precomputed, &mut rng),
            )
        })
        .collect();

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "GG18");
}

#[test]
#[ignore = "slow Paillier keygen"]
fn wire_ggn16_keygen() {
    use tecdsa_ggn16::keygen::Ggn16KeygenMachine;
    use tecdsa_paillier::{backend::Integer, threshold::trusted_dealer_setup};

    let n = 3u16;
    let t = 2u16;
    let mut rng = rand::thread_rng();

    let (setup, dec_shares) =
        trusted_dealer_setup(t - 1, n, &mut rng).expect("trusted dealer setup");

    let p = Integer::generate_safe_prime(&mut rng, 256);
    let q = Integer::generate_safe_prime(&mut rng, 256);
    let n_tilde = &p * &q;
    let h1 = Integer::sample_in_mult_group_of(&mut rng, &n_tilde);
    let xhi_bound = Integer::one() << 256u32;
    let xhi = xhi_bound.random_below_ref(&mut rng);
    let h1_xhi = h1
        .pow_mod_ref(&xhi, &n_tilde)
        .expect("pow_mod must succeed");
    let h2 = h1_xhi
        .invert_ref(&n_tilde)
        .expect("h1^xhi must be invertible mod N_tilde");

    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let mut machines: Vec<(PartyId, Ggn16KeygenMachine<k256::Secp256k1>)> = Vec::new();
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
            &mut rng,
        );
        machines.push((pid, machine));
    }

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "GGN16");
}

#[test]
fn wire_ln18_keygen() {
    use tecdsa_core::Csprng;
    use tecdsa_ln18::keygen::Ln18KeygenMachine;

    let n = 3u16;
    let t = 3u16;
    let session_id = SessionId([0u8; 32]);
    let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    let configs: Vec<SessionConfig> = (1..=n)
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
        .collect();
    let mut rng = Csprng::new();

    let machines: Vec<(PartyId, Ln18KeygenMachine<k256::Secp256k1>)> = configs
        .iter()
        .map(|cfg| (cfg.local_party.id, Ln18KeygenMachine::new(cfg, &mut rng)))
        .collect();

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "LN18");
}

#[test]
#[ignore = "slow crypto operations (class group)"]
fn wire_wmy23_keygen() {
    use tecdsa_wmy23::keygen::Wmy23KeygenMachine;

    let n = 3u16;
    let t = 2u16;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let machines: Vec<(PartyId, Wmy23KeygenMachine)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Wmy23KeygenMachine::new(
                pid,
                all_parties.clone(),
                t,
                "12345",
                false,
            )
            .expect("WMY23 keygen machine construction");
            (pid, machine)
        })
        .collect();

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "WMY23");
}

#[test]
#[ignore = "slow crypto operations (class group)"]
fn wire_tx25_keygen() {
    use tecdsa_tx25::keygen::Tx25KeygenMachine;

    let n = 3u16;
    let t = 2u16;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let machines: Vec<(PartyId, Tx25KeygenMachine)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Tx25KeygenMachine::new(
                pid,
                all_parties.clone(),
                t,
                "90001",
                false,
            )
            .expect("TX25 keygen machine construction");
            (pid, machine)
        })
        .collect();

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "TX25");
}

#[test]
#[ignore = "slow crypto operations (class group)"]
fn wire_jtx25_keygen() {
    use tecdsa_jtx25::keygen::Jtx25KeygenMachine;

    let n = 3u16;
    let t = 2u16;
    let all_parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let machines: Vec<(PartyId, Jtx25KeygenMachine)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Jtx25KeygenMachine::new(
                pid,
                all_parties.clone(),
                t,
                "50001",
                false,
            )
            .expect("JTX25 keygen machine construction");
            (pid, machine)
        })
        .collect();

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "JTX25");
}

#[test]
#[ignore = "slow crypto operations (class group)"]
fn wire_wmc24_keygen() {
    use tecdsa_wmc24::keygen::Wmc24KeygenMachine;

    let n = 3u16;
    let t = 2u16;
    let all_parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    let machines: Vec<(PartyId, Wmc24KeygenMachine)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Wmc24KeygenMachine::new(pid, all_parties.clone(), t, "60001", false)
                .expect("WMC24 keygen machine construction");
            (pid, machine)
        })
        .collect();

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "WMC24");
}

#[test]
#[ignore = "slow crypto operations (class group)"]
fn wire_llz25_keygen() {
    use tecdsa_class_group::cl::ClSetup;
    use tecdsa_llz25::keygen::Llz25KeygenMachine;

    let n = 3u16;
    let t = 2u16;
    let seed = "12345";
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let machines: Vec<(PartyId, Llz25KeygenMachine)> = all_parties
        .iter()
        .map(|&pid| {
            let mut setup = ClSetup::new_secp256k1(seed).expect("CL setup");
            let (_sk, pk_crs) = setup.keygen().expect("CRS keygen");
            let machine = Llz25KeygenMachine::new(pid, all_parties.clone(), t, seed, false, pk_crs)
                .expect("LLZ25 keygen machine construction");
            (pid, machine)
        })
        .collect();

    let results = WireOrchestrator::new(machines, 15).run();
    assert_all_ok(&results, "LLZ25");
}

#[test]
#[ignore = "slow crypto operations (class group)"]
fn wire_trout_keygen() {
    use tecdsa_trout::keygen::TroutKeygenMachine;

    let n = 3u16;
    let t = 2u16;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let machines: Vec<(PartyId, TroutKeygenMachine)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = TroutKeygenMachine::new(pid, all_parties.clone(), t, "77777", false)
                .expect("Trout keygen machine construction");
            (pid, machine)
        })
        .collect();

    let results = WireOrchestrator::new(machines, 10).run();
    assert_all_ok(&results, "Trout");
}

#[test]
#[ignore = "slow crypto operations (JL key generation)"]
fn wire_xal23_keygen() {
    use tecdsa_xal23::keygen::Xal23KeygenMachine;

    let n = 3u16;
    let t = 2u16;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    let jl_p_bits: u64 = 800;
    let jl_k: u32 = 544;

    let machines: Vec<(PartyId, Xal23KeygenMachine<k256::Secp256k1>)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Xal23KeygenMachine::new(pid, all_parties.clone(), t, jl_p_bits, jl_k)
                .expect("XAL23 keygen machine construction");
            (pid, machine)
        })
        .collect();

    let results = WireOrchestrator::new(machines, 15).run();
    assert_all_ok(&results, "XAL23");
}

#[test]
#[ignore = "slow crypto operations (Paillier keygen ~10-30s debug)"]
fn wire_lin17_keygen() {
    use tecdsa_lin17::keygen::{Lin17KeygenMachine, TwoPartyRole};

    let mut rng = rand_core::OsRng;
    let p1_id = PartyId(1);
    let p2_id = PartyId(2);

    let p1 =
        Lin17KeygenMachine::<k256::Secp256k1>::new(TwoPartyRole::Party1, p1_id, p2_id, &mut rng)
            .expect("Lin17 P1 construction");
    let p2 =
        Lin17KeygenMachine::<k256::Secp256k1>::new(TwoPartyRole::Party2, p2_id, p1_id, &mut rng)
            .expect("Lin17 P2 construction");

    let machines = vec![(p1_id, p1), (p2_id, p2)];
    let results = WireOrchestrator::new(machines, 20).run();
    assert_all_ok(&results, "Lin17");
}

#[test]
#[ignore = "slow crypto operations (Paillier keygen ~10-30s debug)"]
fn wire_kgg24_keygen() {
    use tecdsa_kgg24::keygen::{Kgg24KeygenMachine, TwoPartyRole};

    let mut rng = rand_core::OsRng;
    let p1_id = PartyId(1);
    let p2_id = PartyId(2);

    let p1 =
        Kgg24KeygenMachine::<k256::Secp256k1>::new(TwoPartyRole::Party1, p1_id, p2_id, &mut rng)
            .expect("KGG24 P1 construction");
    let p2 =
        Kgg24KeygenMachine::<k256::Secp256k1>::new(TwoPartyRole::Party2, p2_id, p1_id, &mut rng)
            .expect("KGG24 P2 construction");

    let machines = vec![(p1_id, p1), (p2_id, p2)];
    let results = WireOrchestrator::new(machines, 20).run();
    assert_all_ok(&results, "KGG24");
}

#[test]
#[ignore = "slow crypto operations (Paillier keygen ~10-30s debug)"]
fn wire_xal21_keygen() {
    use tecdsa_xal21::keygen::{TwoPartyRole, Xal21KeygenMachine};

    let mut rng = rand_core::OsRng;
    let p1_id = PartyId(1);
    let p2_id = PartyId(2);

    let p1 =
        Xal21KeygenMachine::<k256::Secp256k1>::new(TwoPartyRole::Party1, p1_id, p2_id, &mut rng)
            .expect("XAL+21 P1 construction");
    let p2 =
        Xal21KeygenMachine::<k256::Secp256k1>::new(TwoPartyRole::Party2, p2_id, p1_id, &mut rng)
            .expect("XAL+21 P2 construction");

    let machines = vec![(p1_id, p1), (p2_id, p2)];
    let results = WireOrchestrator::new(machines, 20).run();
    assert_all_ok(&results, "XAL+21");
}

#[test]
#[ignore = "slow crypto operations (Paillier keygen ~10-30s debug)"]
fn wire_abc24_keygen() {
    use tecdsa_abc24::keygen::{Abc24KeygenMachine, TwoPartyRole};

    let mut rng = rand_core::OsRng;
    let p1_id = PartyId(1);
    let p2_id = PartyId(2);

    let p1 =
        Abc24KeygenMachine::<k256::Secp256k1>::new(TwoPartyRole::Party1, p1_id, p2_id, &mut rng)
            .expect("ABC+24 P1 construction");
    let p2 =
        Abc24KeygenMachine::<k256::Secp256k1>::new(TwoPartyRole::Party2, p2_id, p1_id, &mut rng)
            .expect("ABC+24 P2 construction");

    let machines = vec![(p1_id, p1), (p2_id, p2)];
    let results = WireOrchestrator::new(machines, 20).run();
    assert_all_ok(&results, "ABC+24");
}
