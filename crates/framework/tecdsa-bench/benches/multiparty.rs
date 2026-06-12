use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::ops::Reduce;
use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_bench::{config, per_party};
use tecdsa_protocol::{PartyId, PartyInfo, SessionConfig, SessionId};
use tecdsa_testkit::Orchestrator;

type C = Secp256k1;

const SAMPLES: usize = 10;

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

fn make_data_to_sign(msg: &[u8]) -> tecdsa_protocol::DataToSign<C> {
    let hash_bytes: [u8; 32] = Sha256::digest(msg).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    tecdsa_protocol::DataToSign::from_digest(scalar)
}

mod cggmp20_helpers {
    use tecdsa_cggmp20::{
        aux_info::AuxInfoMachine,
        key_share::{AuxInfo, Cggmp20CoreKeyShare},
        keygen::Cggmp20KeygenMachine,
        presign::Cggmp20PresignMachine,
        security_level::SecurityLevel128,
        sign::types::{Presignature, PresignaturePublicData},
    };

    use super::*;

    pub fn run_keygen(n: u16, t: u16) -> Vec<Cggmp20CoreKeyShare<C>> {
        let configs = make_session_configs(n, t);
        let mut rng = tecdsa_core::Csprng::new();

        let machines: Vec<(PartyId, Cggmp20KeygenMachine<C>)> = configs
            .iter()
            .map(|cfg| {
                (
                    cfg.local_party.id,
                    Cggmp20KeygenMachine::<C>::new(cfg, &mut rng),
                )
            })
            .collect();

        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");
        results
            .into_iter()
            .map(|r| r.expect("keygen must succeed"))
            .collect()
    }

    pub fn run_aux_info(n: u16) -> Vec<AuxInfo> {
        let configs = make_session_configs(n, 2);
        let mut rng = tecdsa_core::Csprng::new();

        let machines: Vec<(PartyId, AuxInfoMachine<SecurityLevel128>)> = configs
            .iter()
            .map(|cfg| {
                (
                    cfg.local_party.id,
                    AuxInfoMachine::<SecurityLevel128>::new(cfg, &mut rng),
                )
            })
            .collect();

        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");
        results
            .into_iter()
            .map(|r| r.expect("auxinfo must succeed"))
            .collect()
    }

    pub fn run_presign(
        core_shares: &[Cggmp20CoreKeyShare<C>],
        aux_infos: &[Arc<AuxInfo>],
        signers: &[u16],
    ) -> Vec<(Presignature<C>, PresignaturePublicData<C>)> {
        let n = core_shares.len() as u16;
        let t = core_shares[0].vss_setup.threshold;
        let signer_configs = make_signer_configs(signers, n, t);
        let mut rng = tecdsa_core::Csprng::new();

        let machines: Vec<(PartyId, Cggmp20PresignMachine<C>)> = signers
            .iter()
            .enumerate()
            .map(|(idx, &signer_1based)| {
                let party_0based = (signer_1based - 1) as usize;
                let pid = PartyId(signer_1based);
                let machine = Cggmp20PresignMachine::<C>::with_security::<SecurityLevel128>(
                    &signer_configs[idx],
                    &core_shares[party_0based],
                    &aux_infos[party_0based],
                    signers,
                    &mut rng,
                );
                (pid, machine)
            })
            .collect();

        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");
        results
            .into_iter()
            .map(|r| r.expect("presign must succeed"))
            .collect()
    }
}

mod dkls23_helpers {
    use tecdsa_dkls23::{
        key_share::Dkls23KeyShare,
        keygen::Dkls23KeygenMachine,
        presign::{Dkls23PresignMachine, Dkls23Presignature, PresignConfig},
    };

    use super::*;

    pub fn run_keygen(n: u16, t: u16) -> Vec<Dkls23KeyShare<C>> {
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
            .map(|r| r.expect("keygen must succeed"))
            .collect()
    }

    pub fn run_presign(
        shares: &[Dkls23KeyShare<C>],
        signer_indices: &[u16],
    ) -> Vec<Dkls23Presignature<C>> {
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
            .map(|r| r.expect("presign must succeed"))
            .collect()
    }
}

mod gg18_helpers {
    use tecdsa_gg18::{
        key_share::Gg18KeyShare,
        keygen::Gg18KeygenMachine,
        presign::{Gg18PresignMachine, Gg18Presignature, PresignConfig},
    };

    use super::*;

    pub fn run_keygen(n: u16, t: u16) -> Vec<Gg18KeyShare<C>> {
        let configs = make_session_configs(n, t);
        let mut rng = tecdsa_core::Csprng::new();

        let machines: Vec<(PartyId, Gg18KeygenMachine<C>)> = configs
            .iter()
            .map(|cfg| {
                (
                    cfg.local_party.id,
                    Gg18KeygenMachine::<C>::new(cfg, &mut rng),
                )
            })
            .collect();

        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");
        results
            .into_iter()
            .map(|r| r.expect("keygen must succeed"))
            .collect()
    }

    pub fn run_presign(
        key_shares: &[Gg18KeyShare<C>],
        signers: &[u16],
    ) -> Vec<Gg18Presignature<C>> {
        let mut rng = tecdsa_core::Csprng::new();

        let machines: Vec<(PartyId, Gg18PresignMachine<C>)> = signers
            .iter()
            .map(|&signer_1based| {
                let party_0based = (signer_1based - 1) as usize;
                let pid = PartyId(signer_1based);
                let config = PresignConfig {
                    key_share: key_shares[party_0based].clone(),
                    signers: signers.to_vec(),
                };
                (pid, Gg18PresignMachine::new(config, &mut rng))
            })
            .collect();

        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");
        results
            .into_iter()
            .map(|r| r.expect("presign must succeed"))
            .collect()
    }
}

mod ggn16_helpers {
    use tecdsa_ggn16::key_share::Ggn16KeyShare;
    use tecdsa_paillier::{
        backend::Integer,
        threshold::{DecryptionShare, ThresholdSetup},
    };

    use super::*;

    pub fn fast_trusted_dealer_setup(
        n: u16,
        corruption_t: u16,
    ) -> (
        ThresholdSetup,
        Vec<DecryptionShare>,
        Integer,
        Integer,
        Integer,
    ) {
        let mut rng = rand_core::OsRng;
        let p = Integer::generate_safe_prime(&mut rng, 1536);
        let q = Integer::generate_safe_prime(&mut rng, 1536);
        let dk = tecdsa_paillier::DecryptionKey::from_primes(p.clone(), q.clone())
            .expect("valid primes");
        let ek = dk.encryption_key().clone();
        let n_int = ek.n().clone();
        let p_minus_1 = &p - Integer::one();
        let q_minus_1 = &q - Integer::one();
        let lambda = p_minus_1.lcm_ref(&q_minus_1);
        let beta = loop {
            let candidate = n_int.random_below_ref(&mut rng);
            if candidate > Integer::zero() && candidate.gcd_ref(&n_int) == Integer::one() {
                break candidate;
            }
        };
        let d = &lambda * &beta;
        let theta = d.modulo_ref(&n_int);
        let mut delta = Integer::one();
        for i in 2..=n as u32 {
            delta *= Integer::from(i);
        }
        let m = &n_int * &delta;
        let mut coeffs = vec![d];
        for _ in 0..corruption_t {
            coeffs.push(m.random_below_ref(&mut rng));
        }
        let mut shares = Vec::with_capacity(n as usize);
        for i in 1..=n {
            let x = Integer::from(i as u32);
            let mut val = Integer::zero();
            let mut x_pow = Integer::one();
            for coeff in &coeffs {
                val += coeff * &x_pow;
                x_pow *= &x;
            }
            shares.push(DecryptionShare { index: i, d_i: val });
        }
        let setup = ThresholdSetup {
            ek,
            theta,
            n,
            corruption_threshold: corruption_t,
            delta,
        };

        let rp = Integer::generate_safe_prime(&mut rng, 1536);
        let rq = Integer::generate_safe_prime(&mut rng, 1536);
        let n_tilde = &rp * &rq;
        let h1 = Integer::sample_in_mult_group_of(&mut rng, &n_tilde);
        let rlambda = (&rp - Integer::one()) * (&rq - Integer::one());
        let h2 = h1.pow_mod_ref(&rlambda, &n_tilde).expect("pow_mod");

        (setup, shares, n_tilde, h1, h2)
    }

    pub fn run_keygen(
        n: u16,
        corruption_t: u16,
        threshold_setup: ThresholdSetup,
        dec_shares: Vec<DecryptionShare>,
        h1: Integer,
        h2: Integer,
        n_tilde: Integer,
    ) -> Vec<Ggn16KeyShare<C>> {
        use tecdsa_ggn16::keygen::Ggn16KeygenMachine;

        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let mut rng = tecdsa_core::Csprng::new();
        let t = corruption_t + 1;

        let machines: Vec<_> = dec_shares
            .into_iter()
            .enumerate()
            .map(|(i, dec_share)| {
                let pid = all_parties[i];
                (
                    pid,
                    Ggn16KeygenMachine::<C>::new(
                        pid,
                        all_parties.clone(),
                        t,
                        threshold_setup.clone(),
                        dec_share,
                        h1.clone(),
                        h2.clone(),
                        n_tilde.clone(),
                        &mut rng,
                    ),
                )
            })
            .collect();

        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");
        results
            .into_iter()
            .map(|r| r.expect("keygen must succeed"))
            .collect()
    }
}

fn cggmp20_benchmarks(c: &mut Criterion) {
    use tecdsa_cggmp20::{
        aux_info::AuxInfoMachine, keygen::Cggmp20KeygenMachine, presign::Cggmp20PresignMachine,
        security_level::SecurityLevel128, sign::types::PartialSignature,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    {
        let cfg = make_session_configs(2, 2)[0].clone();
        let mut setup_group = c.benchmark_group("multiparty/cggmp20");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/cggmp20", |b| {
            b.iter(|| {
                let mut rng = tecdsa_core::Csprng::new();
                AuxInfoMachine::<SecurityLevel128>::new(&cfg, &mut rng)
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/cggmp20");
    per_party::configure_replay_group(&mut group, SAMPLES);

    for &(n, t) in &dkg_configs {
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let configs = make_session_configs(n, t);
            let builders: Vec<_> = configs
                .iter()
                .map(|cfg| {
                    let cfg = cfg.clone();
                    let pid = cfg.local_party.id;
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        Cggmp20KeygenMachine::<C>::new(&cfg, &mut rng)
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/cggmp20/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    let mut aux_ns: Vec<u16> = dkg_configs.iter().map(|&(n, _)| n).collect();
    aux_ns.sort_unstable();
    aux_ns.dedup();
    for &n in &aux_ns {
        let (aux_full_runs, aux_rounds_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let configs = make_session_configs(n, n);
            let builders: Vec<_> = configs
                .iter()
                .map(|cfg| {
                    let cfg = cfg.clone();
                    let pid = cfg.local_party.id;
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        AuxInfoMachine::<SecurityLevel128>::new(&cfg, &mut rng)
                    })
                })
                .collect();
            let timings = per_party::run_timed_with_init(builders, 10).1;
            (
                per_party::active_map(timings.clone()),
                per_party::active_map_rounds_only(timings),
            )
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("aux_info/cggmp20/n{n}/party{party_idx}"),
                &aux_full_runs,
                PartyId(party_idx),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("aux_info_rounds/cggmp20/n{n}/party{party_idx}"),
                &aux_rounds_runs,
                PartyId(party_idx),
            );
        }
    }

    let aux_infos: Vec<Arc<_>> = cggmp20_helpers::run_aux_info(sign_n)
        .into_iter()
        .map(Arc::new)
        .collect();
    let shares_by_t: Vec<(u16, Vec<_>)> = sign_thresholds
        .iter()
        .map(|&t| (t, cggmp20_helpers::run_keygen(sign_n, t)))
        .collect();

    for (t, core_shares) in &shares_by_t {
        let t = *t;
        let signers = config::first_signers(t);
        let presign_runs = per_party::precompute_runs(SAMPLES, || {
            let kg_t = core_shares[0].vss_setup.threshold;
            let signer_configs = make_signer_configs(&signers, sign_n, kg_t);
            let builders: Vec<_> = signers
                .iter()
                .enumerate()
                .map(|(idx, &signer_1based)| {
                    let pid = PartyId(signer_1based);
                    let cfg = signer_configs[idx].clone();
                    let core_share = core_shares[(signer_1based - 1) as usize].clone();
                    let aux = Arc::clone(&aux_infos[(signer_1based - 1) as usize]);
                    let signers_clone = signers.clone();
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        Cggmp20PresignMachine::<C>::with_security::<SecurityLevel128>(
                            &cfg,
                            &core_share,
                            &aux,
                            &signers_clone,
                            &mut rng,
                        )
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/cggmp20/n{sign_n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();

    let mut sign_group = c.benchmark_group("multiparty/cggmp20");
    sign_group.sample_size(10);
    let message = make_data_to_sign(b"benchmark message");
    for (t, core_shares) in &shares_by_t {
        let t = *t;
        let signers = config::first_signers(t);
        let presigs = cggmp20_helpers::run_presign(core_shares, &aux_infos, &signers);
        let public_key = &core_shares[0].public_key;

        for (idx, &signer) in signers.iter().enumerate().take(1) {
            sign_group.bench_function(
                format!("online_sign/cggmp20/n{sign_n}_t{t}/party{signer}/partial_sign"),
                |b| {
                    b.iter(|| presigs[idx].0.partial_sign(&message));
                },
            );
        }

        let partials: Vec<_> = presigs
            .iter()
            .map(|(p, _)| p.partial_sign(&message))
            .collect();
        let pub_data = &presigs[0].1;
        sign_group.bench_function(format!("online_sign/cggmp20/n{sign_n}_t{t}/combine"), |b| {
            b.iter(|| PartialSignature::combine(&partials, pub_data, public_key, &message));
        });
    }

    sign_group.finish();
}

fn dkls23_benchmarks(c: &mut Criterion) {
    use tecdsa_dkls23::{
        keygen::Dkls23KeygenMachine,
        presign::{Dkls23PresignMachine, PresignConfig},
        sign::{Dkls23OnlineSignMachine, OnlineSignConfig},
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();
    let message = make_data_to_sign(b"benchmark message");

    let mut group = c.benchmark_group("multiparty/dkls23");
    per_party::configure_replay_group(&mut group, SAMPLES);

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let all_p = all_parties.clone();
            let builders: Vec<_> = all_p
                .iter()
                .map(|&p| {
                    let all_p2 = all_p.clone();
                    (p, move || {
                        let mut rng = rand::thread_rng();
                        Dkls23KeygenMachine::<C>::new(p, all_p2, t, &mut rng)
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/dkls23/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    for &t in &sign_thresholds {
        let n = sign_n;
        let signer_indices = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signer_indices.iter().map(|&i| PartyId(i)).collect();

        let shares = dkls23_helpers::run_keygen(n, t);

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signer_indices
                .iter()
                .map(|&idx| {
                    let share = shares[(idx - 1) as usize].clone();
                    let pid = PartyId(idx);
                    let signer_parties_clone = signer_parties.clone();
                    (pid, move || {
                        let config = PresignConfig {
                            key_share: share,
                            my_id: pid,
                            signer_parties: signer_parties_clone,
                        };
                        Dkls23PresignMachine::new(config, rand_core::OsRng)
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 20);

            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();
            let sign_builders: Vec<_> = presigs
                .into_iter()
                .map(|presig| {
                    let pid = presig.my_id;
                    (pid, move || {
                        let config = OnlineSignConfig {
                            presignature: presig,
                            message,
                        };
                        Dkls23OnlineSignMachine::new(config)
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signer_indices.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/dkls23/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/dkls23/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }

        let full_runs = per_party::precompute_runs(SAMPLES, || {
            let presign_builders: Vec<_> = signer_indices
                .iter()
                .map(|&idx| {
                    let share = shares[(idx - 1) as usize].clone();
                    let pid = PartyId(idx);
                    let signer_parties_clone = signer_parties.clone();
                    (pid, move || {
                        let config = PresignConfig {
                            key_share: share,
                            my_id: pid,
                            signer_parties: signer_parties_clone,
                        };
                        Dkls23PresignMachine::new(config, rand_core::OsRng)
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 20);

            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();
            let sign_builders: Vec<_> = presigs
                .into_iter()
                .map(|presig| {
                    let pid = presig.my_id;
                    (pid, move || {
                        let config = OnlineSignConfig {
                            presignature: presig,
                            message,
                        };
                        Dkls23OnlineSignMachine::new(config)
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            let mut map = per_party::active_map(presign_timings);
            for (pid, d) in per_party::active_map(sign_timings) {
                *map.entry(pid).or_default() += d;
            }
            map
        });
        for &signer in signer_indices.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("full_sign/dkls23/n{n}_t{t}/party{signer}"),
                &full_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn gg18_benchmarks(c: &mut Criterion) {
    use tecdsa_gg18::{
        keygen::{Gg18KeygenMachine, PaillierPrecomputed},
        presign::{Gg18PresignMachine, PresignConfig},
        sign::{Gg18OnlineSignMachine, OnlineSignConfig},
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();
    let message = make_data_to_sign(b"benchmark message");

    {
        let mut setup_group = c.benchmark_group("multiparty/gg18");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/gg18", |b| {
            b.iter(|| PaillierPrecomputed::generate(&mut tecdsa_core::Csprng::new()));
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/gg18");
    per_party::configure_replay_group(&mut group, SAMPLES);

    for &(n, t) in &dkg_configs {
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let configs = make_session_configs(n, t);
            let builders: Vec<_> = configs
                .iter()
                .map(|cfg| {
                    let cfg = cfg.clone();
                    let pid = cfg.local_party.id;
                    let precomputed =
                        PaillierPrecomputed::generate(&mut tecdsa_core::Csprng::new());
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        Gg18KeygenMachine::<C>::new_with_precomputed(&cfg, precomputed, &mut rng)
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/gg18/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    for &t in &sign_thresholds {
        let n = sign_n;
        let signers = config::first_signers(t);

        let key_shares = gg18_helpers::run_keygen(n, t);

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&signer_1based| {
                    let party_0based = (signer_1based - 1) as usize;
                    let pid = PartyId(signer_1based);
                    let key_share = key_shares[party_0based].clone();
                    let signers_clone = signers.clone();
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        let config = PresignConfig {
                            key_share,
                            signers: signers_clone,
                        };
                        Gg18PresignMachine::new(config, &mut rng)
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);

            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();
            let sign_builders: Vec<_> = presigs
                .into_iter()
                .map(|presig| {
                    let pid = presig.my_id;
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        let config = OnlineSignConfig {
                            presignature: presig,
                            message,
                        };
                        Gg18OnlineSignMachine::new(config, &mut rng)
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/gg18/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/gg18/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }

        let full_runs = per_party::precompute_runs(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&signer_1based| {
                    let party_0based = (signer_1based - 1) as usize;
                    let pid = PartyId(signer_1based);
                    let key_share = key_shares[party_0based].clone();
                    let signers_clone = signers.clone();
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        let config = PresignConfig {
                            key_share,
                            signers: signers_clone,
                        };
                        Gg18PresignMachine::new(config, &mut rng)
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);

            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();
            let sign_builders: Vec<_> = presigs
                .into_iter()
                .map(|presig| {
                    let pid = presig.my_id;
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        let config = OnlineSignConfig {
                            presignature: presig,
                            message,
                        };
                        Gg18OnlineSignMachine::new(config, &mut rng)
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            let mut map = per_party::active_map(presign_timings);
            for (pid, d) in per_party::active_map(sign_timings) {
                *map.entry(pid).or_default() += d;
            }
            map
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("full_sign/gg18/n{n}_t{t}/party{signer}"),
                &full_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn ggn16_benchmarks(c: &mut Criterion) {
    use tecdsa_ggn16::{
        keygen::Ggn16KeygenMachine, presign::Ggn16PresignMachine, sign::Ggn16OnlineSignMachine,
    };
    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();
    let message = make_data_to_sign(b"benchmark message");

    {
        let mut setup_group = c.benchmark_group("multiparty/ggn16");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/ggn16", |b| {
            b.iter(|| ggn16_helpers::fast_trusted_dealer_setup(2, 1));
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/ggn16");
    per_party::configure_replay_group(&mut group, SAMPLES);

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let (ts, ds, nt, h1c, h2c) = ggn16_helpers::fast_trusted_dealer_setup(n, t - 1);
            let builders: Vec<_> = ds
                .into_iter()
                .enumerate()
                .map(|(i, dec_share)| {
                    let pid = all_parties[i];
                    let all_parties = all_parties.clone();
                    let ts = ts.clone();
                    let h1c = h1c.clone();
                    let h2c = h2c.clone();
                    let nt = nt.clone();
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        Ggn16KeygenMachine::<C>::new(
                            pid,
                            all_parties,
                            t,
                            ts,
                            dec_share,
                            h1c,
                            h2c,
                            nt,
                            &mut rng,
                        )
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/ggn16/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    for &t in &sign_thresholds {
        let n = sign_n;
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        let (threshold_setup, dec_shares, n_tilde, h1, h2) =
            ggn16_helpers::fast_trusted_dealer_setup(n, t - 1);
        let key_shares =
            ggn16_helpers::run_keygen(n, t - 1, threshold_setup, dec_shares, h1, h2, n_tilde);

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let key_share = key_shares[(s - 1) as usize].clone();
                    let signer_parties = signer_parties.clone();
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        Ggn16PresignMachine::<C>::new(key_share, pid, signer_parties, &mut rng)
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            let sign_builders: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (pid, move || {
                        Ggn16OnlineSignMachine::<C>::new(presig, message).expect("ggn16 sign")
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/ggn16/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/ggn16/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn ln18_benchmarks(c: &mut Criterion) {
    use tecdsa_ln18::{
        key_share::Ln18KeyShare,
        keygen::Ln18KeygenMachine,
        sign::{
            build_signing_setup, Ln18MtaBackend, Ln18MtaHybrid, Ln18OfflineSignMachine,
            Ln18OfflineSignParams, Ln18OnlineSignMachine, Ln18OnlineSignParams,
        },
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();
    let message = make_data_to_sign(b"benchmark message");
    let m_scalar = *message.digest();
    let backend = Ln18MtaBackend::Paillier;

    let mut group = c.benchmark_group("multiparty/ln18");
    per_party::configure_replay_group(&mut group, SAMPLES);

    for &(n, t) in &dkg_configs {
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let configs = make_session_configs(n, t);
            let builders: Vec<_> = configs
                .iter()
                .map(|cfg| {
                    let cfg = cfg.clone();
                    let pid = cfg.local_party.id;
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        Ln18KeygenMachine::<C>::new(&cfg, &mut rng)
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/ln18/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    for &t in &sign_thresholds {
        let n = sign_n;
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        let key_shares: Vec<Ln18KeyShare<C>> = {
            let configs = make_session_configs(n, t);
            let mut rng = tecdsa_core::Csprng::new();
            let machines: Vec<_> = configs
                .iter()
                .map(|cfg| (cfg.local_party.id, Ln18KeygenMachine::<C>::new(cfg, &mut rng)))
                .collect();
            Orchestrator::new(machines, 10)
                .run()
                .expect("orch")
                .into_iter()
                .map(|r| r.expect("ln18 keygen"))
                .collect()
        };

        let setup_t0 = std::time::Instant::now();
        let base_params = {
            let mut rng = rand_core::OsRng;
            build_signing_setup::<C>(&key_shares, &signer_parties, &mut rng)
                .expect("ln18 signing setup")
        };
        let setup_per_party = setup_t0.elapsed() / signer_parties.len() as u32;

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let mta = Arc::new(Ln18MtaHybrid::<C>::new(signer_parties.clone(), backend));

            let offline_builders: Vec<_> = signers
                .iter()
                .enumerate()
                .map(|(pos, &s)| {
                    let pid = PartyId(s);
                    let base = base_params[pos].clone();
                    let signer_parties = signer_parties.clone();
                    let mta = Arc::clone(&mta);
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        let params = Ln18OfflineSignParams {
                            base,
                            signer_parties: signer_parties.clone(),
                            mta,
                        };
                        Ln18OfflineSignMachine::<C>::new(pid, signer_parties, params, &mut rng)
                    })
                })
                .collect();
            let (offline_outputs, offline_timings) =
                per_party::run_timed_with_init(offline_builders, 4);
            let offline_states: Vec<_> = offline_outputs.into_iter().map(|r| r.unwrap()).collect();

            let sign_builders: Vec<_> = offline_states
                .into_iter()
                .map(|state| {
                    let pid = state.my_id;
                    (pid, move || {
                        let mut rng = tecdsa_core::Csprng::new();
                        let params = Ln18OnlineSignParams {
                            offline_state: state,
                            message_digest: m_scalar,
                        };
                        Ln18OnlineSignMachine::<C>::new(params, &mut rng)
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 8);

            let mut offline_map = per_party::active_map(offline_timings);
            for d in offline_map.values_mut() {
                *d += setup_per_party;
            }
            (offline_map, per_party::active_map(sign_timings))
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/ln18/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/ln18/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn tx25_benchmarks(c: &mut Criterion) {
    use tecdsa_tx25::{
        keygen::Tx25KeygenMachine, presign::Tx25PresignMachine, sign::Tx25OnlineSignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    {
        let mut setup_group = c.benchmark_group("multiparty/tx25");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/tx25", |b| {
            b.iter(|| {
                let mut s = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit("42042")
                    .expect("cl setup");
                s.keygen().expect("cl keygen")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/tx25");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_bytes = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let builders: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    let all_parties = all_parties.clone();
                    let mut cl_setup = cl_setup.clone();
                    let (cl_sk, cl_pk) = cl_setup.keygen().expect("tx25 cl keygen");
                    (pid, move || {
                        Tx25KeygenMachine::new_with_keypair(
                            pid,
                            all_parties,
                            t,
                            seed,
                            true,
                            cl_setup,
                            cl_sk,
                            cl_pk,
                        )
                        .expect("tx25 keygen")
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/tx25/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        let key_shares = {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    (
                        pid,
                        Tx25KeygenMachine::new_with_setup(
                            pid,
                            all_parties.clone(),
                            t,
                            seed,
                            true,
                            cl_setup.clone(),
                        )
                        .expect("tx25 keygen"),
                    )
                })
                .collect();
            let result = Orchestrator::new(machines, 10).run().expect("orch");
            result.into_iter().map(|r| r.unwrap()).collect::<Vec<_>>()
        };

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let key_share = &key_shares[(s - 1) as usize];
                    let signer_parties = signer_parties.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        Tx25PresignMachine::new(pid, signer_parties, key_share, cl_setup)
                            .expect("tx25 presign")
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            let pk = key_shares[0].public_key;
            let sign_builders: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    let signer_parties = signer_parties.clone();
                    (pid, move || {
                        Tx25OnlineSignMachine::new(pid, signer_parties, presig, &msg_bytes, pk)
                            .expect("tx25 sign")
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/tx25/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/tx25/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn jtx25_benchmarks(c: &mut Criterion) {
    use tecdsa_jtx25::{
        keygen::Jtx25KeygenMachine, presign::Jtx25PresignMachine, sign::Jtx25OnlineSignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    {
        let mut setup_group = c.benchmark_group("multiparty/jtx25");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/jtx25", |b| {
            b.iter(|| {
                let mut s = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit("42042")
                    .expect("cl setup");
                s.keygen().expect("cl keygen")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/jtx25");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_bytes = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let builders: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    let all_parties = all_parties.clone();
                    let mut cl_setup = cl_setup.clone();
                    let (cl_sk, cl_pk) = cl_setup.keygen().expect("jtx25 cl keygen");
                    (pid, move || {
                        Jtx25KeygenMachine::new_with_keypair(
                            pid,
                            all_parties,
                            t,
                            seed,
                            true,
                            cl_setup,
                            cl_sk,
                            cl_pk,
                        )
                        .expect("jtx25 keygen")
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/jtx25/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        let key_shares = {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    (
                        pid,
                        Jtx25KeygenMachine::new_with_setup(
                            pid,
                            all_parties.clone(),
                            t,
                            seed,
                            true,
                            cl_setup.clone(),
                        )
                        .expect("jtx25 keygen"),
                    )
                })
                .collect();
            let (outputs, _) = per_party::run_timed_without_init(machines, 10);
            outputs.into_iter().map(|r| r.unwrap()).collect::<Vec<_>>()
        };

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let key_share = &key_shares[(s - 1) as usize];
                    let signer_parties = signer_parties.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        Jtx25PresignMachine::new(pid, signer_parties, key_share, cl_setup)
                            .expect("jtx25 presign")
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            let pk = key_shares[0].public_key;
            let sign_builders: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    let signer_parties = signer_parties.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        Jtx25OnlineSignMachine::new_with_setup(
                            pid,
                            signer_parties,
                            presig,
                            &msg_bytes,
                            pk,
                            cl_setup,
                        )
                        .expect("jtx25 sign")
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/jtx25/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/jtx25/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn jtx25_robust_benchmarks(c: &mut Criterion) {
    use tecdsa_jtx25::{
        keygen::Jtx25KeygenMachine, presign::robust::Jtx25RobustPresignMachine,
        sign::robust::Jtx25RobustOnlineSignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    {
        let mut setup_group = c.benchmark_group("multiparty/jtx25_robust");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/jtx25_robust", |b| {
            b.iter(|| {
                let mut s = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit("42042")
                    .expect("cl setup");
                s.keygen().expect("cl keygen")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/jtx25_robust");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_bytes = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let builders: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    let all_parties = all_parties.clone();
                    let mut cl_setup = cl_setup.clone();
                    let (cl_sk, cl_pk) = cl_setup.keygen().expect("jtx25 cl keygen");
                    (pid, move || {
                        Jtx25KeygenMachine::new_with_keypair(
                            pid,
                            all_parties,
                            t,
                            seed,
                            true,
                            cl_setup,
                            cl_sk,
                            cl_pk,
                        )
                        .expect("jtx25 keygen")
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/jtx25_robust/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        let key_shares = {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    (
                        pid,
                        Jtx25KeygenMachine::new_with_setup(
                            pid,
                            all_parties.clone(),
                            t,
                            seed,
                            true,
                            cl_setup.clone(),
                        )
                        .expect("jtx25 keygen"),
                    )
                })
                .collect();
            let (outputs, _) = per_party::run_timed_without_init(machines, 10);
            outputs.into_iter().map(|r| r.unwrap()).collect::<Vec<_>>()
        };

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let key_share = &key_shares[(s - 1) as usize];
                    let signer_parties = signer_parties.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        Jtx25RobustPresignMachine::new(pid, signer_parties, key_share, cl_setup)
                            .expect("jtx25 robust presign")
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            let pk = key_shares[0].public_key;
            let sign_builders: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    let signer_parties = signer_parties.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        Jtx25RobustOnlineSignMachine::new_with_setup(
                            pid,
                            signer_parties,
                            presig,
                            &msg_bytes,
                            pk,
                            cl_setup,
                        )
                        .expect("jtx25 robust sign")
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/jtx25_robust/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/jtx25_robust/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn wmy23_benchmarks(c: &mut Criterion) {
    use tecdsa_wmy23::{
        keygen::Wmy23KeygenMachine,
        presign::{PresignConfig, Wmy23PresignMachine},
        sign::Wmy23OnlineSignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    {
        let mut setup_group = c.benchmark_group("multiparty/wmy23");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/wmy23", |b| {
            b.iter(|| {
                let mut s = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit("42042")
                    .expect("cl setup");
                s.keygen().expect("cl keygen")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/wmy23");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_data = make_data_to_sign(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let builders: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    let all_parties = all_parties.clone();
                    let mut cl_setup = cl_setup.clone();
                    let (cl_sk, cl_pk) = cl_setup.keygen().expect("wmy23 cl keygen");
                    (pid, move || {
                        Wmy23KeygenMachine::new_with_keypair(
                            pid,
                            all_parties,
                            t,
                            seed,
                            true,
                            cl_setup,
                            cl_sk,
                            cl_pk,
                        )
                        .expect("wmy23 keygen")
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/wmy23/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        let key_shares = {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    (
                        pid,
                        Wmy23KeygenMachine::new_with_setup(
                            pid,
                            all_parties.clone(),
                            t,
                            seed,
                            true,
                            cl_setup.clone(),
                        )
                        .expect("wmy23 keygen"),
                    )
                })
                .collect();
            Orchestrator::new(machines, 10)
                .run()
                .expect("orch")
                .into_iter()
                .map(|r| r.unwrap())
                .collect::<Vec<_>>()
        };
        let public_key = key_shares[0].public_key;

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let key_share = key_shares[(s - 1) as usize].clone();
                    let signer_parties = signer_parties.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        let config = PresignConfig {
                            key_share,
                            my_id: pid,
                            signer_parties,
                            cl_setup,
                        };
                        Wmy23PresignMachine::new(config).expect("wmy23 presign")
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            let sign_builders: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    let signer_parties = signer_parties.clone();
                    (pid, move || {
                        Wmy23OnlineSignMachine::new(
                            pid,
                            signer_parties,
                            presig,
                            msg_data,
                            public_key,
                        )
                        .expect("wmy23 sign")
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/wmy23/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/wmy23/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn wmc24_benchmarks(c: &mut Criterion) {
    use tecdsa_wmc24::{
        keygen::Wmc24KeygenMachine, presign::Wmc24PresignMachine, sign::Wmc24OnlineSignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    {
        let mut setup_group = c.benchmark_group("multiparty/wmc24");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/wmc24", |b| {
            b.iter(|| {
                let mut s = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit("42042")
                    .expect("cl setup");
                s.keygen().expect("cl keygen")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/wmc24");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_bytes = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let builders: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    let all_parties = all_parties.clone();
                    let mut cl_setup = cl_setup.clone();
                    let (cl_sk, cl_pk) = cl_setup.keygen().expect("wmc24 cl keygen");
                    (pid, move || {
                        Wmc24KeygenMachine::new_with_keypair(
                            pid,
                            all_parties,
                            t,
                            seed,
                            true,
                            cl_setup,
                            cl_sk,
                            cl_pk,
                        )
                        .expect("wmc24 keygen")
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/wmc24/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        let key_shares = {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    (
                        pid,
                        Wmc24KeygenMachine::new_with_setup(
                            pid,
                            all_parties.clone(),
                            t,
                            seed,
                            true,
                            cl_setup.clone(),
                        )
                        .expect("wmc24 keygen"),
                    )
                })
                .collect();
            let (outputs, _) = per_party::run_timed_without_init(machines, 10);
            outputs.into_iter().map(|r| r.unwrap()).collect::<Vec<_>>()
        };

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let key_share = &key_shares[(s - 1) as usize];
                    let signer_parties = signer_parties.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        Wmc24PresignMachine::new(pid, signer_parties, key_share, cl_setup)
                            .expect("wmc24 presign")
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            let pk = key_shares[0].public_key;
            let sign_builders: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    let signer_parties = signer_parties.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        Wmc24OnlineSignMachine::new_with_setup(
                            pid,
                            signer_parties,
                            presig,
                            &msg_bytes,
                            pk,
                            cl_setup,
                        )
                        .expect("wmc24 sign")
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/wmc24/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/wmc24/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn llz25_benchmarks(c: &mut Criterion) {
    use tecdsa_llz25::{
        keygen::Llz25KeygenMachine, presign::machine::Llz25PresignMachine,
        sign::machine::Llz25SignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    {
        let mut setup_group = c.benchmark_group("multiparty/llz25");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/llz25", |b| {
            b.iter(|| {
                let mut s = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit("42042")
                    .expect("cl setup");
                s.keygen().expect("cl keygen")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/llz25");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_bytes = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    let pk_crs = {
        let mut tmp = cl_setup.clone();
        let (_, pk) = tmp.keygen().expect("crs keygen");
        pk
    };

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let builders: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    let all_parties = all_parties.clone();
                    let pk_crs = pk_crs.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        Llz25KeygenMachine::new_with_setup(
                            pid,
                            all_parties,
                            t,
                            seed,
                            true,
                            pk_crs,
                            cl_setup,
                        )
                        .expect("llz25 keygen")
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/llz25/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
        let quorum_indices: Vec<u16> = signers.clone();

        let key_shares = {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    (
                        pid,
                        Llz25KeygenMachine::new_with_setup(
                            pid,
                            all_parties.clone(),
                            t,
                            seed,
                            true,
                            pk_crs.clone(),
                            cl_setup.clone(),
                        )
                        .expect("llz25 keygen"),
                    )
                })
                .collect();
            Orchestrator::new(machines, 10)
                .run()
                .expect("orch")
                .into_iter()
                .map(|r| r.unwrap())
                .collect::<Vec<_>>()
        };

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .enumerate()
                .map(|(pos, &s)| {
                    let pid = PartyId(s);
                    let signer_parties = signer_parties.clone();
                    let key_share = key_shares[(s - 1) as usize].clone();
                    let quorum_indices = quorum_indices.clone();
                    let cl_setup = cl_setup.clone();
                    let pk_crs = pk_crs.clone();
                    (pid, move || {
                        Llz25PresignMachine::new(
                            pid,
                            signer_parties,
                            key_share,
                            quorum_indices,
                            pos,
                            cl_setup,
                            pk_crs,
                        )
                        .expect("llz25 presign")
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            let sign_builders: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    let signer_parties = signer_parties.clone();
                    let cl_setup = cl_setup.clone();
                    (pid, move || {
                        Llz25SignMachine::new_with_setup(
                            pid,
                            signer_parties,
                            presig,
                            &msg_bytes,
                            cl_setup,
                        )
                        .expect("llz25 sign")
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/llz25/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/llz25/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn trout_benchmarks(c: &mut Criterion) {
    use tecdsa_trout::{
        keygen::TroutKeygenMachine, presign::machine::TroutPresignMachine,
        sign::machine::TroutSignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    {
        let mut setup_group = c.benchmark_group("multiparty/trout");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/trout", |b| {
            b.iter(|| {
                let mut s = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit("42042")
                    .expect("cl setup");
                let _evrf = tecdsa_evrf::EvrfSecretKey::<C>::generate(&mut rand_core::OsRng);
                s.keygen().expect("cl keygen")
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/trout");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let message = make_data_to_sign(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let builders: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    let all_parties = all_parties.clone();
                    let mut cl_setup = cl_setup.clone();
                    let (evrf_sk, evrf_pk) =
                        tecdsa_evrf::EvrfSecretKey::<C>::generate(&mut rand_core::OsRng);
                    let (_cl_sk, cl_pk_i) = cl_setup.keygen().expect("trout cl keygen");
                    (pid, move || {
                        TroutKeygenMachine::new_with_key_material(
                            pid,
                            all_parties,
                            t,
                            seed,
                            true,
                            cl_setup,
                            evrf_sk,
                            evrf_pk,
                            cl_pk_i,
                        )
                        .expect("trout keygen")
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/trout/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
        let signing_1based: Vec<u16> = signers.clone();

        let key_shares = {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    (
                        pid,
                        TroutKeygenMachine::new_with_setup(
                            pid,
                            all_parties.clone(),
                            t,
                            seed,
                            true,
                            cl_setup.clone(),
                        )
                        .expect("trout keygen"),
                    )
                })
                .collect();
            Orchestrator::new(machines, 10)
                .run()
                .expect("orch")
                .into_iter()
                .map(|r| r.unwrap())
                .collect::<Vec<_>>()
        };

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let local_setup = cl_setup.clone();
                    let share = key_shares[(s - 1) as usize].clone();
                    let (pa, pb, pc) = &share.cl_pk_abc;
                    let cl_pk_qfi =
                        tecdsa_trout::error::qfi_from_abc(pa, pb, pc).expect("reconstruct CL pk");
                    let cl_pk = local_setup.pk_from_qfi(&cl_pk_qfi).expect("pk_from_qfi");
                    let signer_parties = signer_parties.clone();
                    let signing_1based = signing_1based.clone();
                    (pid, move || {
                        TroutPresignMachine::new(
                            pid,
                            signer_parties,
                            share,
                            signing_1based,
                            b"bench-session",
                            local_setup,
                            cl_pk,
                        )
                        .expect("trout presign")
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            let sign_builders: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    let local_setup = cl_setup.clone();
                    let share = key_shares[(s - 1) as usize].clone();
                    let (pa, pb, pc) = &share.cl_pk_abc;
                    let cl_pk_qfi =
                        tecdsa_trout::error::qfi_from_abc(pa, pb, pc).expect("reconstruct CL pk");
                    let cl_pk = local_setup.pk_from_qfi(&cl_pk_qfi).expect("pk_from_qfi");
                    let signer_parties = signer_parties.clone();
                    (pid, move || {
                        TroutSignMachine::new(
                            pid,
                            signer_parties,
                            presig,
                            &message,
                            &share,
                            local_setup,
                            &cl_pk,
                        )
                        .expect("trout sign")
                    })
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/trout/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/trout/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

fn xal23_benchmarks(c: &mut Criterion) {
    use tecdsa_xal23::{
        keygen::Xal23KeygenMachine, presign::Xal23PresignMachine, sign::Xal23SignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    {
        let mut setup_group = c.benchmark_group("multiparty/xal23");
        setup_group.sample_size(10);
        setup_group.bench_function("setup/xal23", |b| {
            b.iter(|| {
                tecdsa_joye_libert::kgen::generate_keypair_with_qnr(
                    1680,
                    712,
                    &mut rand_core::OsRng,
                )
            });
        });
        setup_group.finish();
    }

    let mut group = c.benchmark_group("multiparty/xal23");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let message = make_data_to_sign(b"benchmark message");

    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let builders: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    let all_parties = all_parties.clone();
                    let (jl_pk, jl_sk, jl_qnr) =
                        tecdsa_joye_libert::kgen::generate_keypair_with_qnr(
                            1680,
                            712,
                            &mut rand_core::OsRng,
                        );
                    (pid, move || {
                        Xal23KeygenMachine::<C>::new_with_jl_keypair(
                            pid,
                            all_parties,
                            t,
                            jl_pk,
                            jl_sk,
                            jl_qnr,
                            1680,
                            712,
                        )
                        .expect("xal23 keygen")
                    })
                })
                .collect();
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("dkg/xal23/n{n}_t{t}/party{party_idx}"),
                &dkg_runs,
                PartyId(party_idx),
            );
        }
    }

    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        let mut key_shares = {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| {
                    (
                        pid,
                        Xal23KeygenMachine::<C>::new(pid, all_parties.clone(), t, 1680, 712)
                            .expect("xal23 keygen"),
                    )
                })
                .collect();
            Orchestrator::new(machines, 10)
                .run()
                .expect("orch")
                .into_iter()
                .map(|r| r.unwrap())
                .collect::<Vec<_>>()
        };
        let lambdas = tecdsa_vss::lagrange::coefficients::<C>(&signers);
        for (pos, &s) in signers.iter().enumerate() {
            key_shares[(s - 1) as usize].secret_share *= lambdas[pos];
        }

        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            let presign_builders: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let key_share = key_shares[(s - 1) as usize].clone();
                    let signer_parties = signer_parties.clone();
                    (pid, move || {
                        Xal23PresignMachine::<C>::new(
                            pid,
                            signer_parties,
                            &key_share,
                            &mut rand_core::OsRng,
                        )
                        .expect("xal23 presign")
                    })
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_with_init(presign_builders, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            let sign_builders: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (pid, move || Xal23SignMachine::<C>::new(presig, message))
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_with_init(sign_builders, 10);

            (
                per_party::active_map(presign_timings),
                per_party::active_map(sign_timings),
            )
        });
        for &signer in signers.iter().take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("presign/xal23/n{n}_t{t}/party{signer}"),
                &presign_runs,
                PartyId(signer),
            );
            per_party::bench_party_replay(
                &mut group,
                format!("online_sign/xal23/n{n}_t{t}/party{signer}"),
                &online_runs,
                PartyId(signer),
            );
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    cggmp20_benchmarks,
    dkls23_benchmarks,
    gg18_benchmarks,
    ln18_benchmarks,
    ggn16_benchmarks,
    tx25_benchmarks,
    jtx25_benchmarks,
    jtx25_robust_benchmarks,
    wmy23_benchmarks,
    wmc24_benchmarks,
    llz25_benchmarks,
    trout_benchmarks,
    xal23_benchmarks
);
criterion_main!(benches);
