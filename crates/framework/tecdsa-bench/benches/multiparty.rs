// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multi-party protocol benchmark suite for threshold ECDSA protocols.
//!
//! Benchmarks multi-party protocols:
//! - **CGGMP20**: Paillier-based, 4-round presign + local sign, `SecurityLevel128`
//! - **DKLs23**: OT/VOLE-based, 3-round presign + 1-round online sign
//! - **GG18**: Classic, 3-round presign + 5-round online sign
//! - **GGN16**: Shared Paillier + threshold decryption, 2-round keygen + 6-round sign
//! - **TX25**: CL public-checked MtA, 2-round presign + 1-round sign
//! - **JTX25**: Threshold CL decryption, 2-round presign + 1-round sign
//! - **WMY23**: CL-based MtAwc, 4-round presign + 1-round sign
//! - **WMC24**: Threshold CL + threshold ElGamal, 3-round presign + 1-round sign
//! - **LLZ25**: NIM over class groups, 3-round keygen + 1-round presign + 1-round sign
//! - **Trout**: eVRF + CL scaled decryption, 3-round keygen + 1-round presign + 1-round sign
//! - **XAL23**: JL-based MtA, 2-round keygen + 4-round presign + 1-round sign
//!
//! Each protocol is measured for keygen, presign, and sign phases with per-party
//! timing via the Orchestrator. The protocol always runs with all `n` parties
//! (they interact during the run), but per-party times are near-symmetric, so to
//! keep the output compact only the first participating party (party 1) is
//! reported per configuration.
//!
//! The swept `(n, t)` configurations are read from the environment at run time
//! (see [`tecdsa_bench::config`]), so they can be changed without recompiling:
//! - **DKG** sweeps `TECDSA_BENCH_DKG_CONFIGS` (default `3:3,7:7,11:11,15:15,20:20`).
//! - **Presign/Sign** sweep `TECDSA_BENCH_SIGN_N` (default `20`) parties with the
//!   thresholds in `TECDSA_BENCH_SIGN_THRESHOLDS` (default `2,3,7,11,15,20`); the
//!   signing quorum is parties `1..=t`.
//!
//! LN18 is benchmarked by `protocol_once`, not Criterion, because its per-session
//! Init + Lagrange setup does not fit the precompute/replay pattern used here.

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::ops::Reduce;
use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_bench::{config, per_party};
use tecdsa_protocol::{PartyId, PartyInfo, SessionConfig, SessionId};
use tecdsa_testkit::Orchestrator;

type C = Secp256k1;

/// Number of Criterion samples per party benchmark. Also the number of real
/// protocol executions per phase (plus one warm-up run). A single execution
/// produces every party's timing, which is then replayed per party.
const SAMPLES: usize = 10;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build `SessionConfig`s for `n` parties with signing threshold `t`.
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

/// Build `SessionConfig`s for a signing subset.
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

/// Create a DataToSign from raw bytes by SHA-256 hashing and reducing mod q.
fn make_data_to_sign(msg: &[u8]) -> tecdsa_protocol::DataToSign<C> {
    let hash_bytes: [u8; 32] = Sha256::digest(msg).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    tecdsa_protocol::DataToSign::from_digest(scalar)
}

// ===========================================================================
// CGGMP20
// ===========================================================================

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

// ===========================================================================
// DKLs23
// ===========================================================================

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

// ===========================================================================
// GG18
// ===========================================================================

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

// ===========================================================================
// GGN16 helpers
// ===========================================================================

mod ggn16_helpers {
    use tecdsa_ggn16::key_share::Ggn16KeyShare;
    use tecdsa_paillier::{
        backend::Integer,
        threshold::{DecryptionShare, ThresholdSetup},
    };

    use super::*;

    /// Generate threshold Paillier setup + Ring-Pedersen parameters for GGN16.
    ///
    /// `corruption_t` is the Paillier polynomial degree (= reconstruction threshold - 1).
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

        // Ring-Pedersen
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
        let t = corruption_t + 1; // reconstruction threshold for keygen constructor

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

// ===========================================================================
// Benchmark groups
// ===========================================================================

fn cggmp20_benchmarks(c: &mut Criterion) {
    use tecdsa_cggmp20::{
        aux_info::AuxInfoMachine, keygen::Cggmp20KeygenMachine, presign::Cggmp20PresignMachine,
        security_level::SecurityLevel128, sign::types::PartialSignature,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    let mut group = c.benchmark_group("multiparty/cggmp20");
    per_party::configure_replay_group(&mut group, SAMPLES);

    // --- DKG: sweep (n, t); one execution per sample, every party reported. ---
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

    // --- AuxInfo: depends only on n; sweep the distinct DKG party counts. ---
    let mut aux_ns: Vec<u16> = dkg_configs.iter().map(|&(n, _)| n).collect();
    aux_ns.sort_unstable();
    aux_ns.dedup();
    for &n in &aux_ns {
        let aux_runs = per_party::precompute_runs(SAMPLES, || {
            // Threshold is irrelevant to aux info; use a valid value (t = n).
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
            per_party::active_with_init(builders, 10)
        });
        for party_idx in (1..=n).take(1) {
            per_party::bench_party_replay(
                &mut group,
                format!("aux_info/cggmp20/n{n}/party{party_idx}"),
                &aux_runs,
                PartyId(party_idx),
            );
        }
    }

    // --- Presign/Sign setup (untimed): aux info once (n-only), shares per t. ---
    let aux_infos: Vec<Arc<_>> = cggmp20_helpers::run_aux_info(sign_n)
        .into_iter()
        .map(Arc::new)
        .collect();
    let shares_by_t: Vec<(u16, Vec<_>)> = sign_thresholds
        .iter()
        .map(|&t| (t, cggmp20_helpers::run_keygen(sign_n, t)))
        .collect();

    // --- Presign: per-party active time for each signer, swept over t. ---
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

    // --- Online Sign: local partial_sign + combine (not a StateMachine) ---
    // Kept in a separate group so they use normal Criterion timing; the replay
    // group above sets measurement_time to ~0 which would break real timing.
    let mut sign_group = c.benchmark_group("multiparty/cggmp20_sign");
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

    // --- DKG: sweep (n, t); every party reported separately. ---
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

    // --- Presign / Online sign / Full sign: sweep t at fixed n. ---
    for &t in &sign_thresholds {
        let n = sign_n;
        let signer_indices = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signer_indices.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: generate key shares once per threshold.
        let shares = dkls23_helpers::run_keygen(n, t);

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed. (Full sign below is a
        // separate end-to-end measurement.)
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed online sign).
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

            // Timed: online sign, consuming the presignatures just produced.
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

        // --- Full Sign: presign + online sign, per-party active time ---
        let full_runs = per_party::precompute_runs(SAMPLES, || {
            // Timed: presign
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

            // Timed: online sign
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

            // Per-party full-sign active time = presign + online sign.
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
        keygen::Gg18KeygenMachine,
        presign::{Gg18PresignMachine, PresignConfig},
        sign::{Gg18OnlineSignMachine, OnlineSignConfig},
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();
    let message = make_data_to_sign(b"benchmark message");

    let mut group = c.benchmark_group("multiparty/gg18");
    per_party::configure_replay_group(&mut group, SAMPLES);

    // --- DKG: sweep (n, t); every party reported separately. ---
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
                        Gg18KeygenMachine::<C>::new(&cfg, &mut rng)
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

    // --- Presign / Online sign / Full sign: sweep t at fixed n. ---
    for &t in &sign_thresholds {
        let n = sign_n;
        let signers = config::first_signers(t);

        // Untimed setup: generate key shares once per threshold.
        let key_shares = gg18_helpers::run_keygen(n, t);

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed. (Full sign below is a
        // separate end-to-end measurement.)
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed online sign).
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

            // Timed: online sign, consuming the presignatures just produced.
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

        // --- Full Sign: presign + online sign, per-party active time ---
        let full_runs = per_party::precompute_runs(SAMPLES, || {
            // Timed: presign
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

            // Timed: online sign
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

            // Per-party full-sign active time = presign + online sign.
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

    let mut group = c.benchmark_group("multiparty/ggn16");
    per_party::configure_replay_group(&mut group, SAMPLES);

    // --- DKG: sweep (n, t). GGN16 keygen requires pre-constructed machines with a
    // threshold-Paillier setup (corruption threshold t-1), so it uses
    // run_*_without_init (init not timed separately). The setup is re-generated
    // per run for independence. ---
    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
            let mut rng = tecdsa_core::Csprng::new();
            let (ts, ds, nt, h1c, h2c) = ggn16_helpers::fast_trusted_dealer_setup(n, t - 1);
            let machines: Vec<_> = ds
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
                            ts.clone(),
                            dec_share,
                            h1c.clone(),
                            h2c.clone(),
                            nt.clone(),
                            &mut rng,
                        ),
                    )
                })
                .collect();
            per_party::active_without_init(machines, 10)
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

    // --- Presign / Online sign: sweep t at fixed n. ---
    for &t in &sign_thresholds {
        let n = sign_n;
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: threshold Paillier + Ring-Pedersen + key shares per threshold.
        let (threshold_setup, dec_shares, n_tilde, h1, h2) =
            ggn16_helpers::fast_trusted_dealer_setup(n, t - 1);
        let key_shares =
            ggn16_helpers::run_keygen(n, t - 1, threshold_setup, dec_shares, h1, h2, n_tilde);

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed.
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed online sign).
            let mut rng = tecdsa_core::Csprng::new();
            let presign_machines: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Ggn16PresignMachine::<C>::new(
                            key_shares[(s - 1) as usize].clone(),
                            pid,
                            signer_parties.clone(),
                            &mut rng,
                        ),
                    )
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_without_init(presign_machines, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            // Timed: online sign, consuming the presignatures just produced.
            let sign_machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Ggn16OnlineSignMachine::<C>::new(presig, message).expect("ggn16 sign"),
                    )
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_without_init(sign_machines, 10);

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

// LN18 is benchmarked via protocol_once (not Criterion). LN18 keygen now
// produces Shamir shares via Feldman VSS DKG, and protocol_once sweeps (n, t)
// for DKG + t-subset signing.

fn tx25_benchmarks(c: &mut Criterion) {
    use tecdsa_tx25::{
        keygen::Tx25KeygenMachine, presign::Tx25PresignMachine, sign::Tx25OnlineSignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    let mut group = c.benchmark_group("multiparty/tx25");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_bytes = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    // --- DKG: sweep (n, t). ---
    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
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
            per_party::active_without_init(machines, 10)
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

    // --- Presign / Online sign: sweep t at fixed n. ---
    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: generate key shares once per threshold.
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

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed.
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed online sign).
            let presign_machines: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Tx25PresignMachine::new(
                            pid,
                            signer_parties.clone(),
                            &key_shares[(s - 1) as usize],
                            cl_setup.clone(),
                        )
                        .expect("tx25 presign"),
                    )
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_without_init(presign_machines, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            // Timed: online sign, consuming the presignatures just produced.
            let pk = key_shares[0].public_key;
            let sign_machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Tx25OnlineSignMachine::new(
                            pid,
                            signer_parties.clone(),
                            presig,
                            &msg_bytes,
                            pk,
                        )
                        .expect("tx25 sign"),
                    )
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_without_init(sign_machines, 10);

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

    let mut group = c.benchmark_group("multiparty/jtx25");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_bytes = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    // --- DKG: sweep (n, t). ---
    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
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
            per_party::active_without_init(machines, 10)
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

    // --- Presign / Online sign: sweep t at fixed n. ---
    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: generate key shares once per threshold.
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

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed.
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed online sign).
            let presign_machines: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Jtx25PresignMachine::new(
                            pid,
                            signer_parties.clone(),
                            &key_shares[(s - 1) as usize],
                            cl_setup.clone(),
                        )
                        .expect("jtx25 presign"),
                    )
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_without_init(presign_machines, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            // Timed: online sign, consuming the presignatures just produced.
            let pk = key_shares[0].public_key;
            let sign_machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Jtx25OnlineSignMachine::new(
                            pid,
                            signer_parties.clone(),
                            presig,
                            &msg_bytes,
                            pk,
                        )
                        .expect("jtx25 sign"),
                    )
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_without_init(sign_machines, 10);

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

fn wmy23_benchmarks(c: &mut Criterion) {
    use tecdsa_wmy23::{
        keygen::Wmy23KeygenMachine,
        presign::{PresignConfig, Wmy23PresignMachine},
        sign::Wmy23OnlineSignMachine,
    };

    let dkg_configs = config::dkg_configs();
    let sign_n = config::sign_n();
    let sign_thresholds = config::sign_thresholds();

    let mut group = c.benchmark_group("multiparty/wmy23");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    // WMY23's Feldman-VSS keygen takes the reconstruction threshold (t); the
    // presign machine Lagrange-weights each signer's Shamir share, so any t-of-n
    // subset (here parties 1..=t) reconstructs the key.
    let msg_data = make_data_to_sign(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    // --- DKG: sweep (n, t). ---
    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
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
            per_party::active_without_init(machines, 10)
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

    // --- Presign / Online sign: sweep t at fixed n. ---
    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: generate key shares once per threshold.
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

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed.
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed online sign).
            let presign_machines: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let config = PresignConfig {
                        key_share: key_shares[(s - 1) as usize].clone(),
                        my_id: pid,
                        signer_parties: signer_parties.clone(),
                        cl_setup: cl_setup.clone(),
                    };
                    (
                        pid,
                        Wmy23PresignMachine::new(config).expect("wmy23 presign"),
                    )
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_without_init(presign_machines, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            // Timed: online sign, consuming the presignatures just produced.
            let sign_machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Wmy23OnlineSignMachine::new(
                            pid,
                            signer_parties.clone(),
                            presig,
                            msg_data,
                            public_key,
                        )
                        .expect("wmy23 sign"),
                    )
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_without_init(sign_machines, 10);

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

    let mut group = c.benchmark_group("multiparty/wmc24");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_bytes = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    // --- DKG: sweep (n, t). ---
    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
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
            per_party::active_without_init(machines, 10)
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

    // --- Presign / Online sign: sweep t at fixed n. ---
    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: generate key shares once per threshold.
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

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed. Each run yields both
        // phases' per-party active times.
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed online sign).
            let presign_machines: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Wmc24PresignMachine::new(
                            pid,
                            signer_parties.clone(),
                            &key_shares[(s - 1) as usize],
                            cl_setup.clone(),
                        )
                        .expect("wmc24 presign"),
                    )
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_without_init(presign_machines, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            // Timed: online sign, consuming the presignatures just produced.
            let pk = key_shares[0].public_key;
            let sign_machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Wmc24OnlineSignMachine::new(
                            pid,
                            signer_parties.clone(),
                            presig,
                            &msg_bytes,
                            pk,
                        )
                        .expect("wmc24 sign"),
                    )
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_without_init(sign_machines, 10);

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

    let mut group = c.benchmark_group("multiparty/llz25");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let msg_bytes = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    // CRS key (shared out-of-band, independent of n/t).
    let pk_crs = {
        let mut tmp = cl_setup.clone();
        let (_, pk) = tmp.keygen().expect("crs keygen");
        pk
    };

    // --- DKG: sweep (n, t). ---
    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
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
            per_party::active_without_init(machines, 10)
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

    // --- Presign / Online sign: sweep t at fixed n. ---
    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
        let quorum_indices: Vec<u16> = signers.clone();

        // Untimed setup: generate key shares once per threshold.
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

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed.
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed sign).
            let presign_machines: Vec<_> = signers
                .iter()
                .enumerate()
                .map(|(pos, &s)| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Llz25PresignMachine::new(
                            pid,
                            signer_parties.clone(),
                            key_shares[(s - 1) as usize].clone(),
                            quorum_indices.clone(),
                            pos,
                            cl_setup.clone(),
                            pk_crs.clone(),
                        )
                        .expect("llz25 presign"),
                    )
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_without_init(presign_machines, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            // Timed: sign, consuming the presignatures just produced.
            let sign_machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Llz25SignMachine::new(pid, signer_parties.clone(), presig, &msg_bytes)
                            .expect("llz25 sign"),
                    )
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_without_init(sign_machines, 10);

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

    let mut group = c.benchmark_group("multiparty/trout");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let seed = "42042";
    let message = make_data_to_sign(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    // --- DKG: sweep (n, t). ---
    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
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
            per_party::active_without_init(machines, 10)
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

    // --- Presign / Online sign: sweep t at fixed n. ---
    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
        let signing_1based: Vec<u16> = signers.clone();

        // Untimed setup: generate key shares once per threshold.
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

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed.
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed sign).
            let presign_machines: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let local_setup = cl_setup.clone();
                    let share = key_shares[(s - 1) as usize].clone();
                    // Reconstruct the *joint* CL public key (Y_cl = ∏ Y_k) that
                    // keygen encrypted x_i under; a fresh single-party key never
                    // matches and breaks scaled decryption.
                    let (pa, pb, pc) = &share.cl_pk_abc;
                    let cl_pk_qfi =
                        tecdsa_trout::error::qfi_from_abc(pa, pb, pc).expect("reconstruct CL pk");
                    let cl_pk = local_setup.pk_from_qfi(&cl_pk_qfi).expect("pk_from_qfi");
                    (
                        pid,
                        TroutPresignMachine::new(
                            pid,
                            signer_parties.clone(),
                            share,
                            signing_1based.clone(),
                            b"bench-session",
                            local_setup,
                            cl_pk,
                        )
                        .expect("trout presign"),
                    )
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_without_init(presign_machines, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            // Timed: sign, consuming the presignatures just produced.
            let sign_machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    let local_setup = cl_setup.clone();
                    let share = &key_shares[(s - 1) as usize];
                    // Same joint-CL-key reconstruction as presign (see above).
                    let (pa, pb, pc) = &share.cl_pk_abc;
                    let cl_pk_qfi =
                        tecdsa_trout::error::qfi_from_abc(pa, pb, pc).expect("reconstruct CL pk");
                    let cl_pk = local_setup.pk_from_qfi(&cl_pk_qfi).expect("pk_from_qfi");
                    (
                        pid,
                        TroutSignMachine::new(
                            pid,
                            signer_parties.clone(),
                            presig,
                            &message,
                            share,
                            local_setup,
                            &cl_pk,
                        )
                        .expect("trout sign"),
                    )
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_without_init(sign_machines, 10);

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

    let mut group = c.benchmark_group("multiparty/xal23");
    per_party::configure_replay_group(&mut group, SAMPLES);

    let message = make_data_to_sign(b"benchmark message");

    // --- DKG: sweep (n, t). JL params (1680, 712) are Profile B, not t/n. ---
    for &(n, t) in &dkg_configs {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let dkg_runs = per_party::precompute_runs(SAMPLES, || {
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
            per_party::active_without_init(machines, 10)
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

    // --- Presign / Online sign: sweep t at fixed n. ---
    let n = sign_n;
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for &t in &sign_thresholds {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: generate key shares once per threshold.
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
        // XAL23's presign/sign assume additive signing shares, but Xal23KeygenMachine
        // performs a Feldman DKG and emits Shamir shares. Convert the quorum's shares
        // to additive via Lagrange weighting (w_i = lambda_i * x_i); each party's
        // Shamir point equals its 1-based keygen index = PartyId value.
        let lambdas = tecdsa_vss::lagrange::coefficients::<C>(&signers);
        for (pos, &s) in signers.iter().enumerate() {
            key_shares[(s - 1) as usize].secret_share *= lambdas[pos];
        }

        // --- Presign + Online sign (pipelined) ---
        // Presign is timed once and its presignatures feed the online-sign
        // timing, instead of regenerating them untimed.
        let (presign_runs, online_runs) = per_party::precompute_runs_2(SAMPLES, || {
            // Timed: presign (capture outputs to feed sign).
            let presign_machines: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Xal23PresignMachine::<C>::new(
                            pid,
                            signer_parties.clone(),
                            &key_shares[(s - 1) as usize],
                            &mut rand_core::OsRng,
                        )
                        .expect("xal23 presign"),
                    )
                })
                .collect();
            let (presign_outputs, presign_timings) =
                per_party::run_timed_without_init(presign_machines, 10);
            let presigs: Vec<_> = presign_outputs.into_iter().map(|r| r.unwrap()).collect();

            // Timed: sign, consuming the presignatures just produced.
            let sign_machines: Vec<_> = signers
                    .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (pid, Xal23SignMachine::<C>::new(presig, message))
                })
                .collect();
            let (_, sign_timings) = per_party::run_timed_without_init(sign_machines, 10);

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

// ---------------------------------------------------------------------------
// Criterion groups and main
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    cggmp20_benchmarks,
    dkls23_benchmarks,
    gg18_benchmarks,
    ggn16_benchmarks,
    // LN18's per-session Init + Lagrange setup does not fit the
    // precompute_runs pattern. Use protocol_once for LN18.
    tx25_benchmarks,
    jtx25_benchmarks,
    wmy23_benchmarks,
    wmc24_benchmarks,
    llz25_benchmarks,
    trout_benchmarks,
    xal23_benchmarks
);
criterion_main!(benches);
