// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multi-party protocol benchmark suite for threshold ECDSA protocols.
//!
//! Benchmarks three multi-party protocols:
//! - **CGGMP20**: Paillier-based, 4-round presign + local sign, `SecurityLevel128` (3071-bit modulus)
//! - **DKLs23**: OT/VOLE-based, 3-round presign + 1-round online sign
//! - **GG18**: Classic, 3-round presign + 5-round online sign
//!
//! Each protocol is measured for keygen, presign, and sign phases
//! using `n=3, t=1` (corruption threshold) with per-party timing via the Orchestrator.
//! Each phase benchmarks every participating party separately.

use std::{sync::Arc, time::Duration};

use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::ops::Reduce;
use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_bench::per_party;
use tecdsa_protocol::{PartyId, PartyInfo, SessionConfig, SessionId};
use tecdsa_testkit::Orchestrator;

type C = Secp256k1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build `SessionConfig`s for `n` parties with corruption threshold `corrupted_t`.
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

/// Build `SessionConfig`s for a signing subset.
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

    pub fn run_keygen(n: u16, corrupted_t: u16) -> Vec<Cggmp20CoreKeyShare<C>> {
        let configs = make_session_configs(n, corrupted_t);
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
        let configs = make_session_configs(n, 1);
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
        let corrupted_t = core_shares[0].vss_setup.threshold - 1;
        let signer_configs = make_signer_configs(signers, n, corrupted_t);
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

    pub fn run_keygen(n: u16, corrupted_t: u16) -> Vec<Dkls23KeyShare<C>> {
        let mut rng = rand::thread_rng();
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let machines: Vec<(PartyId, Dkls23KeygenMachine<C>)> = all_parties
            .iter()
            .map(|&pid| {
                let machine =
                    Dkls23KeygenMachine::new(pid, all_parties.clone(), corrupted_t + 1, &mut rng);
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

    pub fn run_keygen(n: u16, corrupted_t: u16) -> Vec<Gg18KeyShare<C>> {
        let configs = make_session_configs(n, corrupted_t);
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
// Benchmark groups
// ===========================================================================

fn cggmp20_benchmarks(c: &mut Criterion) {
    use tecdsa_cggmp20::{
        aux_info::AuxInfoMachine, keygen::Cggmp20KeygenMachine, presign::Cggmp20PresignMachine,
        security_level::SecurityLevel128, sign::types::PartialSignature,
    };

    let mut group = c.benchmark_group("cggmp20");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(120));

    // --- DKG: per-party active time for each party ---
    for party_idx in 1..=3u16 {
        let pid = PartyId(party_idx);
        group.bench_function(format!("dkg/cggmp20/n3_t1/party{party_idx}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let configs = make_session_configs(3, 1);
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
                    let (_, timings) = per_party::run_timed_with_init(builders, 10);
                    total += per_party::party_active_time(&timings, pid);
                }
                total
            });
        });
    }

    // --- AuxInfo: per-party active time for each party ---
    for party_idx in 1..=3u16 {
        let pid = PartyId(party_idx);
        group.bench_function(format!("aux_info/cggmp20/n3/party{party_idx}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let configs = make_session_configs(3, 1);
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
                    let (_, timings) = per_party::run_timed_with_init(builders, 10);
                    total += per_party::party_active_time(&timings, pid);
                }
                total
            });
        });
    }

    // --- Presign: per-party active time for each signer ---
    // Untimed setup: generate key shares and aux info once
    let core_shares = cggmp20_helpers::run_keygen(3, 1);
    let aux_infos: Vec<Arc<_>> = cggmp20_helpers::run_aux_info(3)
        .into_iter()
        .map(Arc::new)
        .collect();
    let signers = [1u16, 2];

    for &signer in &signers {
        let pid = PartyId(signer);
        group.bench_function(
            format!("presign/cggmp20/n3_t1/signers_1_2/party{signer}"),
            |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let n = core_shares.len() as u16;
                        let corrupted_t = core_shares[0].vss_setup.threshold - 1;
                        let signer_configs = make_signer_configs(&signers, n, corrupted_t);
                        let builders: Vec<_> = signers
                            .iter()
                            .enumerate()
                            .map(|(idx, &signer_1based)| {
                                let pid = PartyId(signer_1based);
                                let cfg = signer_configs[idx].clone();
                                let core_share = core_shares[(signer_1based - 1) as usize].clone();
                                let aux = Arc::clone(&aux_infos[(signer_1based - 1) as usize]);
                                let signers_clone = signers.to_vec();
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
                        let (_, timings) = per_party::run_timed_with_init(builders, 10);
                        total += per_party::party_active_time(&timings, pid);
                    }
                    total
                });
            },
        );
    }

    // --- Online Sign: per-party partial_sign + combine (not a StateMachine) ---
    let presigs = cggmp20_helpers::run_presign(&core_shares, &aux_infos, &signers);
    let message = make_data_to_sign(b"benchmark message");
    let public_key = &core_shares[0].public_key;

    for (idx, &signer) in signers.iter().enumerate() {
        group.bench_function(
            format!("online_sign/cggmp20/n3_t1/signers_1_2/party{signer}/partial_sign"),
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
    group.bench_function("online_sign/cggmp20/n3_t1/combine", |b| {
        b.iter(|| PartialSignature::combine(&partials, pub_data, public_key, &message));
    });

    group.finish();
}

fn dkls23_benchmarks(c: &mut Criterion) {
    use tecdsa_dkls23::{
        keygen::Dkls23KeygenMachine,
        presign::{Dkls23PresignMachine, PresignConfig},
        sign::{Dkls23OnlineSignMachine, OnlineSignConfig},
    };

    let mut group = c.benchmark_group("dkls23");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    let n = 3u16;
    let corrupted_t = 1u16;
    let signer_indices = [1u16, 2];
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    let signer_parties: Vec<PartyId> = signer_indices.iter().map(|&i| PartyId(i)).collect();
    let message = make_data_to_sign(b"benchmark message");

    // --- DKG: per-party active time for each party ---
    for party_idx in 1..=n {
        let pid = PartyId(party_idx);
        group.bench_function(format!("dkg/dkls23/n3_t1/party{party_idx}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let all_p = all_parties.clone();
                    let builders: Vec<_> = all_p
                        .iter()
                        .map(|&p| {
                            let all_p2 = all_p.clone();
                            (p, move || {
                                let mut rng = rand::thread_rng();
                                Dkls23KeygenMachine::<C>::new(p, all_p2, corrupted_t + 1, &mut rng)
                            })
                        })
                        .collect();
                    let (_, timings) = per_party::run_timed_with_init(builders, 10);
                    total += per_party::party_active_time(&timings, pid);
                }
                total
            });
        });
    }

    // --- Presign: per-party active time for each signer ---
    // Untimed setup: generate key shares once
    let shares = dkls23_helpers::run_keygen(n, corrupted_t);

    for &signer in &signer_indices {
        let pid = PartyId(signer);
        group.bench_function(
            format!("presign/dkls23/n3_t1/signers_1_2/party{signer}"),
            |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let builders: Vec<_> = signer_indices
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
                        let (_, timings) = per_party::run_timed_with_init(builders, 20);
                        total += per_party::party_active_time(&timings, pid);
                    }
                    total
                });
            },
        );
    }

    // --- Online Sign: per-party active time for each signer ---
    // Presignature is one-time use, so generate fresh per iteration (untimed).
    for &signer in &signer_indices {
        let pid = PartyId(signer);
        group.bench_function(
            format!("online_sign/dkls23/n3_t1/signers_1_2/party{signer}"),
            |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // Untimed: generate fresh presignature
                        let presigs = dkls23_helpers::run_presign(&shares, &signer_indices);
                        // Timed: construct + run online sign machines
                        let builders: Vec<_> = presigs
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
                        let (_, timings) = per_party::run_timed_with_init(builders, 10);
                        total += per_party::party_active_time(&timings, pid);
                    }
                    total
                });
            },
        );
    }

    // --- Full Sign: presign + online sign, per-party active time for each signer ---
    for &signer in &signer_indices {
        let pid = PartyId(signer);
        group.bench_function(
            format!("full_sign/dkls23/n3_t1/signers_1_2/party{signer}"),
            |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
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
                        total += per_party::party_active_time(&presign_timings, pid);

                        // Timed: online sign
                        let presigs: Vec<_> =
                            presign_outputs.into_iter().map(|r| r.unwrap()).collect();
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
                        total += per_party::party_active_time(&sign_timings, pid);
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

fn gg18_benchmarks(c: &mut Criterion) {
    use tecdsa_gg18::{
        keygen::Gg18KeygenMachine,
        presign::{Gg18PresignMachine, PresignConfig},
        sign::{Gg18OnlineSignMachine, OnlineSignConfig},
    };

    let mut group = c.benchmark_group("gg18");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    let n = 3u16;
    let corrupted_t = 1u16;
    let signers = [1u16, 2];
    let message = make_data_to_sign(b"benchmark message");

    // --- DKG: per-party active time for each party ---
    for party_idx in 1..=n {
        let pid = PartyId(party_idx);
        group.bench_function(format!("dkg/gg18/n3_t1/party{party_idx}"), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let configs = make_session_configs(n, corrupted_t);
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
                    let (_, timings) = per_party::run_timed_with_init(builders, 10);
                    total += per_party::party_active_time(&timings, pid);
                }
                total
            });
        });
    }

    // --- Presign: per-party active time for each signer ---
    // Untimed setup: generate key shares once
    let key_shares = gg18_helpers::run_keygen(n, corrupted_t);

    for &signer in &signers {
        let pid = PartyId(signer);
        group.bench_function(
            format!("presign/gg18/n3_t1/signers_1_2/party{signer}"),
            |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let builders: Vec<_> = signers
                            .iter()
                            .map(|&signer_1based| {
                                let party_0based = (signer_1based - 1) as usize;
                                let pid = PartyId(signer_1based);
                                let key_share = key_shares[party_0based].clone();
                                let signers_clone = signers.to_vec();
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
                        let (_, timings) = per_party::run_timed_with_init(builders, 10);
                        total += per_party::party_active_time(&timings, pid);
                    }
                    total
                });
            },
        );
    }

    // --- Online Sign: per-party active time for each signer ---
    // Presignature is one-time use, so generate fresh per iteration (untimed).
    for &signer in &signers {
        let pid = PartyId(signer);
        group.bench_function(
            format!("online_sign/gg18/n3_t1/signers_1_2/party{signer}"),
            |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // Untimed: generate fresh presignature
                        let presigs = gg18_helpers::run_presign(&key_shares, &signers);
                        // Timed: construct + run online sign machines
                        let builders: Vec<_> = presigs
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
                        let (_, timings) = per_party::run_timed_with_init(builders, 10);
                        total += per_party::party_active_time(&timings, pid);
                    }
                    total
                });
            },
        );
    }

    // --- Full Sign: presign + online sign, per-party active time for each signer ---
    for &signer in &signers {
        let pid = PartyId(signer);
        group.bench_function(
            format!("full_sign/gg18/n3_t1/signers_1_2/party{signer}"),
            |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // Timed: presign
                        let presign_builders: Vec<_> = signers
                            .iter()
                            .map(|&signer_1based| {
                                let party_0based = (signer_1based - 1) as usize;
                                let pid = PartyId(signer_1based);
                                let key_share = key_shares[party_0based].clone();
                                let signers_clone = signers.to_vec();
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
                        total += per_party::party_active_time(&presign_timings, pid);

                        // Timed: online sign
                        let presigs: Vec<_> =
                            presign_outputs.into_iter().map(|r| r.unwrap()).collect();
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
                        total += per_party::party_active_time(&sign_timings, pid);
                    }
                    total
                });
            },
        );
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
    gg18_benchmarks
);
criterion_main!(benches);
