// SPDX-License-Identifier: MIT OR Apache-2.0
//! One-shot protocol timing.
//!
//! Runs each protocol phase (keygen, presign, sign) once per swept `(n, t)`
//! configuration and prints TSV rows from the Orchestrator timing
//! infrastructure: a `/wall` row for the whole orchestrated run plus the active
//! time of the first participating party (party 1). The protocol always runs
//! with all `n` parties, but per-party times are near-symmetric so only one is
//! reported.
//!
//! Covers: MtA primitives, multi-party (CGGMP20, DKLs23, GG18),
//! and two-party (Lin17, KGG24, XAL21, ABC24) protocols.
//!
//! The swept `(n, t)` configurations are read from the environment (see
//! [`tecdsa_bench::config`]): DKG uses `TECDSA_BENCH_DKG_CONFIGS`
//! (default `3:3,7:7,11:11,15:15,20:20`); presign/sign use `TECDSA_BENCH_SIGN_N`
//! (default `20`) parties with thresholds `TECDSA_BENCH_SIGN_THRESHOLDS`
//! (default `2,3,7,11,15,20`), signing quorum parties `1..=t`.
//!
//! LN18 and GGN16 have external setup (Shamir re-sharing / threshold Paillier)
//! timed separately.
//!
//! Format: name<TAB>elapsed_ns<TAB>elapsed_human

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use elliptic_curve::{ops::Reduce, PrimeField};
use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_bench::{config, per_party};
use tecdsa_ln18::sign::Ln18MtaBackend;
use tecdsa_protocol::{DataToSign, PartyId, PartyInfo, SessionConfig, SessionId};

type C = Secp256k1;

fn time_once<T>(name: &str, f: impl FnOnce() -> T) -> T {
    // For presign/offline-sign phases, attribute the per-party OFFLINE
    // communication: the timed-run helpers serialize messages and record the
    // representative party's bytes_sent under "<proto>/<config>/presign" while
    // this key is set. Parsed from names like "<proto>/presign/n{n}_t{t}/wall"
    // or "<proto>/offline_sign/n{n}_t{t}/wall". (Online comm is recorded
    // explicitly via per_party::record_online_comm.)
    let parts: Vec<&str> = name.split('/').collect();
    let comm_key = if parts.len() >= 3 && (parts[1] == "presign" || parts[1] == "offline_sign") {
        Some(format!("{}/{}/presign", parts[0], parts[2]))
    } else {
        None
    };
    per_party::set_comm_key(comm_key);
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed();
    per_party::set_comm_key(None);
    println!("{name}\t{}\t{}", elapsed.as_nanos(), HumanDuration(elapsed));
    out
}

struct HumanDuration(Duration);

impl std::fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ns = self.0.as_nanos();
        if ns < 1_000 {
            write!(f, "{ns} ns")
        } else if ns < 1_000_000 {
            write!(f, "{:.3} us", ns as f64 / 1_000.0)
        } else if ns < 1_000_000_000 {
            write!(f, "{:.3} ms", ns as f64 / 1_000_000.0)
        } else {
            write!(f, "{:.3} s", ns as f64 / 1_000_000_000.0)
        }
    }
}

fn print_timing(prefix: &str, pid: PartyId, dur: Duration) {
    println!(
        "{prefix}/party{}\t{}\t{}",
        pid.0,
        dur.as_nanos(),
        HumanDuration(dur)
    );
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

fn make_data_to_sign(msg: &[u8]) -> DataToSign<C> {
    let hash_bytes: [u8; 32] = Sha256::digest(msg).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    DataToSign::from_digest(scalar)
}

/// Wire size (bytes) of a curve point in its compressed SEC1 encoding (33 B on
/// secp256k1). Two-party round messages store bare `ProjectivePoint`s (not
/// `Serialize`), so their communication is sized as compressed points plus
/// `wire_size` of the serializable fields (DlogProof, ciphertexts, scalars).
fn point_wire_len(p: &k256::ProjectivePoint) -> usize {
    use elliptic_curve::group::GroupEncoding;
    AsRef::<[u8]>::as_ref(&p.to_bytes()).len()
}

type GroupFn = fn();

/// All protocol groups. Each is independent (its own keygen/presign/sign).
fn all_groups() -> Vec<(&'static str, GroupFn)> {
    vec![
        ("mta", mta_once),
        ("cggmp20", cggmp20_once),
        ("dkls23", dkls23_once),
        ("gg18", gg18_once),
        ("ggn16", ggn16_once),
        ("ln18", ln18_once),
        ("tx25", tx25_once),
        ("jtx25", jtx25_once),
        ("jtx25_robust", jtx25_robust_once),
        ("wmy23", wmy23_once),
        ("wmc24", wmc24_once),
        ("llz25", llz25_once),
        ("trout", trout_once),
        ("xal23", xal23_once),
        ("lin17", lin17_once),
        ("kgg24", kgg24_once),
        ("xal21", xal21_once),
        ("abc24", abc24_once),
    ]
}

fn main() {
    println!("name\telapsed_ns\telapsed");

    // Optional subset filter (comma-separated names), e.g.
    // TECDSA_BENCH_PROTOCOLS=cggmp20,gg18 — avoids hand-editing this list.
    let filter = std::env::var("TECDSA_BENCH_PROTOCOLS").ok();
    let groups: Vec<(&'static str, GroupFn)> = all_groups()
        .into_iter()
        .filter(|(name, _)| {
            filter
                .as_ref()
                .map_or(true, |f| f.split(',').map(str::trim).any(|p| p == *name))
        })
        .collect();

    // Run groups concurrently via a small worker pool. The comm collector is a
    // global Mutex and the per-phase comm key is thread-local, so parallel groups
    // don't interfere. Concurrency defaults to the CPU count; override with
    // TECDSA_BENCH_JOBS (1 = sequential).
    let jobs = std::env::var("TECDSA_BENCH_JOBS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()))
        .min(groups.len().max(1));

    let queue = std::sync::Arc::new(std::sync::Mutex::new(groups));
    let workers: Vec<_> = (0..jobs)
        .map(|_| {
            let queue = std::sync::Arc::clone(&queue);
            std::thread::spawn(move || loop {
                // Pop without holding the lock during the (heavy) group run, so a
                // panicking group can't poison the queue for the other workers.
                let next = queue.lock().expect("queue lock").pop();
                match next {
                    Some((name, f)) => run_group(name, f),
                    None => break,
                }
            })
        })
        .collect();
    for w in workers {
        if w.join().is_err() {
            eprintln!("# a protocol group thread panicked");
        }
    }

    // Write a PER-PROCESS file into target/comm_online/ so concurrent runs (or
    // re-runs of subsets) never clobber each other; the table generators merge
    // every target/comm_online/*.tsv (newest file wins per key).
    let dir = std::path::Path::new("target/comm_online");
    std::fs::create_dir_all(dir).expect("create comm dir");
    let out = dir.join(format!("{}.tsv", std::process::id()));
    per_party::write_online_comm(out.to_str().expect("utf-8 path"));
}

fn run_group(name: &str, f: impl FnOnce()) {
    eprintln!("# {name}");
    f();
}

// ═══════════════════════════════════════════════════════════════════════
// MtA primitives (all 6 variants)
// ═══════════════════════════════════════════════════════════════════════

fn mta_once() {
    use rand_core::OsRng;
    use tecdsa_curve::TecdsaCurve;
    use tecdsa_protocol::MtA;

    let a = Secp256k1::random_scalar(&mut OsRng);
    let b = Secp256k1::random_scalar(&mut OsRng);
    let a_bytes = a.to_repr();
    let b_bytes = b.to_repr();
    let neg_one = -k256::Scalar::ONE;
    let neg_one_bytes = neg_one.to_repr();
    let q_int = tecdsa_paillier::backend::Integer::from_bytes_msf(neg_one_bytes.as_ref()) + 1u8;
    let q_bytes = q_int.to_bytes_msf();

    // ── Setup (timed separately) ──
    let paillier_dk = time_once("mta/setup/paillier_keygen", || {
        tecdsa_paillier::keygen(&mut OsRng).expect("keygen")
    });
    let paillier_ek = paillier_dk.encryption_key().clone();

    let cl_setup_seed = "42042";
    let (_cl_sk, _cl_pk, _cl_setup) = time_once("mta/setup/cl_keygen", || {
        let mut s =
            tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(cl_setup_seed).expect("cl setup");
        let (sk, pk) = s.keygen().expect("cl keygen");
        (sk, pk, s)
    });

    let ntilde = time_once("mta/setup/ntilde_params", || {
        tecdsa_bench::zk_fixtures::NTildeFixture::generate()
    });

    let (jl_pk, jl_sk, jl_pk0) = time_once("mta/setup/jl_keygen", || {
        let (pk, sk, _x) =
            tecdsa_joye_libert::kgen::generate_keypair_with_qnr(1680, 712, &mut OsRng);
        let (pk0, _, _) =
            tecdsa_joye_libert::kgen::generate_keypair_with_qnr(1680, 712, &mut OsRng);
        (pk, sk, pk0)
    });

    // ── 1. Paillier MtA (Alice/Bob range proofs with Ring-Pedersen) ──
    {
        use tecdsa_paillier::mta::{Gg18ProofSetup, Gg18Proofs, PaillierMtA, PaillierMtaSetup};
        type M = PaillierMtA<Gg18Proofs>;
        let setup = PaillierMtaSetup {
            ek: paillier_ek.clone(),
            dk: paillier_dk.clone(),
            proof_setup: Gg18ProofSetup {
                ntilde: ntilde.to_mta_params(),
            },
        };
        let (sm, ss) = time_once("mta/paillier/sender_encrypt", || {
            M::sender_encrypt(&setup, b_bytes.as_ref(), &q_bytes, &mut OsRng).expect("se")
        });
        let (rm, _) = time_once("mta/paillier/receiver_compute", || {
            M::receiver_compute(&setup, a_bytes.as_ref(), &q_bytes, &sm, &mut OsRng).expect("rc")
        });
        time_once("mta/paillier/sender_decrypt", || {
            M::sender_decrypt(&setup, &ss, &q_bytes, &rm).expect("sd")
        });
    }

    // ── 3. CL MtA ──
    {
        use std::cell::RefCell;

        use tecdsa_class_group::mta::{ClMtA, ClMtaSetup};
        type M = ClMtA;
        let setup = ClMtaSetup {
            setup: RefCell::new(
                tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(cl_setup_seed)
                    .expect("cl setup"),
            ),
            pk: {
                let mut tmp = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(cl_setup_seed)
                    .expect("cl");
                let (_, pk) = tmp.keygen().expect("keygen");
                pk
            },
            sk: {
                let mut tmp = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(cl_setup_seed)
                    .expect("cl");
                let (sk, _) = tmp.keygen().expect("keygen");
                sk
            },
        };
        let (sm, ss) = time_once("mta/cl/sender_encrypt", || {
            M::sender_encrypt(&setup, b_bytes.as_ref(), &q_bytes, &mut OsRng).expect("se")
        });
        let (rm, _) = time_once("mta/cl/receiver_compute", || {
            M::receiver_compute(&setup, a_bytes.as_ref(), &q_bytes, &sm, &mut OsRng).expect("rc")
        });
        time_once("mta/cl/sender_decrypt", || {
            M::sender_decrypt(&setup, &ss, &q_bytes, &rm).expect("sd")
        });
    }

    // ── 4. JL MtA ──
    {
        use tecdsa_joye_libert::mta::{JlMtA, JlMtaSetup};
        type M = JlMtA;
        let setup = JlMtaSetup {
            pk: jl_pk,
            pk0: jl_pk0,
            sk: jl_sk,
            s: 40,
            t: 40,
        };
        let (sm, ss) = time_once("mta/jl/sender_encrypt", || {
            M::sender_encrypt(&setup, b_bytes.as_ref(), &q_bytes, &mut OsRng).expect("se")
        });
        let (rm, _) = time_once("mta/jl/receiver_compute", || {
            M::receiver_compute(&setup, a_bytes.as_ref(), &q_bytes, &sm, &mut OsRng).expect("rc")
        });
        time_once("mta/jl/sender_decrypt", || {
            M::sender_decrypt(&setup, &ss, &q_bytes, &rm).expect("sd")
        });
    }

    // ── 5. RVOLE MtA (interactive, 4 steps) ──
    {
        use tecdsa_ot::mta::{RvoleMtA, RvoleSetup};
        use tecdsa_protocol::MtAInteractive;
        type M = RvoleMtA;
        let setup = RvoleSetup {
            session_id: b"bench-rvole".to_vec(),
        };
        let (init_msg, sender_state) = time_once("mta/rvole/sender_init", || {
            M::sender_init(&setup, &mut OsRng).expect("init")
        });
        let (resp_msg, recv_state) = time_once("mta/rvole/receiver_respond", || {
            M::receiver_respond(&setup, b_bytes.as_ref(), &q_bytes, &init_msg, &mut OsRng)
                .expect("respond")
        });
        let (compute_msg, _alpha) = time_once("mta/rvole/sender_compute", || {
            M::sender_compute(sender_state, a_bytes.as_ref(), &q_bytes, &resp_msg).expect("compute")
        });
        time_once("mta/rvole/receiver_finish", || {
            M::receiver_finish(recv_state, &compute_msg, &q_bytes).expect("finish")
        });
    }

    // ── 6. NIM (non-interactive multiplication) ──
    {
        use tecdsa_class_group::nim::Nim;
        let mut nim_setup =
            tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(cl_setup_seed).expect("cl");
        let (_, nim_pk) = nim_setup.keygen().expect("nim keygen");
        let x_bytes = tecdsa_curve::conv::scalar_to_bytes::<Secp256k1>(&a);
        let y_bytes = tecdsa_curve::conv::scalar_to_bytes::<Secp256k1>(&b);
        let encode_a_out = time_once("mta/nim/encode_a", || {
            let mut nim = Nim::new(&mut nim_setup);
            nim.encode_a(&x_bytes, &nim_pk).expect("encode_a")
        });
        let encode_b_out = time_once("mta/nim/encode_b", || {
            let mut nim = Nim::new(&mut nim_setup);
            nim.encode_b(&y_bytes, &nim_pk).expect("encode_b")
        });
        time_once("mta/nim/decode_a", || {
            let nim = Nim::new(&mut nim_setup);
            nim.decode_a(&encode_b_out.pe_b, &encode_a_out.state)
                .expect("decode_a")
        });
        time_once("mta/nim/decode_b", || {
            let nim = Nim::new(&mut nim_setup);
            nim.decode_b(&encode_a_out.pe_a, &encode_b_out.state)
                .expect("decode_b")
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CGGMP20
// ═══════════════════════════════════════════════════════════════════════

fn cggmp20_once() {
    use tecdsa_cggmp20::{
        aux_info::AuxInfoMachine, keygen::Cggmp20KeygenMachine, presign::Cggmp20PresignMachine,
        security_level::SecurityLevel128, sign::types::PartialSignature,
    };

    let message = make_data_to_sign(b"benchmark message");

    // DKG: sweep (n, t).
    for (n, t) in config::dkg_configs() {
        let keygen_out = time_once(&format!("cggmp20/dkg/n{n}_t{t}/wall"), || {
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
            per_party::run_timed_with_init(builders, 10)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(
                &format!("cggmp20/dkg/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }

    // AuxInfo: depends only on n; sweep the distinct DKG party counts.
    let mut aux_ns: Vec<u16> = config::dkg_configs().into_iter().map(|(n, _)| n).collect();
    aux_ns.sort_unstable();
    aux_ns.dedup();
    for n in aux_ns {
        let aux_out = time_once(&format!("cggmp20/aux_info/n{n}/wall"), || {
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
            per_party::run_timed_with_init(builders, 10)
        });
        for (&pid, timing) in aux_out.1.iter().take(1) {
            print_timing(
                &format!("cggmp20/aux_info/n{n}"),
                pid,
                timing.total_active(),
            );
        }
    }

    // Presign / Online sign: sweep t at fixed n.
    let n = config::sign_n();
    for t in config::sign_thresholds() {
        let signers = config::first_signers(t);

        // Untimed setup: key shares + aux info at (n, t) (DKG/aux timed above).
        let core_shares: Vec<_> = {
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
            per_party::run_timed_with_init(builders, 10)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };
        let aux_infos: Vec<Arc<_>> = {
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
            per_party::run_timed_with_init(builders, 10)
                .0
                .into_iter()
                .map(|r| Arc::new(r.unwrap()))
                .collect()
        };

        // Presign
        let presign_out = time_once(&format!("cggmp20/presign/n{n}_t{t}/wall"), || {
            let kg_t = core_shares[0].vss_setup.threshold;
            let signer_configs = make_signer_configs(&signers, n, kg_t);
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
            per_party::run_timed_with_init(builders, 10)
        });
        let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in presign_out.1.iter().take(1) {
            print_timing(
                &format!("cggmp20/presign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Online sign
        let public_key = &core_shares[0].public_key;
        for (idx, &signer) in signers.iter().enumerate().take(1) {
            let name = format!("cggmp20/online_sign/n{n}_t{t}/party{signer}/partial_sign");
            time_once(&name, || presigs[idx].0.partial_sign(&message));
        }
        let partials: Vec<_> = presigs
            .iter()
            .map(|(p, _)| p.partial_sign(&message))
            .collect();
        let pub_data = &presigs[0].1;
        time_once(&format!("cggmp20/online_sign/n{n}_t{t}/combine"), || {
            PartialSignature::combine(&partials, pub_data, public_key, &message).expect("combine")
        });

        // CGGMP20 online is local (partial_sign + combine): each signer broadcasts
        // one sigma scalar (32 B on secp256k1) to the other t-1 signers. No
        // orchestrator messages, so account for it directly, matching the
        // broadcast convention used elsewhere (payload x #recipients).
        per_party::record_online_comm(
            format!("cggmp20/n{n}_t{t}"),
            32 * (t as usize).saturating_sub(1),
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// DKLs23
// ═══════════════════════════════════════════════════════════════════════

fn dkls23_once() {
    use tecdsa_dkls23::{
        keygen::Dkls23KeygenMachine,
        presign::{Dkls23PresignMachine, PresignConfig},
        sign::{Dkls23OnlineSignMachine, OnlineSignConfig},
    };

    let message = make_data_to_sign(b"benchmark message");

    // DKG: sweep (n, t).
    for (n, t) in config::dkg_configs() {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let keygen_out = time_once(&format!("dkls23/dkg/n{n}_t{t}/wall"), || {
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
            per_party::run_timed_with_init(builders, 10)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(&format!("dkls23/dkg/n{n}_t{t}"), pid, timing.total_active());
        }
    }

    // Presign / Online sign: sweep t at fixed n.
    let n = config::sign_n();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for t in config::sign_thresholds() {
        let signer_indices = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signer_indices.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: key shares at (n, t).
        let shares: Vec<_> = {
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
            per_party::run_timed_with_init(builders, 10)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };

        // Presign
        let presign_out = time_once(&format!("dkls23/presign/n{n}_t{t}/wall"), || {
            let builders: Vec<_> = signer_indices
                .iter()
                .map(|&idx| {
                    let share = shares[(idx - 1) as usize].clone();
                    let pid = PartyId(idx);
                    let sp = signer_parties.clone();
                    (pid, move || {
                        let config = PresignConfig {
                            key_share: share,
                            my_id: pid,
                            signer_parties: sp,
                        };
                        Dkls23PresignMachine::new(config, rand_core::OsRng)
                    })
                })
                .collect();
            per_party::run_timed_with_init(builders, 20)
        });
        let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in presign_out.1.iter().take(1) {
            print_timing(
                &format!("dkls23/presign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Online sign
        let sign_out = time_once(&format!("dkls23/online_sign/n{n}_t{t}/wall"), || {
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
            per_party::run_online_comm_with_init(format!("dkls23/n{n}_t{t}"), builders, 10)
        });
        for (&pid, timing) in sign_out.1.iter().take(1) {
            print_timing(
                &format!("dkls23/online_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// GG18
// ═══════════════════════════════════════════════════════════════════════

fn gg18_once() {
    use tecdsa_gg18::{
        keygen::Gg18KeygenMachine,
        presign::{Gg18PresignMachine, PresignConfig},
        sign::{Gg18OnlineSignMachine, OnlineSignConfig},
    };

    let message = make_data_to_sign(b"benchmark message");

    // DKG: sweep (n, t).
    for (n, t) in config::dkg_configs() {
        let keygen_out = time_once(&format!("gg18/dkg/n{n}_t{t}/wall"), || {
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
            per_party::run_timed_with_init(builders, 10)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(&format!("gg18/dkg/n{n}_t{t}"), pid, timing.total_active());
        }
    }

    // Presign / Online sign: sweep t at fixed n.
    let n = config::sign_n();
    for t in config::sign_thresholds() {
        let signers = config::first_signers(t);

        // Untimed setup: key shares at (n, t).
        let key_shares: Vec<_> = {
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
            per_party::run_timed_with_init(builders, 10)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };

        // Presign
        let presign_out = time_once(&format!("gg18/presign/n{n}_t{t}/wall"), || {
            let builders: Vec<_> = signers
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
            per_party::run_timed_with_init(builders, 10)
        });
        let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in presign_out.1.iter().take(1) {
            print_timing(
                &format!("gg18/presign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Online sign
        let sign_out = time_once(&format!("gg18/online_sign/n{n}_t{t}/wall"), || {
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
            per_party::run_online_comm_with_init(format!("gg18/n{n}_t{t}"), builders, 10)
        });
        for (&pid, timing) in sign_out.1.iter().take(1) {
            print_timing(
                &format!("gg18/online_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// GGN16
// ═══════════════════════════════════════════════════════════════════════

/// Trusted-dealer setup for GGN16: threshold Paillier (corruption threshold
/// `corruption_t`) + Ring-Pedersen parameters. Generates 1536-bit safe primes
/// (slow). Mirrors the Criterion bench's `fast_trusted_dealer_setup`.
fn ggn16_dealer_setup(
    n: u16,
    corruption_t: u16,
) -> (
    tecdsa_paillier::threshold::ThresholdSetup,
    Vec<tecdsa_paillier::threshold::DecryptionShare>,
    tecdsa_paillier::backend::Integer,
    tecdsa_paillier::backend::Integer,
    tecdsa_paillier::backend::Integer,
) {
    use tecdsa_paillier::{
        backend::Integer,
        threshold::{DecryptionShare, ThresholdSetup},
    };

    let mut rng = rand_core::OsRng;
    let p = Integer::generate_safe_prime(&mut rng, 1536);
    let q = Integer::generate_safe_prime(&mut rng, 1536);
    let dk =
        tecdsa_paillier::DecryptionKey::from_primes(p.clone(), q.clone()).expect("valid primes");
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

fn ggn16_once() {
    use tecdsa_ggn16::{
        keygen::Ggn16KeygenMachine, presign::Ggn16PresignMachine, sign::Ggn16OnlineSignMachine,
    };

    let message = make_data_to_sign(b"benchmark message");

    // DKG: sweep (n, t). Dealer setup (safe primes, corruption threshold t-1) is
    // timed per config, then the keygen protocol itself.
    for (n, t) in config::dkg_configs() {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let (threshold_setup, dec_shares, n_tilde, h1, h2) =
            time_once(&format!("ggn16/setup/n{n}_t{t}/wall"), || {
                ggn16_dealer_setup(n, t - 1)
            });
        let keygen_out = time_once(&format!("ggn16/dkg/n{n}_t{t}/wall"), || {
            let mut rng = tecdsa_core::Csprng::new();
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
            per_party::run_timed_without_init(machines, 10)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(&format!("ggn16/dkg/n{n}_t{t}"), pid, timing.total_active());
        }
    }

    // Presign / Online sign: sweep t at fixed n.
    let n = config::sign_n();
    for t in config::sign_thresholds() {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        // Untimed setup: dealer setup + key shares at (n, t).
        let (threshold_setup, dec_shares, n_tilde, h1, h2) = ggn16_dealer_setup(n, t - 1);
        let key_shares: Vec<_> = {
            let mut rng = tecdsa_core::Csprng::new();
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
            per_party::run_timed_without_init(machines, 10)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };

        // Presign
        let presign_out = time_once(&format!("ggn16/presign/n{n}_t{t}/wall"), || {
            let mut rng = tecdsa_core::Csprng::new();
            let machines: Vec<_> = signers
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
            per_party::run_timed_without_init(machines, 10)
        });
        let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in presign_out.1.iter().take(1) {
            print_timing(
                &format!("ggn16/presign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Online sign
        let sign_out = time_once(&format!("ggn16/online_sign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
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
            per_party::run_online_comm(format!("ggn16/n{n}_t{t}"), machines, 10)
        });
        for (&pid, timing) in sign_out.1.iter().take(1) {
            print_timing(
                &format!("ggn16/online_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// LN18 (2-round offline + 6-round online via StateMachine)
// ═══════════════════════════════════════════════════════════════════════

fn ln18_once() {
    ln18_once_with_backend("ln18-paillier", Ln18MtaBackend::Paillier);
    ln18_once_with_backend("ln18-ot", Ln18MtaBackend::Ot);
}

fn ln18_once_with_backend(name: &str, backend: Ln18MtaBackend) {
    use tecdsa_ln18::{
        key_share::Ln18KeyShare,
        keygen::Ln18KeygenMachine,
        sign::{
            Ln18MtaHybrid, Ln18OfflineSignMachine, Ln18OfflineSignParams, Ln18OnlineSignMachine,
            Ln18OnlineSignParams,
        },
    };

    let message = make_data_to_sign(b"benchmark message");

    // DKG: sweep (n, t).
    for (n, t) in config::dkg_configs() {
        let keygen_out = time_once(&format!("{name}/dkg/n{n}_t{t}/wall"), || {
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
            per_party::run_timed_with_init(builders, 10)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(&format!("{name}/dkg/n{n}_t{t}"), pid, timing.total_active());
        }
    }

    // Presign / Online sign: sweep t at fixed n.
    let n = config::sign_n();
    for t in config::sign_thresholds() {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: key shares at (n, t).
        let key_shares: Vec<Ln18KeyShare<C>> = {
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
            per_party::run_timed_with_init(builders, 10)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };
        let public_key = key_shares[0].public_key;

        // Per-session signing setup (untimed): Lagrange + Init + Input(w_i) + Paillier
        let mut rng = rand_core::OsRng;
        let sign_params =
            tecdsa_ln18::sign::build_signing_setup::<C>(&key_shares, &signer_parties, &mut rng)
                .expect("LN18 signing setup");

        // Offline sign (2 rounds, message-independent)
        let mta = Arc::new(Ln18MtaHybrid::<C>::new(signer_parties.clone(), backend));

        let offline_out = time_once(&format!("{name}/offline_sign/n{n}_t{t}/wall"), || {
            let mut rng = tecdsa_core::Csprng::new();
            let machines: Vec<_> = sign_params
                .into_iter()
                .zip(signer_parties.iter())
                .map(|(base, &pid)| {
                    let params = Ln18OfflineSignParams {
                        base,
                        signer_parties: signer_parties.clone(),
                        mta: Arc::clone(&mta),
                    };
                    (
                        pid,
                        Ln18OfflineSignMachine::<C>::new(
                            pid,
                            signer_parties.clone(),
                            params,
                            &mut rng,
                        ),
                    )
                })
                .collect();
            per_party::run_timed_without_init(machines, 4)
        });
        let offline_states: Vec<_> = offline_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in offline_out.1.iter().take(1) {
            print_timing(
                &format!("{name}/offline_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Online sign (6 rounds, message-dependent)
        let m_scalar = *message.digest();

        let sign_out = time_once(&format!("{name}/online_sign/n{n}_t{t}/wall"), || {
            let mut rng = tecdsa_core::Csprng::new();
            let machines: Vec<_> = offline_states
                .into_iter()
                .map(|state| {
                    let pid = state.my_id;
                    let params = Ln18OnlineSignParams {
                        offline_state: state,
                        message_digest: m_scalar,
                    };
                    (pid, Ln18OnlineSignMachine::<C>::new(params, &mut rng))
                })
                .collect();
            per_party::run_online_comm(format!("{name}/n{n}_t{t}"), machines, 8)
        });
        let sigs: Vec<_> = sign_out.0.into_iter().map(|r| r.unwrap()).collect();
        assert!(!sigs.is_empty(), "must produce signatures");
        tecdsa_protocol::ecdsa::verify_ecdsa::<C>(&sigs[0], &public_key, &message)
            .expect("LN18 benchmark signature must verify");
        for (&pid, timing) in sign_out.1.iter().take(1) {
            print_timing(
                &format!("{name}/online_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Lin17
// ═══════════════════════════════════════════════════════════════════════

fn lin17_once() {
    use tecdsa_lin17::{
        keygen::{Lin17KeygenMachine, TwoPartyRole},
        sign,
    };

    let specs = [(PartyId(1), PartyId(2)), (PartyId(2), PartyId(1))];

    // DKG
    let keygen_out = time_once("lin17/dkg/n2_t2/wall", || {
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(my_id, peer_id))| {
                let role = roles[i];
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Lin17KeygenMachine::<C>::new(role, my_id, peer_id, &mut rng)
                        .expect("keygen machine init")
                })
            })
            .collect();
        per_party::run_timed_with_init(builders, 10)
    });
    for (&pid, timing) in keygen_out.1.iter().take(1) {
        print_timing("lin17/dkg/n2_t2", pid, timing.total_active());
    }

    // Sign (round-level per-party timing)
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_lin17::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    // Full sign, measure per-party
    let t0 = Instant::now();
    let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
    let p1_r1 = t0.elapsed();

    let t0 = Instant::now();
    let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
    let p2_r2 = t0.elapsed();

    let t0 = Instant::now();
    sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
    let p1_r3 = t0.elapsed();

    let t0 = Instant::now();
    let p2_r4_msg = sign::party2_round4::<C>(
        &p2_key,
        &p2_state,
        &p1_r1_msg,
        &p1_decommit,
        &message,
        &mut rng,
    )
    .expect("round4");
    let p2_r4 = t0.elapsed();

    let t0 = Instant::now();
    sign::party1_finalize::<C>(&p1_key, &p1_state, &p2_state.r2, &p2_r4_msg, &message)
        .expect("finalize");
    let p1_fin = t0.elapsed();

    let p1_total = p1_r1 + p1_r3 + p1_fin;
    let p2_total = p2_r2 + p2_r4;
    print_timing("lin17/full_sign/n2_t2", PartyId(1), p1_total);
    print_timing("lin17/full_sign/n2_t2", PartyId(2), p2_total);

    // Offline (presigning) communication. P1 sends round-1 commitment + round-3
    // decommit (R_1 + DLog proof + nonce); P2 sends round-2 (R_2 + DLog proof).
    per_party::record_online_comm(
        "lin17/n2_t2/party1/presign",
        tecdsa_testkit::wire_size(&p1_r1_msg)
            + point_wire_len(&p1_decommit.r1)
            + tecdsa_testkit::wire_size(&p1_decommit.dlog_proof)
            + p1_decommit.nonce.len(),
    );
    per_party::record_online_comm(
        "lin17/n2_t2/party2/presign",
        point_wire_len(&p2_r2_msg.r2) + tecdsa_testkit::wire_size(&p2_r2_msg.dlog_proof),
    );
    // Online communication: P2 sends one round-4 message; P1 only finalizes
    // locally (sends nothing online).
    per_party::record_online_comm("lin17/n2_t2/party1", 0);
    per_party::record_online_comm(
        "lin17/n2_t2/party2",
        tecdsa_testkit::wire_size(&p2_r4_msg),
    );
}

// ═══════════════════════════════════════════════════════════════════════
// KGG24
// ═══════════════════════════════════════════════════════════════════════

fn kgg24_once() {
    use tecdsa_kgg24::{
        keygen::{Kgg24KeygenMachine, TwoPartyRole},
        sign,
    };

    let specs = [(PartyId(1), PartyId(2)), (PartyId(2), PartyId(1))];

    // DKG
    let keygen_out = time_once("kgg24/dkg/n2_t2/wall", || {
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(my_id, peer_id))| {
                let role = roles[i];
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Kgg24KeygenMachine::<C>::new(role, my_id, peer_id, &mut rng)
                        .expect("keygen machine init")
                })
            })
            .collect();
        per_party::run_timed_with_init(builders, 10)
    });
    for (&pid, timing) in keygen_out.1.iter().take(1) {
        print_timing("kgg24/dkg/n2_t2", pid, timing.total_active());
    }

    // Sign
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_kgg24::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let t0 = Instant::now();
    let (p1_r1_msg, p1_state, p1_decommit) = sign::party1_round1::<C>(&mut rng);
    let p1_r1 = t0.elapsed();

    let t0 = Instant::now();
    let (p2_r2_msg, p2_state) = sign::party2_round2::<C>(&mut rng);
    let p2_r2 = t0.elapsed();

    let t0 = Instant::now();
    sign::party1_round3::<C>(&p2_r2_msg).expect("round3");
    let p1_r3 = t0.elapsed();

    let t0 = Instant::now();
    let p2_partial = sign::party2_compute_partial_sig::<C>(
        &p2_key,
        &p2_state,
        &p1_r1_msg,
        &p1_decommit,
        &message,
        &mut rng,
    )
    .expect("partial_sig");
    let p2_partial_dur = t0.elapsed();

    let t0 = Instant::now();
    sign::party1_finalize::<C>(
        &p1_key,
        &p1_state,
        &p2_state.r2,
        &p2_partial,
        &message,
        &mut rng,
    )
    .expect("finalize");
    let p1_fin = t0.elapsed();

    let p1_total = p1_r1 + p1_r3 + p1_fin;
    let p2_total = p2_r2 + p2_partial_dur;
    print_timing("kgg24/full_sign/n2_t2", PartyId(1), p1_total);
    print_timing("kgg24/full_sign/n2_t2", PartyId(2), p2_total);

    // Offline (presigning) communication, same message shapes as Lin17.
    per_party::record_online_comm(
        "kgg24/n2_t2/party1/presign",
        tecdsa_testkit::wire_size(&p1_r1_msg)
            + point_wire_len(&p1_decommit.r1)
            + tecdsa_testkit::wire_size(&p1_decommit.dlog_proof)
            + p1_decommit.nonce.len(),
    );
    per_party::record_online_comm(
        "kgg24/n2_t2/party2/presign",
        point_wire_len(&p2_r2_msg.r2) + tecdsa_testkit::wire_size(&p2_r2_msg.dlog_proof),
    );
    // Online communication: P2 sends one partial-signature message; P1 finalizes.
    per_party::record_online_comm("kgg24/n2_t2/party1", 0);
    per_party::record_online_comm(
        "kgg24/n2_t2/party2",
        tecdsa_testkit::wire_size(&p2_partial),
    );
}

// ═══════════════════════════════════════════════════════════════════════
// XAL21
// ═══════════════════════════════════════════════════════════════════════

fn xal21_once() {
    use tecdsa_xal21::{
        keygen::{TwoPartyRole, Xal21KeygenMachine},
        offline_sign, online_sign,
    };

    let specs = [(PartyId(1), PartyId(2)), (PartyId(2), PartyId(1))];

    // DKG
    let keygen_out = time_once("xal21/dkg/n2_t2/wall", || {
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(my_id, peer_id))| {
                let role = roles[i];
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Xal21KeygenMachine::<C>::new(role, my_id, peer_id, &mut rng)
                        .expect("keygen machine init")
                })
            })
            .collect();
        per_party::run_timed_with_init(builders, 10)
    });
    for (&pid, timing) in keygen_out.1.iter().take(1) {
        print_timing("xal21/dkg/n2_t2", pid, timing.total_active());
    }

    // Offline sign (presign) via the per-step functions (mirrors twoparty.rs), so
    // each party's offline message can be sized for communication.
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_xal21::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let mta_setup = tecdsa_paillier::mta::PaillierMtaSetup {
        ek: p2_key.ek.clone(),
        dk: p2_key.dk.clone(),
        proof_setup: tecdsa_paillier::mta::Gg18ProofSetup {
            ntilde: p2_key.ntilde.clone(),
        },
    };

    let (step1_msg, step1_state) = offline_sign::step1_p2_commit::<C>(&mut rng); // P2
    let (sender_msg, sender_state) =
        offline_sign::step2_p2_encrypt_k2::<C, offline_sign::DefaultMtA>(
            &mta_setup,
            &step1_state.k2,
            &mut rng,
        )
        .expect("step2_p2_encrypt_k2"); // P2 (MtA)
    let (step2_msg, step2_state) = offline_sign::step2_p1_compute::<C, offline_sign::DefaultMtA>(
        &p1_key,
        &mta_setup,
        &sender_msg,
        &mut rng,
    )
    .expect("step2_p1_compute"); // P1 (MtA)
    let x2_prime = offline_sign::step2_p2_verify::<C, offline_sign::DefaultMtA>(
        &p2_key,
        &mta_setup,
        &sender_state,
        &step1_state.k2,
        &step2_msg,
    )
    .expect("step2_p2_verify"); // P2 (local)
    let (step3_p1_msg, k1) = offline_sign::step3_p1_send_nonce::<C>(&mut rng); // P1
    let (step3_p2_decommit, p2_presig) = offline_sign::step3_p2_decommit_and_compute_R::<C>(
        &step1_state,
        &step3_p1_msg,
        &step2_msg.r1,
        x2_prime,
    )
    .expect("step3_p2_decommit_and_compute_R"); // P2
    let p1_presig = offline_sign::step3_p1_verify_and_compute_R::<C>(
        &step1_msg,
        &step3_p2_decommit,
        k1,
        &step2_state,
    )
    .expect("step3_p1_verify_and_compute_R"); // P1 (local)

    // Offline communication (presigning):
    //   P2 -> P1: step1 commit + MtA sender msg + step3 decommit (R_2 + proof + nonce)
    //   P1 -> P2: step2 (Q1' + r1 + cc + MtA receiver msg) + step3 nonce (R_1 + proof)
    const SCALAR_LEN: usize = 32; // secp256k1 scalar repr
    per_party::record_online_comm(
        "xal21/n2_t2/party2/presign",
        tecdsa_testkit::wire_size(&step1_msg)
            + tecdsa_testkit::wire_size(&sender_msg)
            + point_wire_len(&step3_p2_decommit.R2)
            + tecdsa_testkit::wire_size(&step3_p2_decommit.nizk3)
            + step3_p2_decommit.commit_nonce.len(),
    );
    per_party::record_online_comm(
        "xal21/n2_t2/party1/presign",
        point_wire_len(&step2_msg.Q1_prime)
            + 2 * SCALAR_LEN
            + tecdsa_testkit::wire_size(&step2_msg.mta_msg)
            + point_wire_len(&step3_p1_msg.R1)
            + tecdsa_testkit::wire_size(&step3_p1_msg.nizk4),
    );

    // Online sign
    time_once("xal21/online_sign/n2_t2/party2", || {
        online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2")
    });
    let p2_msg = online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2");
    time_once("xal21/online_sign/n2_t2/party1", || {
        online_sign::party1_compute_signature::<C>(&p1_key, &p1_presig, &p2_msg, &message)
            .expect("sig")
    });

    // Online communication: P2 sends one s2 message; P1 finalizes locally.
    per_party::record_online_comm("xal21/n2_t2/party1", 0);
    per_party::record_online_comm("xal21/n2_t2/party2", tecdsa_testkit::wire_size(&p2_msg));
}

// ═══════════════════════════════════════════════════════════════════════
// ABC24
// ═══════════════════════════════════════════════════════════════════════

fn abc24_once() {
    use tecdsa_abc24::{
        keygen::{Abc24KeygenMachine, TwoPartyRole},
        sign,
    };

    let specs = [(PartyId(1), PartyId(2)), (PartyId(2), PartyId(1))];

    // DKG
    let keygen_out = time_once("abc24/dkg/n2_t2/wall", || {
        let roles = [TwoPartyRole::Party1, TwoPartyRole::Party2];
        let builders: Vec<(PartyId, _)> = specs
            .iter()
            .enumerate()
            .map(|(i, &(my_id, peer_id))| {
                let role = roles[i];
                (my_id, move || {
                    let mut rng = tecdsa_core::Csprng::new();
                    Abc24KeygenMachine::<C>::new(role, my_id, peer_id, &mut rng)
                        .expect("keygen machine init")
                })
            })
            .collect();
        per_party::run_timed_with_init(builders, 10)
    });
    for (&pid, timing) in keygen_out.1.iter().take(1) {
        print_timing("abc24/dkg/n2_t2", pid, timing.total_active());
    }

    // Sign
    let mut rng = rand_core::OsRng;
    let (server_key, client_key) = tecdsa_abc24::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let t0 = Instant::now();
    let (server_msg, server_state) = sign::server_round1::<C>(&server_key, &mut rng);
    let p1_r1 = t0.elapsed();

    let t0 = Instant::now();
    let client_msg = sign::client_round2::<C>(&client_key, &server_msg, &message, &mut rng)
        .expect("client_round2");
    let p2_r2 = t0.elapsed();

    let t0 = Instant::now();
    sign::server_finalize::<C>(&server_key, &server_state, &client_msg, &message)
        .expect("server_finalize");
    let p1_fin = t0.elapsed();

    let p1_total = p1_r1 + p1_fin;
    print_timing("abc24/full_sign/n2_t2", PartyId(1), p1_total);
    print_timing("abc24/full_sign/n2_t2", PartyId(2), p2_r2);

    // Offline (presigning) communication: the server (P1) sends round 1
    // (R_2 + Y, two compressed points); the client (P2) has no offline round.
    per_party::record_online_comm(
        "abc24/n2_t2/party1/presign",
        point_wire_len(&server_msg.r2) + point_wire_len(&server_msg.y),
    );
    per_party::record_online_comm("abc24/n2_t2/party2/presign", 0);
    // Online communication: the client (P2) sends one round-2 message; the server
    // (P1) finalizes locally. ClientRound2Msg isn't Serialize (raw ProjectivePoint
    // fields), so size its parts: two compressed points + the OLE Paillier ct.
    per_party::record_online_comm("abc24/n2_t2/party1", 0);
    per_party::record_online_comm(
        "abc24/n2_t2/party2",
        point_wire_len(&client_msg.r1)
            + point_wire_len(&client_msg.r_point)
            + tecdsa_testkit::wire_size(&client_msg.s_ct),
    );
}

// ═══════════════════════════════════════════════════════════════════════
// CL-based helpers (shared ClSetup for TX25, JTX25, WMY23, WMC24, LLZ25, Trout)
// ═══════════════════════════════════════════════════════════════════════

/// DKG-only sweep for CL-based protocols: times keygen for each
/// `TECDSA_BENCH_DKG_CONFIGS` `(n, t)` and prints per-party active time.
///
/// CL protocols use without_init (machine construction includes a CL setup
/// clone which is not protocol work); matches the Criterion benchmark.
fn cl_dkg_sweep<KM>(name: &str, make_keygen: impl Fn(PartyId, Vec<PartyId>, u16) -> KM)
where
    KM: tecdsa_protocol::StateMachine,
    KM::Outbound: Clone + Into<KM::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    KM::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    for (n, t) in config::dkg_configs() {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let keygen_out = time_once(&format!("{name}/dkg/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| (pid, make_keygen(pid, all_parties.clone(), t)))
                .collect();
            per_party::run_timed_without_init(machines, 15)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(&format!("{name}/dkg/n{n}_t{t}"), pid, timing.total_active());
        }
    }
}

/// Presign + online-sign sweep for CL-based protocols: for each threshold in
/// `TECDSA_BENCH_SIGN_THRESHOLDS` at `TECDSA_BENCH_SIGN_N` parties, silently
/// regenerates key shares (DKG timing lives in [`cl_dkg_sweep`]) then times
/// presign and online sign, printing per-party active time. The signing quorum
/// is parties `1..=t`.
fn cl_presign_sign_sweep<KM, PM, SM>(
    name: &str,
    msg_bytes: &[u8],
    make_keygen: impl Fn(PartyId, Vec<PartyId>, u16) -> KM,
    // Post-keygen fixup applied to the collected key shares before presign.
    // Most protocols pass a no-op since their DKG output is directly usable.
    post_keygen: impl Fn(&mut [<KM as tecdsa_protocol::StateMachine>::Output]),
    make_presign: impl Fn(PartyId, Vec<PartyId>, &<KM as tecdsa_protocol::StateMachine>::Output) -> PM,
    make_sign: impl Fn(
        PartyId,
        Vec<PartyId>,
        <PM as tecdsa_protocol::StateMachine>::Output,
        &[u8],
        k256::ProjectivePoint,
    ) -> SM,
    extract_pk: impl Fn(&<KM as tecdsa_protocol::StateMachine>::Output) -> k256::ProjectivePoint,
) where
    KM: tecdsa_protocol::StateMachine,
    KM::Outbound: Clone + Into<KM::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    KM::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
    PM: tecdsa_protocol::StateMachine,
    PM::Outbound: Clone + Into<PM::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    PM::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
    SM: tecdsa_protocol::StateMachine,
    SM::Outbound: Clone + Into<SM::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    SM::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    let n = config::sign_n();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for t in config::sign_thresholds() {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: key shares at (n, t).
        let mut key_shares: Vec<_> = {
            let machines: Vec<_> = all_parties
                .iter()
                .map(|&pid| (pid, make_keygen(pid, all_parties.clone(), t)))
                .collect();
            per_party::run_timed_without_init(machines, 15)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };

        // Install the protocol's required key material (e.g. trusted threshold-CL
        // setup) before presign. No-op for protocols with self-contained DKG output.
        post_keygen(&mut key_shares);
        let public_key = extract_pk(&key_shares[0]);

        // Presign
        let presign_out = time_once(&format!("{name}/presign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let share = &key_shares[(s - 1) as usize];
                    (pid, make_presign(pid, signer_parties.clone(), share))
                })
                .collect();
            per_party::run_timed_without_init(machines, 10)
        });
        let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in presign_out.1.iter().take(1) {
            print_timing(
                &format!("{name}/presign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Online sign
        let sign_out = time_once(&format!("{name}/online_sign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (
                        pid,
                        make_sign(pid, signer_parties.clone(), presig, msg_bytes, public_key),
                    )
                })
                .collect();
            per_party::run_online_comm(format!("{name}/n{n}_t{t}"), machines, 10)
        });
        for (&pid, timing) in sign_out.1.iter().take(1) {
            print_timing(
                &format!("{name}/online_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TX25
// ═══════════════════════════════════════════════════════════════════════

fn tx25_once() {
    use tecdsa_tx25::{
        keygen::Tx25KeygenMachine, presign::Tx25PresignMachine, sign::Tx25OnlineSignMachine,
    };

    let seed = "42042";
    let msg = sha2::Sha256::digest(b"benchmark message");

    let cl_setup = time_once("tx25/setup/cl", || {
        tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup")
    });

    cl_dkg_sweep("tx25", |pid, all, threshold| {
        Tx25KeygenMachine::new_with_setup(pid, all, threshold, seed, true, cl_setup.clone())
            .expect("tx25 keygen")
    });
    cl_presign_sign_sweep(
        "tx25",
        &msg,
        |pid, all, threshold| {
            Tx25KeygenMachine::new_with_setup(pid, all, threshold, seed, true, cl_setup.clone())
                .expect("tx25 keygen")
        },
        |_shares| {},
        |pid, all, share| {
            Tx25PresignMachine::new(pid, all, share, cl_setup.clone()).expect("tx25 presign")
        },
        |pid, all, presig, msg_bytes, pk| {
            Tx25OnlineSignMachine::new(pid, all, presig, msg_bytes, pk).expect("tx25 sign")
        },
        |share| share.public_key,
    );
}

// ═══════════════════════════════════════════════════════════════════════
// JTX25
// ═══════════════════════════════════════════════════════════════════════

fn jtx25_once() {
    use tecdsa_jtx25::{
        keygen::Jtx25KeygenMachine, presign::Jtx25PresignMachine, sign::Jtx25OnlineSignMachine,
    };

    let seed = "42042";
    let msg = sha2::Sha256::digest(b"benchmark message");

    let cl_setup = time_once("jtx25/setup/cl", || {
        tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup")
    });

    cl_dkg_sweep("jtx25", |pid, all, threshold| {
        Jtx25KeygenMachine::new_with_setup(pid, all, threshold, seed, true, cl_setup.clone())
            .expect("jtx25 keygen")
    });
    cl_presign_sign_sweep(
        "jtx25",
        &msg,
        |pid, all, threshold| {
            Jtx25KeygenMachine::new_with_setup(pid, all, threshold, seed, true, cl_setup.clone())
                .expect("jtx25 keygen")
        },
        |_shares| {},
        |pid, all, share| {
            Jtx25PresignMachine::new(pid, all, share, cl_setup.clone()).expect("jtx25 presign")
        },
        |pid, all, presig, msg_bytes, pk| {
            Jtx25OnlineSignMachine::new(pid, all, presig, msg_bytes, pk).expect("jtx25 sign")
        },
        |share| share.public_key,
    );
}

fn jtx25_robust_once() {
    use tecdsa_jtx25::{
        keygen::Jtx25KeygenMachine, presign::robust::Jtx25RobustPresignMachine,
        sign::robust::Jtx25RobustOnlineSignMachine,
    };

    let seed = "42042";
    let msg = sha2::Sha256::digest(b"benchmark message");
    let cl_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");

    // Keygen is shared with the normal variant; only presign/online differ, so we
    // run just the sign sweep to record the robust online communication.
    cl_presign_sign_sweep(
        "jtx25_robust",
        &msg,
        |pid, all, threshold| {
            Jtx25KeygenMachine::new_with_setup(pid, all, threshold, seed, true, cl_setup.clone())
                .expect("jtx25 keygen")
        },
        |_shares| {},
        |pid, all, share| {
            Jtx25RobustPresignMachine::new(pid, all, share, cl_setup.clone())
                .expect("jtx25 robust presign")
        },
        |pid, all, presig, msg_bytes, pk| {
            Jtx25RobustOnlineSignMachine::new(pid, all, presig, msg_bytes, pk)
                .expect("jtx25 robust sign")
        },
        |share| share.public_key,
    );
}

// ═══════════════════════════════════════════════════════════════════════
// WMY23
// ═══════════════════════════════════════════════════════════════════════

fn wmy23_once() {
    use tecdsa_wmy23::{
        keygen::Wmy23KeygenMachine,
        presign::{PresignConfig, Wmy23PresignMachine},
        sign::Wmy23OnlineSignMachine,
    };

    let seed = "42042";
    let msg_data = make_data_to_sign(b"benchmark message");

    let cl_setup = time_once("wmy23/setup/cl", || {
        tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup")
    });

    // DKG: sweep (n, t).
    for (n, t) in config::dkg_configs() {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let keygen_out = time_once(&format!("wmy23/dkg/n{n}_t{t}/wall"), || {
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
            per_party::run_timed_without_init(machines, 15)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(&format!("wmy23/dkg/n{n}_t{t}"), pid, timing.total_active());
        }
    }

    // Presign / Online sign: sweep t at fixed n.
    let n = config::sign_n();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for t in config::sign_thresholds() {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: key shares at (n, t).
        let key_shares: Vec<_> = {
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
            per_party::run_timed_without_init(machines, 15)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };
        let public_key = key_shares[0].public_key;

        // Presign
        let presign_out = time_once(&format!("wmy23/presign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
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
            per_party::run_timed_without_init(machines, 10)
        });
        let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in presign_out.1.iter().take(1) {
            print_timing(
                &format!("wmy23/presign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Online sign
        let sign_out = time_once(&format!("wmy23/online_sign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
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
            per_party::run_online_comm(format!("wmy23/n{n}_t{t}"), machines, 10)
        });
        for (&pid, timing) in sign_out.1.iter().take(1) {
            print_timing(
                &format!("wmy23/online_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// WMC24
// ═══════════════════════════════════════════════════════════════════════

fn wmc24_once() {
    use tecdsa_wmc24::{
        keygen::Wmc24KeygenMachine, presign::Wmc24PresignMachine, sign::Wmc24OnlineSignMachine,
    };

    let seed = "42042";
    let msg = sha2::Sha256::digest(b"benchmark message");

    let cl_setup = time_once("wmc24/setup/cl", || {
        tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup")
    });

    cl_dkg_sweep("wmc24", |pid, all, threshold| {
        Wmc24KeygenMachine::new_with_setup(pid, all, threshold, seed, true, cl_setup.clone())
            .expect("wmc24 keygen")
    });
    cl_presign_sign_sweep(
        "wmc24",
        &msg,
        |pid, all, threshold| {
            Wmc24KeygenMachine::new_with_setup(pid, all, threshold, seed, true, cl_setup.clone())
                .expect("wmc24 keygen")
        },
        |_shares| { /* DKG produces proper Shamir ElGamal shares natively */ },
        |pid, all, share| {
            Wmc24PresignMachine::new(pid, all, share, cl_setup.clone()).expect("wmc24 presign")
        },
        |pid, all, presig, msg_bytes, pk| {
            Wmc24OnlineSignMachine::new(pid, all, presig, msg_bytes, pk).expect("wmc24 sign")
        },
        |share| share.public_key,
    );
}

// ═══════════════════════════════════════════════════════════════════════
// LLZ25
// ═══════════════════════════════════════════════════════════════════════

fn llz25_once() {
    use tecdsa_llz25::{
        keygen::Llz25KeygenMachine, presign::machine::Llz25PresignMachine,
        sign::machine::Llz25SignMachine,
    };

    let seed = "42042";
    let msg = sha2::Sha256::digest(b"benchmark message");

    let cl_setup = time_once("llz25/setup/cl", || {
        tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup")
    });

    // Setup: CL CRS key (shared out-of-band, independent of n/t).
    let pk_crs = {
        let mut tmp = cl_setup.clone();
        let (_, pk) = tmp.keygen().expect("crs keygen");
        pk
    };

    // DKG: sweep (n, t).
    for (n, t) in config::dkg_configs() {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let keygen_out = time_once(&format!("llz25/dkg/n{n}_t{t}/wall"), || {
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
                        .expect("llz25 keygen machine"),
                    )
                })
                .collect();
            per_party::run_timed_without_init(machines, 10)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(&format!("llz25/dkg/n{n}_t{t}"), pid, timing.total_active());
        }
    }

    // Presign / Online sign: sweep t at fixed n.
    let n = config::sign_n();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for t in config::sign_thresholds() {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
        let quorum_indices: Vec<u16> = signers.clone();

        // Untimed setup: key shares at (n, t).
        let key_shares: Vec<_> = {
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
                        .expect("llz25 keygen machine"),
                    )
                })
                .collect();
            per_party::run_timed_without_init(machines, 10)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };

        // Presign
        let presign_out = time_once(&format!("llz25/presign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
                .iter()
                .enumerate()
                .map(|(pos, &s)| {
                    let pid = PartyId(s);
                    let local_pk_crs = {
                        let mut tmp = cl_setup.clone();
                        let (_, pk) = tmp.keygen().expect("crs");
                        pk
                    };
                    (
                        pid,
                        Llz25PresignMachine::new(
                            pid,
                            signer_parties.clone(),
                            key_shares[(s - 1) as usize].clone(),
                            quorum_indices.clone(),
                            pos,
                            cl_setup.clone(),
                            local_pk_crs,
                        )
                        .expect("llz25 presign"),
                    )
                })
                .collect();
            per_party::run_timed_without_init(machines, 10)
        });
        let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in presign_out.1.iter().take(1) {
            print_timing(
                &format!("llz25/presign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Sign
        let sign_out = time_once(&format!("llz25/online_sign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (
                        pid,
                        Llz25SignMachine::new(pid, signer_parties.clone(), presig, &msg)
                            .expect("llz25 sign"),
                    )
                })
                .collect();
            per_party::run_online_comm(format!("llz25/n{n}_t{t}"), machines, 10)
        });
        for (&pid, timing) in sign_out.1.iter().take(1) {
            print_timing(
                &format!("llz25/online_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Trout
// ═══════════════════════════════════════════════════════════════════════

fn trout_once() {
    use tecdsa_trout::{
        keygen::TroutKeygenMachine, presign::machine::TroutPresignMachine,
        sign::machine::TroutSignMachine,
    };

    let seed = "42042";
    let message = make_data_to_sign(b"benchmark message");

    let cl_setup = time_once("trout/setup/cl", || {
        tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup")
    });

    // DKG: sweep (n, t).
    for (n, t) in config::dkg_configs() {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let keygen_out = time_once(&format!("trout/dkg/n{n}_t{t}/wall"), || {
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
                        .expect("trout keygen machine"),
                    )
                })
                .collect();
            per_party::run_timed_without_init(machines, 10)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(&format!("trout/dkg/n{n}_t{t}"), pid, timing.total_active());
        }
    }

    // Presign / Online sign: sweep t at fixed n.
    let n = config::sign_n();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for t in config::sign_thresholds() {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
        let signing_1based: Vec<u16> = signers.clone();

        // Untimed setup: key shares at (n, t).
        let key_shares: Vec<_> = {
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
                        .expect("trout keygen machine"),
                    )
                })
                .collect();
            per_party::run_timed_without_init(machines, 10)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };

        // Presign (clone key shares)
        let presign_out = time_once(&format!("trout/presign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
                .iter()
                .map(|&s| {
                    let pid = PartyId(s);
                    let share = key_shares[(s - 1) as usize].clone();
                    // Reconstruct the *joint* CL public key (Y_cl = product Y_k) that
                    // keygen encrypted x_i under. Passing a fresh single-party key
                    // here never matches and breaks scaled decryption — mirror the
                    // crate's integration test instead.
                    let (pa, pb, pc) = &share.cl_pk_abc;
                    let cl_pk_qfi =
                        tecdsa_trout::error::qfi_from_abc(pa, pb, pc).expect("reconstruct CL pk");
                    let local_setup = cl_setup.clone();
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
            per_party::run_timed_without_init(machines, 10)
        });
        let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in presign_out.1.iter().take(1) {
            print_timing(
                &format!("trout/presign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Sign via Orchestrator (1-round: broadcast F_i shares, aggregate, compute signature)
        let sign_out = time_once(&format!("trout/online_sign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
                .iter()
                .zip(presigs)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    let share = key_shares[(s - 1) as usize].clone();
                    // Same joint-CL-key reconstruction as presign (see above).
                    let (pa, pb, pc) = &share.cl_pk_abc;
                    let cl_pk_qfi =
                        tecdsa_trout::error::qfi_from_abc(pa, pb, pc).expect("reconstruct CL pk");
                    let local_setup = cl_setup.clone();
                    let cl_pk = local_setup.pk_from_qfi(&cl_pk_qfi).expect("pk_from_qfi");
                    (
                        pid,
                        TroutSignMachine::new(
                            pid,
                            signer_parties.clone(),
                            presig,
                            &message,
                            &share,
                            local_setup,
                            &cl_pk,
                        )
                        .expect("trout sign"),
                    )
                })
                .collect();
            per_party::run_online_comm(format!("trout/n{n}_t{t}"), machines, 10)
        });
        for (&pid, timing) in sign_out.1.iter().take(1) {
            print_timing(
                &format!("trout/online_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// XAL23
// ═══════════════════════════════════════════════════════════════════════

fn xal23_once() {
    use tecdsa_xal23::{
        keygen::Xal23KeygenMachine, presign::Xal23PresignMachine, sign::Xal23SignMachine,
    };

    let message = make_data_to_sign(b"benchmark message");

    // DKG (JL-based, Profile B: p_bits=1680, k=712): sweep (n, t).
    for (n, t) in config::dkg_configs() {
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
        let keygen_out = time_once(&format!("xal23/dkg/n{n}_t{t}/wall"), || {
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
            per_party::run_timed_without_init(machines, 10)
        });
        for (&pid, timing) in keygen_out.1.iter().take(1) {
            print_timing(&format!("xal23/dkg/n{n}_t{t}"), pid, timing.total_active());
        }
    }

    // Presign / Online sign: sweep t at fixed n.
    let n = config::sign_n();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    for t in config::sign_thresholds() {
        let signers = config::first_signers(t);
        let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

        // Untimed setup: key shares at (n, t).
        let mut key_shares: Vec<_> = {
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
            per_party::run_timed_without_init(machines, 10)
                .0
                .into_iter()
                .map(|r| r.unwrap())
                .collect()
        };

        // XAL23's presign/sign assume *additive* signing shares (w_i = secret_share,
        // summed over the quorum), but Xal23KeygenMachine performs a Feldman DKG and
        // emits *Shamir* shares. Convert the quorum's Shamir shares to additive shares
        // via Lagrange weighting (w_i = lambda_i * x_i) so any t subset reconstructs the
        // key. Each party's Shamir evaluation point equals its 1-based keygen index.
        let lambdas = tecdsa_vss::lagrange::coefficients::<C>(&signers);
        for (pos, &s) in signers.iter().enumerate() {
            key_shares[(s - 1) as usize].secret_share *= lambdas[pos];
        }

        // Presign (interactive 4-round StateMachine via Orchestrator)
        let presign_out = time_once(&format!("xal23/presign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
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
            per_party::run_timed_without_init(machines, 10)
        });
        let presig_results: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
        for (&pid, timing) in presign_out.1.iter().take(1) {
            print_timing(
                &format!("xal23/presign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }

        // Online sign
        let sign_out = time_once(&format!("xal23/online_sign/n{n}_t{t}/wall"), || {
            let machines: Vec<_> = signers
                .iter()
                .zip(presig_results)
                .map(|(&s, presig)| {
                    let pid = PartyId(s);
                    (pid, Xal23SignMachine::<C>::new(presig, message))
                })
                .collect();
            per_party::run_online_comm(format!("xal23/n{n}_t{t}"), machines, 10)
        });
        for (&pid, timing) in sign_out.1.iter().take(1) {
            print_timing(
                &format!("xal23/online_sign/n{n}_t{t}"),
                pid,
                timing.total_active(),
            );
        }
    }
}
