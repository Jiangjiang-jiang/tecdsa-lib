// SPDX-License-Identifier: MIT OR Apache-2.0
//! One-shot protocol timing.
//!
//! Runs each protocol phase (keygen, presign, sign) once and prints TSV rows
//! with per-party active time from the Orchestrator timing infrastructure.
//!
//! Covers: MtA primitives, multi-party (CGGMP20, DKLs23, GG18),
//! and two-party (Lin17, KGG24, XAL21, ABC24) protocols.
//!
//! Format: name<TAB>elapsed_ns<TAB>elapsed_human

use std::sync::Arc;
use std::time::{Duration, Instant};

use elliptic_curve::ops::Reduce;
use elliptic_curve::PrimeField;
use k256::Secp256k1;
use sha2::{Digest, Sha256};
use tecdsa_bench::per_party;
use tecdsa_protocol::{DataToSign, PartyId, PartyInfo, SessionConfig, SessionId};

type C = Secp256k1;

fn time_once<T>(name: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed();
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

fn make_data_to_sign(msg: &[u8]) -> DataToSign<C> {
    let hash_bytes: [u8; 32] = Sha256::digest(msg).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    DataToSign::from_digest(scalar)
}

fn main() {
    println!("name\telapsed_ns\telapsed");

    run_group("mta", mta_once);
    run_group("cggmp20", cggmp20_once);
    run_group("dkls23", dkls23_once);
    run_group("gg18", gg18_once);
    run_group("ggn16", ggn16_once);
    run_group("ln18", ln18_once);
    run_group("tx25", tx25_once);
    run_group("jtx25", jtx25_once);
    run_group("wmy23", wmy23_once);
    run_group("wmc24", wmc24_once);
    run_group("llz25", llz25_once);
    run_group("trout", trout_once);
    run_group("xal23", xal23_once);
    run_group("lin17", lin17_once);
    run_group("kgg24", kgg24_once);
    run_group("xal21", xal21_once);
    run_group("abc24", abc24_once);
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

    let n = 3u16;
    let corrupted_t = 1u16;
    let signers = [1u16, 2];
    let message = make_data_to_sign(b"benchmark message");

    // DKG
    let keygen_out = time_once("cggmp20/dkg/n3_t1/wall", || {
        let configs = make_session_configs(n, corrupted_t);
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
    let core_shares: Vec<_> = keygen_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &keygen_out.1 {
        print_timing("cggmp20/dkg/n3_t1", pid, timing.total_active());
    }

    // AuxInfo
    let aux_out = time_once("cggmp20/aux_info/n3/wall", || {
        let configs = make_session_configs(n, 1);
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
    let aux_infos: Vec<Arc<_>> = aux_out
        .0
        .into_iter()
        .map(|r| Arc::new(r.unwrap()))
        .collect();
    for (&pid, timing) in &aux_out.1 {
        print_timing("cggmp20/aux_info/n3", pid, timing.total_active());
    }

    // Presign
    let presign_out = time_once("cggmp20/presign/n3_t1/wall", || {
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
        per_party::run_timed_with_init(builders, 10)
    });
    let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &presign_out.1 {
        print_timing("cggmp20/presign/n3_t1", pid, timing.total_active());
    }

    // Online sign
    let public_key = &core_shares[0].public_key;
    for (idx, &signer) in signers.iter().enumerate() {
        let name = format!("cggmp20/online_sign/n3_t1/party{signer}/partial_sign");
        time_once(&name, || presigs[idx].0.partial_sign(&message));
    }
    let partials: Vec<_> = presigs
        .iter()
        .map(|(p, _)| p.partial_sign(&message))
        .collect();
    let pub_data = &presigs[0].1;
    time_once("cggmp20/online_sign/n3_t1/combine", || {
        PartialSignature::combine(&partials, pub_data, public_key, &message).expect("combine")
    });
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

    let n = 3u16;
    let corrupted_t = 1u16;
    let signer_indices = [1u16, 2];
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    let signer_parties: Vec<PartyId> = signer_indices.iter().map(|&i| PartyId(i)).collect();
    let message = make_data_to_sign(b"benchmark message");

    // DKG
    let keygen_out = time_once("dkls23/dkg/n3_t1/wall", || {
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
        per_party::run_timed_with_init(builders, 10)
    });
    let shares: Vec<_> = keygen_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &keygen_out.1 {
        print_timing("dkls23/dkg/n3_t1", pid, timing.total_active());
    }

    // Presign
    let presign_out = time_once("dkls23/presign/n3_t1/wall", || {
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
    for (&pid, timing) in &presign_out.1 {
        print_timing("dkls23/presign/n3_t1", pid, timing.total_active());
    }

    // Online sign
    let sign_out = time_once("dkls23/online_sign/n3_t1/wall", || {
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
        per_party::run_timed_with_init(builders, 10)
    });
    for (&pid, timing) in &sign_out.1 {
        print_timing("dkls23/online_sign/n3_t1", pid, timing.total_active());
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

    let n = 3u16;
    let corrupted_t = 1u16;
    let signers = [1u16, 2];
    let message = make_data_to_sign(b"benchmark message");

    // DKG
    let keygen_out = time_once("gg18/dkg/n3_t1/wall", || {
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
        per_party::run_timed_with_init(builders, 10)
    });
    let key_shares: Vec<_> = keygen_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &keygen_out.1 {
        print_timing("gg18/dkg/n3_t1", pid, timing.total_active());
    }

    // Presign
    let presign_out = time_once("gg18/presign/n3_t1/wall", || {
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
        per_party::run_timed_with_init(builders, 10)
    });
    let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &presign_out.1 {
        print_timing("gg18/presign/n3_t1", pid, timing.total_active());
    }

    // Online sign
    let sign_out = time_once("gg18/online_sign/n3_t1/wall", || {
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
        per_party::run_timed_with_init(builders, 10)
    });
    for (&pid, timing) in &sign_out.1 {
        print_timing("gg18/online_sign/n3_t1", pid, timing.total_active());
    }
}

// ═══════════════════════════════════════════════════════════════════════
// GGN16
// ═══════════════════════════════════════════════════════════════════════

fn ggn16_once() {
    use tecdsa_ggn16::{
        key_share::Ggn16KeyShare, keygen::Ggn16KeygenMachine, presign::Ggn16PresignMachine,
        sign::Ggn16OnlineSignMachine,
    };
    use tecdsa_paillier::{
        backend::Integer,
        threshold::{DecryptionShare, ThresholdSetup},
    };

    let n = 3u16;
    let corrupted_t = 1u16;
    let signers = [1u16, 2];
    let message = make_data_to_sign(b"benchmark message");
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    // ── Setup: threshold Paillier + Ring-Pedersen (timed separately) ──
    let (threshold_setup, dec_shares) = time_once("ggn16/setup/threshold_paillier", || {
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
        for _ in 0..corrupted_t {
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
            threshold: corrupted_t,
            delta,
        };
        (setup, shares)
    });

    let (n_tilde, h1, h2) = time_once("ggn16/setup/ring_pedersen", || {
        let mut rng = rand_core::OsRng;
        let p = Integer::generate_safe_prime(&mut rng, 1536);
        let q = Integer::generate_safe_prime(&mut rng, 1536);
        let nt = &p * &q;
        let h1 = Integer::sample_in_mult_group_of(&mut rng, &nt);
        let lambda = (&p - Integer::one()) * (&q - Integer::one());
        let h2 = h1.pow_mod_ref(&lambda, &nt).expect("pow_mod");
        (nt, h1, h2)
    });

    // DKG
    let keygen_out = time_once("ggn16/dkg/n3_t1/wall", || {
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
                        corrupted_t,
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
    let key_shares: Vec<Ggn16KeyShare<C>> = keygen_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &keygen_out.1 {
        print_timing("ggn16/dkg/n3_t1", pid, timing.total_active());
    }

    let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

    // Presign
    let presign_out = time_once("ggn16/presign/n3_t1/wall", || {
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
    for (&pid, timing) in &presign_out.1 {
        print_timing("ggn16/presign/n3_t1", pid, timing.total_active());
    }

    // Online sign
    let sign_out = time_once("ggn16/online_sign/n3_t1/wall", || {
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
        per_party::run_timed_without_init(machines, 10)
    });
    for (&pid, timing) in &sign_out.1 {
        print_timing("ggn16/online_sign/n3_t1", pid, timing.total_active());
    }
}

// ═══════════════════════════════════════════════════════════════════════
// LN18 (8-round full sign via simulation)
// ═══════════════════════════════════════════════════════════════════════

fn ln18_once() {
    use std::collections::BTreeMap;
    use tecdsa_ln18::{
        f_mult::{
            init::InitState,
            input::{InputOutput, InputRound1Msg, InputRound2Msg, InputState},
        },
        key_share::Ln18KeyShare,
        keygen::Ln18KeygenMachine,
        sign::{ln18_full_sign_parallel, Ln18PresignParams},
    };

    let n = 3u16;
    let corrupted_t = 1u16;
    let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

    // ── Setup (timed separately) ──

    // DKG via StateMachine
    let key_shares: Vec<Ln18KeyShare<C>> = time_once("ln18/dkg/n3_t1/wall", || {
        let session_id = SessionId([0u8; 32]);
        let configs: Vec<SessionConfig> = (0..n)
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
            .collect();
        let mut rng = tecdsa_core::Csprng::new();
        let machines: Vec<_> = configs
            .iter()
            .map(|cfg| {
                (
                    cfg.local_party.id,
                    Ln18KeygenMachine::<C>::new(cfg, &mut rng),
                )
            })
            .collect();
        let (outputs, timings) = per_party::run_timed_without_init(machines, 10);
        for (&pid, timing) in &timings {
            print_timing("ln18/dkg/n3_t1", pid, timing.total_active());
        }
        outputs.into_iter().map(|r| r.unwrap()).collect()
    });

    // Init sub-protocol (ElGamal DKG, 2 rounds — setup, not timed as "sign")
    let init_outputs = time_once("ln18/setup/init", || {
        let mut rng = rand_core::OsRng;
        let n_usize = parties.len();
        let mut states = Vec::with_capacity(n_usize);
        let mut r1_msgs = Vec::with_capacity(n_usize);
        for i in 0..n_usize {
            let (state, msg) = InitState::<C>::new(parties[i], parties.to_vec(), &mut rng);
            states.push(state);
            r1_msgs.push(msg);
        }
        let mut r2_msgs = Vec::with_capacity(n_usize);
        for i in 0..n_usize {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            r2_msgs.push(states[i].handle_round1(&others).expect("init R1"));
        }
        let mut outputs = Vec::with_capacity(n_usize);
        for i in 0..n_usize {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            outputs.push(states[i].finish_round2(&others).expect("init R2"));
        }
        outputs
    });

    // Paillier keys + NTilde (setup, not timed as "sign")
    let (dks, eks, ntilde_map) = time_once("ln18/setup/paillier_ntilde", || {
        let mut rng = rand_core::OsRng;
        let mut dks = Vec::new();
        let mut eks = BTreeMap::new();
        let mut ntilde_map = BTreeMap::new();
        for &pid in &parties {
            let dk = tecdsa_paillier::keygen(&mut rng).expect("paillier keygen");
            eks.insert(pid, dk.encryption_key().clone());
            dks.push(dk);
            let nt = tecdsa_bench::zk_fixtures::NTildeFixture::generate();
            ntilde_map.insert(pid, nt.to_mta_params());
        }
        (dks, eks, ntilde_map)
    });

    // Input(x) sub-protocol (2 rounds — setup, stores x_i for signing)
    let stored_x_inputs: Vec<InputOutput<C>> = time_once("ln18/setup/input_x", || {
        let mut rng = rand_core::OsRng;
        let elgamal_pk = init_outputs[0].elgamal_pk;
        let x_shares: Vec<_> = key_shares.iter().map(|ks| ks.secret_share).collect();
        let n_usize = parties.len();
        let mut states = Vec::with_capacity(n_usize);
        let mut r1_msgs: Vec<InputRound1Msg> = Vec::with_capacity(n_usize);
        for i in 0..n_usize {
            let (state, msg) = InputState::<C>::new(
                parties[i],
                parties.to_vec(),
                elgamal_pk,
                x_shares[i],
                &mut rng,
            );
            states.push(state);
            r1_msgs.push(msg);
        }
        let mut r2_msgs: Vec<InputRound2Msg<C>> = Vec::with_capacity(n_usize);
        for i in 0..n_usize {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            r2_msgs.push(states[i].handle_round1(&others).expect("input R1"));
        }
        let mut outputs = Vec::with_capacity(n_usize);
        for i in 0..n_usize {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            outputs.push(states[i].finish_round2(&others).expect("input R2"));
        }
        outputs
    });

    // Build sign params
    let sign_params: Vec<Ln18PresignParams<C>> = (0..n as usize)
        .map(|i| {
            let ks = Ln18KeyShare {
                party_index: key_shares[i].party_index,
                secret_share: key_shares[i].secret_share,
                public_key: key_shares[i].public_key,
                elgamal_dk: init_outputs[i].d_i,
                elgamal_pk: init_outputs[i].elgamal_pk,
                elgamal_pk_shares: init_outputs[i].elgamal_pk_shares.clone(),
                n: key_shares[i].n,
                t: key_shares[i].t,
            };
            Ln18PresignParams {
                key_share: ks,
                paillier_dk: dks[i].clone(),
                paillier_eks: eks.clone(),
                ntilde_params: ntilde_map.clone(),
                init_output: init_outputs[i].clone(),
                stored_x_input: stored_x_inputs[i].clone(),
            }
        })
        .collect();

    // ── 8-round full sign (timed) ──
    let message = make_data_to_sign(b"benchmark message");
    let m_scalar = message.digest();
    let sign_start = Instant::now();
    let sigs = ln18_full_sign_parallel(&sign_params, &parties, m_scalar, &mut rand_core::OsRng);
    let sign_wall = sign_start.elapsed();
    assert!(!sigs.is_empty(), "must produce signatures");
    println!(
        "ln18/full_sign_8round/n3_t1/wall\t{}\t{}",
        sign_wall.as_nanos(),
        HumanDuration(sign_wall)
    );
    let per_party = sign_wall / n as u32;
    println!(
        "ln18/full_sign_8round/n3_t1/per_party_avg\t{}\t{}",
        per_party.as_nanos(),
        HumanDuration(per_party)
    );
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
    let keygen_out = time_once("lin17/dkg/n2_t1/wall", || {
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
    for (&pid, timing) in &keygen_out.1 {
        print_timing("lin17/dkg/n2_t1", pid, timing.total_active());
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
    print_timing("lin17/full_sign/n2_t1", PartyId(1), p1_total);
    print_timing("lin17/full_sign/n2_t1", PartyId(2), p2_total);
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
    let keygen_out = time_once("kgg24/dkg/n2_t1/wall", || {
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
    for (&pid, timing) in &keygen_out.1 {
        print_timing("kgg24/dkg/n2_t1", pid, timing.total_active());
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
    print_timing("kgg24/full_sign/n2_t1", PartyId(1), p1_total);
    print_timing("kgg24/full_sign/n2_t1", PartyId(2), p2_total);
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
    let keygen_out = time_once("xal21/dkg/n2_t1/wall", || {
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
    for (&pid, timing) in &keygen_out.1 {
        print_timing("xal21/dkg/n2_t1", pid, timing.total_active());
    }

    // Offline sign (presign) — combined total (step functions don't separate parties cleanly)
    let mut rng = rand_core::OsRng;
    let (p1_key, p2_key) = tecdsa_xal21::keygen::trusted_dealer_keygen::<C>(&mut rng);
    let message = make_data_to_sign(b"benchmark message");

    let (p1_presig, p2_presig) = time_once("xal21/presign/n2_t1/combined", || {
        offline_sign::offline_sign::<C>(&p1_key, &p2_key, &mut rng).expect("offline_sign")
    });

    // Online sign
    time_once("xal21/online_sign/n2_t1/party2", || {
        online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2")
    });
    let p2_msg = online_sign::party2_compute_s2::<C>(&p2_presig, &message).expect("s2");
    time_once("xal21/online_sign/n2_t1/party1", || {
        online_sign::party1_compute_signature::<C>(&p1_key, &p1_presig, &p2_msg, &message)
            .expect("sig")
    });
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
    let keygen_out = time_once("abc24/dkg/n2_t1/wall", || {
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
    for (&pid, timing) in &keygen_out.1 {
        print_timing("abc24/dkg/n2_t1", pid, timing.total_active());
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
    print_timing("abc24/full_sign/n2_t1", PartyId(1), p1_total);
    print_timing("abc24/full_sign/n2_t1", PartyId(2), p2_r2);
}

// ═══════════════════════════════════════════════════════════════════════
// CL-based helpers (shared ClSetup for TX25, JTX25, WMY23, WMC24, LLZ25, Trout)
// ═══════════════════════════════════════════════════════════════════════

fn cl_keygen_presign_sign<KM, PM, SM>(
    name: &str,
    n: u16,
    corrupted_t: u16,
    signers: &[u16],
    msg_bytes: &[u8],
    make_keygen: impl Fn(PartyId, Vec<PartyId>, u16) -> KM,
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
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    // DKG
    let keygen_out = time_once(&format!("{name}/dkg/n{n}_t{corrupted_t}/wall"), || {
        let machines: Vec<_> = all_parties
            .iter()
            .map(|&pid| (pid, make_keygen(pid, all_parties.clone(), corrupted_t)))
            .collect();
        per_party::run_timed_without_init(machines, 10)
    });
    let key_shares: Vec<_> = keygen_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &keygen_out.1 {
        print_timing(
            &format!("{name}/dkg/n{n}_t{corrupted_t}"),
            pid,
            timing.total_active(),
        );
    }

    let public_key = extract_pk(&key_shares[0]);
    let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

    // Presign
    let presign_out = time_once(&format!("{name}/presign/n{n}_t{corrupted_t}/wall"), || {
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
    for (&pid, timing) in &presign_out.1 {
        print_timing(
            &format!("{name}/presign/n{n}_t{corrupted_t}"),
            pid,
            timing.total_active(),
        );
    }

    // Online sign
    let sign_out = time_once(
        &format!("{name}/online_sign/n{n}_t{corrupted_t}/wall"),
        || {
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
            per_party::run_timed_without_init(machines, 10)
        },
    );
    for (&pid, timing) in &sign_out.1 {
        print_timing(
            &format!("{name}/online_sign/n{n}_t{corrupted_t}"),
            pid,
            timing.total_active(),
        );
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
    let n = 3u16;
    let t = 1u16;
    let signers = [1u16, 2];
    let msg = sha2::Sha256::digest(b"benchmark message");

    cl_keygen_presign_sign(
        "tx25",
        n,
        t,
        &signers,
        &msg,
        |pid, all, threshold| {
            Tx25KeygenMachine::new(pid, all, threshold, seed, true).expect("tx25 keygen")
        },
        |pid, all, share| {
            let setup =
                tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");
            Tx25PresignMachine::new(pid, all, share, setup).expect("tx25 presign")
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
    let n = 3u16;
    let t = 1u16;
    let signers = [1u16, 2];
    let msg = sha2::Sha256::digest(b"benchmark message");

    cl_keygen_presign_sign(
        "jtx25",
        n,
        t,
        &signers,
        &msg,
        |pid, all, threshold| {
            Jtx25KeygenMachine::new(pid, all, threshold, seed, true).expect("jtx25 keygen")
        },
        |pid, all, share| {
            let setup =
                tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");
            Jtx25PresignMachine::new(pid, all, share, setup).expect("jtx25 presign")
        },
        |pid, all, presig, msg_bytes, pk| {
            Jtx25OnlineSignMachine::new(pid, all, presig, msg_bytes, pk).expect("jtx25 sign")
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
    let n = 3u16;
    let t = 1u16;
    let signers = [1u16, 2];
    let msg_data = make_data_to_sign(b"benchmark message");
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    // DKG
    let keygen_out = time_once("wmy23/dkg/n3_t1/wall", || {
        let machines: Vec<_> = all_parties
            .iter()
            .map(|&pid| {
                (
                    pid,
                    Wmy23KeygenMachine::new(pid, all_parties.clone(), t, seed, true)
                        .expect("wmy23 keygen"),
                )
            })
            .collect();
        per_party::run_timed_without_init(machines, 10)
    });
    let key_shares: Vec<_> = keygen_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &keygen_out.1 {
        print_timing("wmy23/dkg/n3_t1", pid, timing.total_active());
    }

    let public_key = key_shares[0].public_key;
    let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

    // Presign (uses PresignConfig with CL setup; key_shares consumed by move)
    let mut key_share_map: std::collections::BTreeMap<u16, _> = key_shares
        .into_iter()
        .enumerate()
        .map(|(i, s)| ((i + 1) as u16, s))
        .collect();
    let presign_out = time_once("wmy23/presign/n3_t1/wall", || {
        let machines: Vec<_> = signers
            .iter()
            .map(|&s| {
                let pid = PartyId(s);
                let setup =
                    tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");
                let config = PresignConfig {
                    key_share: key_share_map.remove(&s).expect("key share"),
                    my_id: pid,
                    signer_parties: signer_parties.clone(),
                    cl_setup: setup,
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
    for (&pid, timing) in &presign_out.1 {
        print_timing("wmy23/presign/n3_t1", pid, timing.total_active());
    }

    // Online sign
    let sign_out = time_once("wmy23/online_sign/n3_t1/wall", || {
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
        per_party::run_timed_without_init(machines, 10)
    });
    for (&pid, timing) in &sign_out.1 {
        print_timing("wmy23/online_sign/n3_t1", pid, timing.total_active());
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
    let n = 3u16;
    let t = 1u16;
    let signers = [1u16, 2];
    let msg = sha2::Sha256::digest(b"benchmark message");

    cl_keygen_presign_sign(
        "wmc24",
        n,
        t,
        &signers,
        &msg,
        |pid, all, threshold| {
            Wmc24KeygenMachine::new(pid, all, threshold, seed, true).expect("wmc24 keygen")
        },
        |pid, all, share| {
            let setup =
                tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");
            Wmc24PresignMachine::new(pid, all, share, setup).expect("wmc24 presign")
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
    let n = 3u16;
    let t = 1u16;
    let signers = [1u16, 2];
    let msg = sha2::Sha256::digest(b"benchmark message");
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    // Setup: CL CRS key (shared out-of-band)
    let pk_crs = {
        let mut tmp =
            tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");
        let (_, pk) = tmp.keygen().expect("crs keygen");
        pk
    };

    // Interactive DKG via Orchestrator
    let keygen_out = time_once("llz25/dkg/n3_t1/wall", || {
        let machines: Vec<_> = all_parties
            .iter()
            .map(|&pid| {
                (
                    pid,
                    Llz25KeygenMachine::new(
                        pid,
                        all_parties.clone(),
                        t,
                        seed,
                        true,
                        pk_crs.clone(),
                    )
                    .expect("llz25 keygen machine"),
                )
            })
            .collect();
        per_party::run_timed_without_init(machines, 10)
    });
    let key_shares: Vec<_> = keygen_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &keygen_out.1 {
        print_timing("llz25/dkg/n3_t1", pid, timing.total_active());
    }

    let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
    let quorum_indices: Vec<u16> = signers.to_vec();

    // Presign (key_shares consumed by move)
    let mut ks_map: std::collections::BTreeMap<u16, _> = key_shares
        .into_iter()
        .enumerate()
        .map(|(i, s)| ((i + 1) as u16, s))
        .collect();
    let presign_out = time_once("llz25/presign/n3_t1/wall", || {
        let machines: Vec<_> = signers
            .iter()
            .enumerate()
            .map(|(pos, &s)| {
                let pid = PartyId(s);
                let local_setup =
                    tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl");
                let (_, local_pk_crs) = {
                    let mut tmp =
                        tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl");
                    tmp.keygen().expect("crs")
                };
                (
                    pid,
                    Llz25PresignMachine::new(
                        pid,
                        signer_parties.clone(),
                        ks_map.remove(&s).expect("key share"),
                        quorum_indices.clone(),
                        pos,
                        local_setup,
                        local_pk_crs,
                    )
                    .expect("llz25 presign"),
                )
            })
            .collect();
        per_party::run_timed_without_init(machines, 10)
    });
    let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &presign_out.1 {
        print_timing("llz25/presign/n3_t1", pid, timing.total_active());
    }

    // Sign
    let sign_out = time_once("llz25/online_sign/n3_t1/wall", || {
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
        per_party::run_timed_without_init(machines, 10)
    });
    for (&pid, timing) in &sign_out.1 {
        print_timing("llz25/online_sign/n3_t1", pid, timing.total_active());
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
    let n = 3u16;
    let t = 1u16;
    let signers = [1u16, 2];
    let message = make_data_to_sign(b"benchmark message");
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    // Interactive DKG via Orchestrator
    let keygen_out = time_once("trout/dkg/n3_t1/wall", || {
        let machines: Vec<_> = all_parties
            .iter()
            .map(|&pid| {
                (
                    pid,
                    TroutKeygenMachine::new(pid, all_parties.clone(), t, seed, true)
                        .expect("trout keygen machine"),
                )
            })
            .collect();
        per_party::run_timed_without_init(machines, 10)
    });
    let key_shares: Vec<_> = keygen_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &keygen_out.1 {
        print_timing("trout/dkg/n3_t1", pid, timing.total_active());
    }

    let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
    let signing_1based: Vec<u16> = signers.to_vec();

    // Second DKG for sign (presign consumes shares, sign needs a reference)
    let sign_keygen_out = {
        let machines: Vec<_> = all_parties
            .iter()
            .map(|&pid| {
                (
                    pid,
                    TroutKeygenMachine::new(pid, all_parties.clone(), t, seed, true)
                        .expect("trout keygen machine"),
                )
            })
            .collect();
        per_party::run_timed_without_init(machines, 10)
    };
    let sign_shares: Vec<_> = sign_keygen_out.0.into_iter().map(|r| r.unwrap()).collect();

    // Presign (key_shares consumed by move)
    let mut ks_map: std::collections::BTreeMap<u16, _> = key_shares
        .into_iter()
        .enumerate()
        .map(|(i, s)| ((i + 1) as u16, s))
        .collect();
    let presign_out = time_once("trout/presign/n3_t1/wall", || {
        let machines: Vec<_> = signers
            .iter()
            .map(|&s| {
                let pid = PartyId(s);
                let local_setup =
                    tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl");
                let (_, local_pk) = {
                    let mut tmp =
                        tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl");
                    tmp.keygen().expect("cl keygen")
                };
                (
                    pid,
                    TroutPresignMachine::new(
                        pid,
                        signer_parties.clone(),
                        ks_map.remove(&s).expect("key share"),
                        signing_1based.clone(),
                        b"bench-session",
                        local_setup,
                        local_pk,
                    )
                    .expect("trout presign"),
                )
            })
            .collect();
        per_party::run_timed_without_init(machines, 10)
    });
    let presigs: Vec<_> = presign_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &presign_out.1 {
        print_timing("trout/presign/n3_t1", pid, timing.total_active());
    }

    // Sign (local computation, uses sign_share kept from keygen)
    let sign_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl setup");
    let (_, sign_cl_pk) = {
        let mut tmp = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl");
        tmp.keygen().expect("cl keygen")
    };
    time_once("trout/online_sign/n3_t1/local", || {
        TroutSignMachine::new(
            &presigs,
            &message,
            &sign_shares[0],
            &sign_setup,
            &sign_cl_pk,
        )
        .expect("trout sign")
    });
}

// ═══════════════════════════════════════════════════════════════════════
// XAL23
// ═══════════════════════════════════════════════════════════════════════

fn xal23_once() {
    use tecdsa_xal23::{
        keygen::Xal23KeygenMachine, presign::Xal23PresignMachine, sign::Xal23SignMachine,
    };

    let n = 3u16;
    let t = 1u16;
    let signers = [1u16, 2];
    let message = make_data_to_sign(b"benchmark message");
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
    let signer_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();

    // DKG (JL-based, Profile B: p_bits=1680, k=712)
    let keygen_out = time_once("xal23/dkg/n3_t1/wall", || {
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
    let key_shares: Vec<_> = keygen_out.0.into_iter().map(|r| r.unwrap()).collect();
    for (&pid, timing) in &keygen_out.1 {
        print_timing("xal23/dkg/n3_t1", pid, timing.total_active());
    }

    // Presign (interactive 4-round StateMachine via Orchestrator)
    let presign_out = time_once("xal23/presign/n3_t1/wall", || {
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
    for (&pid, timing) in &presign_out.1 {
        print_timing("xal23/presign/n3_t1", pid, timing.total_active());
    }

    // Online sign
    let sign_out = time_once("xal23/online_sign/n3_t1/wall", || {
        let machines: Vec<_> = signers
            .iter()
            .zip(presig_results)
            .map(|(&s, presig)| {
                let pid = PartyId(s);
                (pid, Xal23SignMachine::<C>::new(presig, message))
            })
            .collect();
        per_party::run_timed_without_init(machines, 10)
    });
    for (&pid, timing) in &sign_out.1 {
        print_timing("xal23/online_sign/n3_t1", pid, timing.total_active());
    }
}
