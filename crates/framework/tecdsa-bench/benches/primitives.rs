// SPDX-License-Identifier: MIT OR Apache-2.0
//! MtA primitive benchmarks for all 6 MtA variants.
//!
//! Measures raw MtA cycles (sender_encrypt, receiver_compute, sender_decrypt)
//! used as building blocks by threshold ECDSA protocols.
//!
//! Setup (keygen) is pre-computed via LazyLock and excluded from timing.

use std::sync::LazyLock;

use criterion::{criterion_group, criterion_main, Criterion};
use elliptic_curve::PrimeField;
use k256::Secp256k1;
use rand_core::OsRng;
use tecdsa_bench::zk_fixtures::{NTildeFixture, PaillierFixture, PedersenFixture};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::backend::Integer;
use tecdsa_protocol::MtA;

static PAILLIER: LazyLock<PaillierFixture> = LazyLock::new(PaillierFixture::generate);
static NTILDE: LazyLock<NTildeFixture> = LazyLock::new(NTildeFixture::generate);
static PEDERSEN: LazyLock<PedersenFixture> = LazyLock::new(PedersenFixture::generate);

fn q_bytes() -> Vec<u8> {
    let neg_one = -k256::Scalar::ONE;
    let neg_one_bytes = neg_one.to_repr();
    let q_int = Integer::from_bytes_msf(neg_one_bytes.as_ref()) + 1u8;
    q_int.to_bytes_msf()
}

// ---------------------------------------------------------------------------
// 1. Paillier MtA (Alice/Bob range proofs with Ring-Pedersen)
// ---------------------------------------------------------------------------

fn paillier_mta(c: &mut Criterion) {
    use tecdsa_paillier::mta::{Gg18ProofSetup, Gg18Proofs, PaillierMtA, PaillierMtaSetup};
    type M = PaillierMtA<Gg18Proofs>;

    let pf = &*PAILLIER;
    let nt = &*NTILDE;
    let setup = PaillierMtaSetup {
        ek: pf.ek.clone(),
        dk: pf.dk.clone(),
        proof_setup: Gg18ProofSetup {
            ntilde: nt.to_mta_params(),
        },
    };
    let q = q_bytes();
    let a = Secp256k1::random_scalar(&mut OsRng).to_repr();
    let b = Secp256k1::random_scalar(&mut OsRng).to_repr();

    let mut g = c.benchmark_group("mta/paillier");

    g.bench_function("sender_encrypt", |bench| {
        bench.iter(|| M::sender_encrypt(&setup, b.as_ref(), &q, &mut OsRng).expect("se"))
    });

    let (sm, ss) = M::sender_encrypt(&setup, b.as_ref(), &q, &mut OsRng).expect("se");
    g.bench_function("receiver_compute", |bench| {
        bench.iter(|| M::receiver_compute(&setup, a.as_ref(), &q, &sm, &mut OsRng).expect("rc"))
    });

    let (rm, _) = M::receiver_compute(&setup, a.as_ref(), &q, &sm, &mut OsRng).expect("rc");
    g.bench_function("sender_decrypt", |bench| {
        bench.iter(|| M::sender_decrypt(&setup, &ss, &q, &rm).expect("sd"))
    });

    g.bench_function("full_cycle", |bench| {
        bench.iter(|| {
            let (sm2, ss2) = M::sender_encrypt(&setup, b.as_ref(), &q, &mut OsRng).expect("se");
            let (rm2, _) =
                M::receiver_compute(&setup, a.as_ref(), &q, &sm2, &mut OsRng).expect("rc");
            M::sender_decrypt(&setup, &ss2, &q, &rm2).expect("sd")
        })
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// 2. Paillier MtA with CGGMP20 proofs (pi_enc + pi_aff-g)
// ---------------------------------------------------------------------------

fn cggmp20_mta(c: &mut Criterion) {
    use paillier_zk::{
        paillier_affine_operation_in_range as pi_aff, paillier_encryption_in_range as pi_enc,
    };
    use tecdsa_paillier::{
        mta::{Cggmp20ProofSetup, Cggmp20Proofs, PaillierMtA, PaillierMtaSetup},
        zk::bridge::pedersen_to_aux,
    };
    type M = PaillierMtA<Cggmp20Proofs>;

    let pf = &*PAILLIER;
    let ped = &*PEDERSEN;
    let q = q_bytes();
    let q_int = Integer::from_bytes_msf(&q);

    // CGGMP20 MtA setup: Ring-Pedersen Aux (verifier's), CGGMP20 security
    // parameters (l=256, l_y=1280, epsilon=512), and the prover's Paillier key.
    let setup = PaillierMtaSetup::<Cggmp20Proofs> {
        ek: pf.ek.clone(),
        dk: pf.dk.clone(),
        proof_setup: Cggmp20ProofSetup {
            aux: pedersen_to_aux(&ped.params),
            sender_security: pi_enc::SecurityParams {
                l: 256,
                epsilon: 512,
                q: q_int.clone(),
            },
            receiver_security: pi_aff::SecurityParams {
                l_x: 256,
                l_y: 1280,
                epsilon: 512,
            },
            prover_ek: pf.ek.clone(),
        },
    };
    let a = Secp256k1::random_scalar(&mut OsRng).to_repr();
    let b = Secp256k1::random_scalar(&mut OsRng).to_repr();

    let mut g = c.benchmark_group("mta/cggmp20");
    // pi_enc / pi_aff-g proving is heavy (~10^2 ms); 10 samples matches the
    // zk/paillier_zk_facade benches and keeps total runtime bounded.
    g.sample_size(10);

    g.bench_function("sender_encrypt", |bench| {
        bench.iter(|| M::sender_encrypt(&setup, b.as_ref(), &q, &mut OsRng).expect("se"))
    });

    let (sm, ss) = M::sender_encrypt(&setup, b.as_ref(), &q, &mut OsRng).expect("se");
    g.bench_function("receiver_compute", |bench| {
        bench.iter(|| M::receiver_compute(&setup, a.as_ref(), &q, &sm, &mut OsRng).expect("rc"))
    });

    let (rm, _) = M::receiver_compute(&setup, a.as_ref(), &q, &sm, &mut OsRng).expect("rc");
    g.bench_function("sender_decrypt", |bench| {
        bench.iter(|| M::sender_decrypt(&setup, &ss, &q, &rm).expect("sd"))
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// 3. CL MtA (with WMY23-style consistency check / MtAwc)
// ---------------------------------------------------------------------------

fn cl_mta(c: &mut Criterion) {
    use std::cell::RefCell;

    use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
    use tecdsa_class_group::mta::{ClMtA, ClMtaSetup};
    use tecdsa_protocol::MtAWithCheck;
    type M = ClMtA;

    let seed = "42042";
    let setup = ClMtaSetup {
        setup: RefCell::new(
            tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl"),
        ),
        pk: {
            let mut tmp = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl");
            let (_, pk) = tmp.keygen().expect("kg");
            pk
        },
        sk: {
            let mut tmp = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl");
            let (sk, _) = tmp.keygen().expect("kg");
            sk
        },
    };
    let q = q_bytes();
    let a_scalar = Secp256k1::random_scalar(&mut OsRng);
    let b_scalar = Secp256k1::random_scalar(&mut OsRng);
    let a = a_scalar.to_repr();
    let b = b_scalar.to_repr();
    // g^a is the public auxiliary input to the MtAwc consistency check.
    let g_a = (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * a_scalar)
        .to_bytes()
        .to_vec();

    let mut g = c.benchmark_group("mta/cl");

    g.bench_function("sender_encrypt", |bench| {
        bench.iter(|| M::sender_encrypt(&setup, b.as_ref(), &q, &mut OsRng).expect("se"))
    });

    let (sm, ss) = M::sender_encrypt(&setup, b.as_ref(), &q, &mut OsRng).expect("se");
    // CL achieves malicious security via the WMY23-style MtAwc consistency
    // check (g^alpha), not a separate ZK proof; measure the check-carrying
    // receiver step (g^alpha generation) and its verification.
    g.bench_function("receiver_compute_with_check", |bench| {
        bench.iter(|| {
            M::receiver_compute_with_check(&setup, a.as_ref(), &q, &sm, &mut OsRng).expect("rcwc")
        })
    });

    let (rm, _alpha, check) =
        M::receiver_compute_with_check(&setup, a.as_ref(), &q, &sm, &mut OsRng).expect("rcwc");
    g.bench_function("sender_decrypt", |bench| {
        bench.iter(|| M::sender_decrypt(&setup, &ss, &q, &rm).expect("sd"))
    });

    let beta = M::sender_decrypt(&setup, &ss, &q, &rm).expect("sd");
    g.bench_function("verify_check", |bench| {
        bench.iter(|| M::verify_check(&setup, &ss, &q, &beta, &check, &g_a).expect("vc"))
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// 4. JL MtA
// ---------------------------------------------------------------------------

fn jl_mta(c: &mut Criterion) {
    use tecdsa_joye_libert::mta::{JlMtA, JlMtaSetup};
    type M = JlMtA;

    let (pk, sk, _) = tecdsa_joye_libert::kgen::generate_keypair_with_qnr(1680, 712, &mut OsRng);
    let (pk0, _, _) = tecdsa_joye_libert::kgen::generate_keypair_with_qnr(1680, 712, &mut OsRng);
    let setup = JlMtaSetup {
        pk,
        pk0,
        sk,
        s: 40,
        t: 40,
    };
    let q = q_bytes();
    let a = Secp256k1::random_scalar(&mut OsRng).to_repr();
    let b = Secp256k1::random_scalar(&mut OsRng).to_repr();

    let mut g = c.benchmark_group("mta/jl");

    g.bench_function("sender_encrypt", |bench| {
        bench.iter(|| M::sender_encrypt(&setup, b.as_ref(), &q, &mut OsRng).expect("se"))
    });

    let (sm, ss) = M::sender_encrypt(&setup, b.as_ref(), &q, &mut OsRng).expect("se");
    g.bench_function("receiver_compute", |bench| {
        bench.iter(|| M::receiver_compute(&setup, a.as_ref(), &q, &sm, &mut OsRng).expect("rc"))
    });

    let (rm, _) = M::receiver_compute(&setup, a.as_ref(), &q, &sm, &mut OsRng).expect("rc");
    g.bench_function("sender_decrypt", |bench| {
        bench.iter(|| M::sender_decrypt(&setup, &ss, &q, &rm).expect("sd"))
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// 5. RVOLE MtA (interactive, 4 steps)
// ---------------------------------------------------------------------------

fn rvole_mta(c: &mut Criterion) {
    use tecdsa_ot::mta::{RvoleMtA, RvoleSetup};
    use tecdsa_protocol::MtAInteractive;
    type M = RvoleMtA;

    let setup = RvoleSetup {
        session_id: b"bench-rvole".to_vec(),
    };
    let q = q_bytes();
    let a = Secp256k1::random_scalar(&mut OsRng).to_repr();
    let b = Secp256k1::random_scalar(&mut OsRng).to_repr();

    let mut g = c.benchmark_group("mta/rvole");

    g.bench_function("sender_init", |bench| {
        bench.iter(|| M::sender_init(&setup, &mut OsRng).expect("init"))
    });

    let (init_msg, _) = M::sender_init(&setup, &mut OsRng).expect("init");
    g.bench_function("receiver_respond", |bench| {
        bench.iter(|| {
            M::receiver_respond(&setup, b.as_ref(), &q, &init_msg, &mut OsRng).expect("respond")
        })
    });

    g.bench_function("sender_compute", |bench| {
        bench.iter(|| {
            let (im, ss) = M::sender_init(&setup, &mut OsRng).expect("init");
            let (rm, _) =
                M::receiver_respond(&setup, b.as_ref(), &q, &im, &mut OsRng).expect("resp");
            M::sender_compute(ss, a.as_ref(), &q, &rm).expect("compute")
        })
    });

    g.bench_function("full_cycle", |bench| {
        bench.iter(|| {
            let (im, ss) = M::sender_init(&setup, &mut OsRng).expect("init");
            let (rm, rs) =
                M::receiver_respond(&setup, b.as_ref(), &q, &im, &mut OsRng).expect("resp");
            let (cm, _) = M::sender_compute(ss, a.as_ref(), &q, &rm).expect("compute");
            M::receiver_finish(rs, &cm, &q).expect("finish")
        })
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// 6. NIM (non-interactive multiplication)
// ---------------------------------------------------------------------------

fn nim_mta(c: &mut Criterion) {
    use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
    use tecdsa_class_group::{nim::Nim, zk::r_ped_ec::RPedEcProof};

    let seed = "42042";
    let mut nim_setup = tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(seed).expect("cl");
    let (_, nim_pk) = nim_setup.keygen().expect("nim keygen");
    let x_scalar = Secp256k1::random_scalar(&mut OsRng);
    let x = tecdsa_curve::conv::scalar_to_bytes(&x_scalar);
    let y = tecdsa_curve::conv::scalar_to_bytes(&Secp256k1::random_scalar(&mut OsRng));
    // V = x * G is the EC commitment that R_Ped binds the Encode_A output to.
    let big_v = (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * x_scalar)
        .to_bytes()
        .to_vec();

    let mut g = c.benchmark_group("mta/nim");

    g.bench_function("encode_a", |bench| {
        bench.iter(|| {
            let mut nim = Nim::new(&mut nim_setup);
            nim.encode_a(&x, &nim_pk).expect("encode_a")
        })
    });

    g.bench_function("encode_b", |bench| {
        bench.iter(|| {
            let mut nim = Nim::new(&mut nim_setup);
            nim.encode_b(&y, &nim_pk).expect("encode_b")
        })
    });

    let ea = {
        let mut nim = Nim::new(&mut nim_setup);
        nim.encode_a(&x, &nim_pk).expect("encode_a")
    };
    let eb = {
        let mut nim = Nim::new(&mut nim_setup);
        nim.encode_b(&y, &nim_pk).expect("encode_b")
    };
    let r_bytes = ea.state.r_bytes.clone();

    // R_Ped (R_Ped_EC, LLZ25 §4.3): proves the Encode_A output
    // pe_A = h^r * pk^x is consistent with V = x*G. Party A proves; the
    // counterparty verifies. This is what makes NIM maliciously secure.
    g.bench_function("r_ped/prove", |bench| {
        bench.iter(|| {
            RPedEcProof::prove(&mut nim_setup, &nim_pk, &ea.pe_a, &big_v, &x, &r_bytes)
                .expect("r_ped prove")
        })
    });

    let ped_proof = RPedEcProof::prove(&mut nim_setup, &nim_pk, &ea.pe_a, &big_v, &x, &r_bytes)
        .expect("r_ped prove");
    g.bench_function("r_ped/verify", |bench| {
        bench.iter(|| {
            ped_proof
                .verify(&nim_setup, &nim_pk, &ea.pe_a, &big_v)
                .expect("r_ped verify")
        })
    });

    g.bench_function("decode_a", |bench| {
        bench.iter(|| {
            let nim = Nim::new(&mut nim_setup);
            nim.decode_a(&eb.pe_b, &ea.state).expect("decode_a")
        })
    });

    g.bench_function("decode_b", |bench| {
        bench.iter(|| {
            let nim = Nim::new(&mut nim_setup);
            nim.decode_b(&ea.pe_a, &eb.state).expect("decode_b")
        })
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// Criterion groups and main
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    paillier_mta,
    cggmp20_mta,
    cl_mta,
    jl_mta,
    rvole_mta,
    nim_mta,
);
criterion_main!(benches);
