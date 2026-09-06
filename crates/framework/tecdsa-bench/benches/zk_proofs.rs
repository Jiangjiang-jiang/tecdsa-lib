// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof microbenchmarks: prove + verify for every proof relation.
//!
//! Every fixture is validated with `assert!` before timing.
//! Naming follows `docs/superpowers/plans/2026-06-02-zk-proof-benchmarks.md`.

use std::{str::FromStr, sync::LazyLock};

use criterion::{criterion_group, criterion_main, Criterion};
use k256::Secp256k1;
use rand::thread_rng;
use rug::{integer::Order, Complete, Integer};
use tecdsa::bigint::random_below;
use tecdsa_bench::zk_fixtures::*;
use tecdsa_class_group::cl::{Cleartext, Mpz, SECP256K1_ORDER};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::BigIntExt;

static PAILLIER: LazyLock<PaillierFixture> = LazyLock::new(PaillierFixture::generate);
static NTILDE: LazyLock<NTildeFixture> = LazyLock::new(NTildeFixture::generate);
static PEDERSEN: LazyLock<PedersenFixture> = LazyLock::new(PedersenFixture::generate);
static JL: LazyLock<JlFixture> = LazyLock::new(JlFixture::generate);
static JL_EXTRA: LazyLock<JlExtraFixture> = LazyLock::new(JlExtraFixture::generate);

// ═══════════════════════════════════════════════════════════════════════
// 1. Curve ZK
// ═══════════════════════════════════════════════════════════════════════

fn curve_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/curve");
    let rng = &mut thread_rng();

    // DlogProof
    {
        use tecdsa_curve::zk::dlog::DlogProof;
        let x = C::random_scalar(rng);
        let p = C::generator() * x;
        let r = C::random_scalar(rng);
        let proof = DlogProof::<C>::prove(&x, &r, &p, b"bench");
        assert!(proof.verify(&p, b"bench"), "DlogProof fixture invalid");
        g.bench_function("dlog/prove", |b| {
            b.iter(|| DlogProof::<C>::prove(&x, &C::random_scalar(rng), &p, b"bench"))
        });
        g.bench_function("dlog/verify", |b| b.iter(|| proof.verify(&p, b"bench")));
    }

    // DdhProof
    {
        use tecdsa_curve::zk::ddh::{DdhProof, DdhStatement, DdhWitness};
        let w = C::random_scalar(rng);
        let gen = C::generator();
        let a = gen * C::random_scalar(rng);
        let b_pt = gen * w;
        let c_pt = a * w;
        let stmt = DdhStatement::<C> {
            g: gen,
            a,
            b: b_pt,
            c: c_pt,
        };
        let wit = DdhWitness::<C> { w };
        let proof = DdhProof::prove(&stmt, &wit, rng);
        assert!(proof.verify(&stmt), "DdhProof fixture invalid");
        g.bench_function("ddh/prove", |b| {
            b.iter(|| DdhProof::prove(&stmt, &wit, rng))
        });
        g.bench_function("ddh/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // EgexpProof
    {
        use tecdsa_curve::zk::egexp::{EgexpProof, EgexpStatement, EgexpWitness};
        let dk = C::random_scalar(rng);
        let pk = C::generator() * dk;
        let x = C::random_scalar(rng);
        let r = C::random_scalar(rng);
        let a = C::generator() * r;
        let b_pt = pk * r + C::generator() * x;
        let stmt = EgexpStatement::<C> { p: pk, a, b: b_pt };
        let wit = EgexpWitness::<C> { x, r };
        let proof = EgexpProof::prove(&stmt, &wit, rng);
        assert!(proof.verify(&stmt), "EgexpProof fixture invalid");
        g.bench_function("egexp/prove", |b| {
            b.iter(|| EgexpProof::prove(&stmt, &wit, rng))
        });
        g.bench_function("egexp/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // ProdProof — relation: C=tG, D=tP+yG, E=yA+rG, F=yB+rP
    {
        use tecdsa_curve::zk::prod::{ProdProof, ProdStatement, ProdWitness};
        let gen = C::generator();
        let dk = C::random_scalar(rng);
        let pk = gen * dk;
        let alpha = C::random_scalar(rng);
        let a = gen * alpha;
        let b_pt = pk * alpha;
        let y = C::random_scalar(rng);
        let t = C::random_scalar(rng);
        let r = C::random_scalar(rng);
        let c_pt = gen * t;
        let d = pk * t + gen * y;
        let e_pt = a * y + gen * r;
        let f_pt = b_pt * y + pk * r;
        let stmt = ProdStatement::<C> {
            p: pk,
            a,
            b: b_pt,
            c: c_pt,
            d,
            e_pt,
            f: f_pt,
        };
        let wit = ProdWitness::<C> { y, t, r };
        let proof = ProdProof::prove(&stmt, &wit, rng);
        assert!(proof.verify(&stmt), "ProdProof fixture invalid");
        g.bench_function("prod/prove", |b| {
            b.iter(|| ProdProof::prove(&stmt, &wit, rng))
        });
        g.bench_function("prod/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // ReProof — relation: A'=rG+sA, B'=rP+sB
    {
        use tecdsa_curve::zk::rerandom::{ReProof, ReStatement, ReWitness};
        let gen = C::generator();
        let p_pt = C::nums_pedersen_h();
        let r = C::random_scalar(rng);
        let s = C::random_scalar(rng);
        let a = gen * C::random_scalar(rng);
        let b_pt = p_pt * C::random_scalar(rng);
        let a_prime = gen * r + a * s;
        let b_prime = p_pt * r + b_pt * s;
        let stmt = ReStatement::<C> {
            g: gen,
            p: p_pt,
            a,
            b: b_pt,
            a_prime,
            b_prime,
        };
        let wit = ReWitness::<C> { r, s };
        let sigma = C::random_scalar(rng);
        let tau = C::random_scalar(rng);
        let proof = ReProof::prove(&stmt, &wit, &sigma, &tau);
        assert!(proof.verify(&stmt), "ReProof fixture invalid");
        g.bench_function("rerandom/prove", |b| {
            b.iter(|| {
                let s = C::random_scalar(rng);
                let t = C::random_scalar(rng);
                ReProof::prove(&stmt, &wit, &s, &t)
            })
        });
        g.bench_function("rerandom/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Pedersen-mod ZK (Pi_prm, Pi_mod) — Profile B: 1536-bit primes
// ═══════════════════════════════════════════════════════════════════════

fn pedersen_mod_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/pedersen_mod");
    g.sample_size(10);
    let rng = &mut thread_rng();

    use tecdsa_pedersen_mod::zk::PiPrm;

    let ped = &*PEDERSEN;
    let params = &ped.params;
    let secret = &ped.secret;

    let piprm_proof = PiPrm::prove(params, secret, rng);
    assert!(piprm_proof.verify(params), "PiPrm fixture invalid");
    g.bench_function("pi_prm/prove", |b| {
        b.iter(|| PiPrm::prove(params, secret, rng))
    });
    g.bench_function("pi_prm/verify", |b| b.iter(|| piprm_proof.verify(params)));

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 3. Class-group ZK
// ═══════════════════════════════════════════════════════════════════════

fn class_group_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/class_group");
    let rng = &mut thread_rng();

    let (mut setup, sk, pk) = cl_setup_with_keys();
    let sk_bytes = setup.sk_to_bytes(&sk).expect("sk_bytes");
    let m_bytes = 42u32.to_be_bytes().to_vec();

    // R_enc
    {
        use tecdsa_class_group::zk::r_enc::REncProof;
        let (r_sk, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_bytes)
            .expect("enc");
        let proof =
            REncProof::prove(&mut setup, &pk, &ct, &m_bytes, &r_bytes).expect("r_enc prove");
        assert!(
            proof.verify(&setup, &pk, &ct).expect("verify"),
            "REncProof fixture invalid"
        );
        g.bench_function("r_enc/prove", |b| {
            b.iter(|| REncProof::prove(&mut setup, &pk, &ct, &m_bytes, &r_bytes))
        });
        g.bench_function("r_enc/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct))
        });
    }

    // R_key
    {
        use tecdsa_class_group::zk::r_key::RKeyProof;
        let proof = RKeyProof::prove(&mut setup, &pk, &sk_bytes).expect("r_key prove");
        assert!(
            proof.verify(&setup, &pk).expect("verify"),
            "RKeyProof fixture invalid"
        );
        g.bench_function("r_key/prove", |b| {
            b.iter(|| RKeyProof::prove(&mut setup, &pk, &sk_bytes))
        });
        g.bench_function("r_key/verify", |b| b.iter(|| proof.verify(&setup, &pk)));
    }

    // R_dl_cl
    {
        use tecdsa_class_group::zk::r_dl_cl::RDlClProof;
        let x_scalar = C::random_scalar(rng);
        let x_bytes = scalar_to_bytes(&x_scalar);
        let x_point =
            <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR * x_scalar;
        let ct = setup.encrypt_bytes(&pk, &x_bytes).expect("enc");
        let (c1, c2) = setup.ct_components(&ct).expect("comp");
        let c1_x = setup.exp_bytes(&c1, &x_bytes).expect("exp");
        let c2_x = setup.exp_bytes(&c2, &x_bytes).expect("exp");
        let ct_x = setup.ct_from_components(&c1_x, &c2_x).expect("ct_from");
        let proof = RDlClProof::prove(&mut setup, &x_point, &ct, &ct_x, &x_bytes).expect("prove");
        assert!(
            proof.verify(&setup, &x_point, &ct, &ct_x).expect("verify"),
            "RDlClProof fixture invalid"
        );
        g.bench_function("r_dl_cl/prove", |b| {
            b.iter(|| RDlClProof::prove(&mut setup, &x_point, &ct, &ct_x, &x_bytes))
        });
        g.bench_function("r_dl_cl/verify", |b| {
            b.iter(|| proof.verify(&setup, &x_point, &ct, &ct_x))
        });
    }

    // R_enc_pc (cross-domain)
    {
        use elliptic_curve::group::GroupEncoding;
        use tecdsa_class_group::zk::r_enc_pc::REncPcProof;
        let (r_sk, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_bytes)
            .expect("enc");
        // EC Pedersen commitment: PC = g^m * h^{m'} (m' = m for simplicity)
        let m_scalar = {
            use elliptic_curve::ops::Reduce;
            let mut buf = [0u8; 32];
            let len = m_bytes.len().min(32);
            buf[32 - len..].copy_from_slice(&m_bytes[m_bytes.len() - len..]);
            let uint = k256::U256::from_be_slice(&buf);
            k256::Scalar::reduce(&uint)
        };
        let g_ec = k256::ProjectivePoint::GENERATOR;
        let h_ec = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();
        let pc = g_ec * m_scalar + h_ec * m_scalar;
        let pc_bytes = pc.to_bytes();
        let proof = REncPcProof::prove(
            &mut setup,
            &pk,
            &ct,
            pc_bytes.as_ref(),
            &m_bytes,
            &m_bytes,
            &r_bytes,
        )
        .expect("prove");
        assert!(
            proof
                .verify(&setup, &pk, &ct, pc_bytes.as_ref())
                .expect("verify"),
            "REncPcProof fixture invalid"
        );
        g.bench_function("r_enc_pc/prove", |b| {
            b.iter(|| {
                REncPcProof::prove(
                    &mut setup,
                    &pk,
                    &ct,
                    pc_bytes.as_ref(),
                    &m_bytes,
                    &m_bytes,
                    &r_bytes,
                )
            })
        });
        g.bench_function("r_enc_pc/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct, pc_bytes.as_ref()))
        });
    }

    // R_pc_dl
    {
        use tecdsa_class_group::zk::r_pc_dl::RPcDlProof;
        let y = setup.power_of_f_bytes(&m_bytes).expect("f^m");
        let proof = RPcDlProof::prove(&mut setup, &y, &m_bytes).expect("prove");
        assert!(
            proof.verify(&setup, &y).expect("verify"),
            "RPcDlProof fixture invalid"
        );
        g.bench_function("r_pc_dl/prove", |b| {
            b.iter(|| RPcDlProof::prove(&mut setup, &y, &m_bytes))
        });
        g.bench_function("r_pc_dl/verify", |b| b.iter(|| proof.verify(&setup, &y)));
    }

    // R_dec_dl
    {
        use tecdsa_class_group::zk::r_dec_dl::RDecDlProof;
        let (r_sk, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_bytes)
            .expect("enc");
        let (c1, _c2) = setup.ct_components(&ct).expect("comp");
        let pd = setup.exp_bytes(&c1, &sk_bytes).expect("pd");
        let proof = RDecDlProof::prove(&mut setup, &pk, &ct, &pd, &sk_bytes).expect("prove");
        assert!(
            proof.verify(&setup, &pk, &ct, &pd).expect("verify"),
            "RDecDlProof fixture invalid"
        );
        g.bench_function("r_dec_dl/prove", |b| {
            b.iter(|| RDecDlProof::prove(&mut setup, &pk, &ct, &pd, &sk_bytes))
        });
        g.bench_function("r_dec_dl/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct, &pd))
        });
    }

    // R_cl_kwlg
    {
        use tecdsa_class_group::zk::r_cl_kwlg::RClKwlgProof;
        let proof = RClKwlgProof::prove(&mut setup, &pk, &sk_bytes).expect("prove");
        assert!(
            proof.verify(&setup, &pk).expect("verify"),
            "RClKwlgProof fixture invalid"
        );
        g.bench_function("r_cl_kwlg/prove", |b| {
            b.iter(|| RClKwlgProof::prove(&mut setup, &pk, &sk_bytes))
        });
        g.bench_function("r_cl_kwlg/verify", |b| b.iter(|| proof.verify(&setup, &pk)));
    }

    // R_bint
    {
        use tecdsa_class_group::zk::r_bint::RBintProof;
        let x_bytes = 42u32.to_be_bytes().to_vec();
        let y = setup.power_of_h("42").expect("h^x");
        let proof = RBintProof::prove(&mut setup, &y, &x_bytes).expect("prove");
        let bound = setup.secretkey_bound_bytes().expect("bound");
        assert!(
            proof.verify(&setup, &y, &bound).expect("verify"),
            "RBintProof fixture invalid"
        );
        g.bench_function("r_bint/prove", |b| {
            b.iter(|| RBintProof::prove(&mut setup, &y, &x_bytes))
        });
        g.bench_function("r_bint/verify", |b| {
            b.iter(|| proof.verify(&setup, &y, &bound))
        });
    }

    // R_com_kwlg
    {
        use tecdsa_class_group::zk::r_com_kwlg::RComKwlgProof;
        let (r_sk2, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk2).expect("r_bytes");
        let fm = setup.power_of_f_bytes(&m_bytes).expect("f^m");
        let hr = setup.power_of_h_bytes(&r_bytes).expect("h^r");
        let commit = setup.compose(&fm, &hr).expect("compose");
        let proof = RComKwlgProof::prove(&mut setup, &commit, &m_bytes, &r_bytes).expect("prove");
        assert!(
            proof.verify(&setup, &commit).expect("verify"),
            "RComKwlgProof fixture invalid"
        );
        g.bench_function("r_com_kwlg/prove", |b| {
            b.iter(|| RComKwlgProof::prove(&mut setup, &commit, &m_bytes, &r_bytes))
        });
        g.bench_function("r_com_kwlg/verify", |b| {
            b.iter(|| proof.verify(&setup, &commit))
        });
    }

    // R_gdec_cl
    {
        use tecdsa_class_group::zk::r_gdec_cl::RGdecClProof;
        let sk_dec = sk.to_string();
        let ct = setup.encrypt(&pk, "42").expect("encrypt");
        let (c1, c2) = setup.ct_components(&ct).expect("comp");
        let mut c1_sk = setup.exp(&c1, &sk_dec).expect("c1^sk");
        c1_sk.neg();
        let dec_result = setup.compose(&c2, &c1_sk).expect("dec");
        let proof =
            RGdecClProof::prove(&mut setup, &pk, &ct, &dec_result, &sk_bytes).expect("prove");
        assert!(
            proof.verify(&setup, &pk, &ct, &dec_result).expect("verify"),
            "RGdecClProof fixture invalid"
        );
        g.bench_function("r_gdec_cl/prove", |b| {
            b.iter(|| RGdecClProof::prove(&mut setup, &pk, &ct, &dec_result, &sk_bytes))
        });
        g.bench_function("r_gdec_cl/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct, &dec_result))
        });
    }

    // R_cl_dl — prove knowledge of plaintext + randomness with F-subgroup
    {
        use tecdsa_class_group::zk::r_cl_dl::RClDlProof;
        let x_bytes = 77u32.to_be_bytes().to_vec();
        let (r_sk2, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk2).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &x_bytes, &r_bytes)
            .expect("enc");
        let y = setup.power_of_f_bytes(&x_bytes).expect("f^x");
        let proof = RClDlProof::prove(&mut setup, &pk, &ct, &y, &x_bytes, &r_bytes).expect("prove");
        assert!(
            proof.verify(&setup, &pk, &ct, &y).expect("verify"),
            "RClDlProof fixture invalid"
        );
        g.bench_function("r_cl_dl/prove", |b| {
            b.iter(|| RClDlProof::prove(&mut setup, &pk, &ct, &y, &x_bytes, &r_bytes))
        });
        g.bench_function("r_cl_dl/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct, &y))
        });
    }

    // R_cl_dl_ec — CL encryption + EC discrete-log
    {
        use elliptic_curve::group::GroupEncoding;
        use tecdsa_class_group::zk::r_cl_dl_ec::RClDlEcProof;
        let v_bytes = 42u32.to_be_bytes().to_vec();
        let (r_sk2, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk2).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &v_bytes, &r_bytes)
            .expect("enc");
        let v_scalar = tecdsa_curve::conv::bytes_to_scalar::<Secp256k1>(&v_bytes);
        let big_v =
            <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR * v_scalar;
        let big_v_bytes = big_v.to_bytes().to_vec();
        let proof = RClDlEcProof::prove(&mut setup, &pk, &ct, &big_v_bytes, &v_bytes, &r_bytes)
            .expect("prove");
        assert!(
            proof
                .verify(&setup, &pk, &ct, &big_v_bytes)
                .expect("verify"),
            "RClDlEcProof fixture invalid"
        );
        g.bench_function("r_cl_dl_ec/prove", |b| {
            b.iter(|| RClDlEcProof::prove(&mut setup, &pk, &ct, &big_v_bytes, &v_bytes, &r_bytes))
        });
        g.bench_function("r_cl_dl_ec/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct, &big_v_bytes))
        });
    }

    // R_ddh_cl — DDH tuple in class group
    {
        use tecdsa_class_group::zk::r_ddh_cl::RDdhClProof;
        let x_bytes = 42u32.to_be_bytes().to_vec();
        let g_qfi = setup.power_of_h("1").expect("h");
        let x_dec = "42";
        let a = setup.exp(&g_qfi, x_dec).expect("g^x");
        let (r_sk2, _) = setup.keygen().expect("keygen");
        let r_dec = r_sk2.to_string();
        let b_qfi = setup.exp(&g_qfi, &r_dec).expect("h^r");
        let c_qfi = setup.exp(&b_qfi, x_dec).expect("B^x");
        let proof =
            RDdhClProof::prove(&mut setup, &g_qfi, &a, &b_qfi, &c_qfi, &x_bytes).expect("prove");
        assert!(
            proof
                .verify(&setup, &g_qfi, &a, &b_qfi, &c_qfi)
                .expect("verify"),
            "RDdhClProof fixture invalid"
        );
        g.bench_function("r_ddh_cl/prove", |b| {
            b.iter(|| RDdhClProof::prove(&mut setup, &g_qfi, &a, &b_qfi, &c_qfi, &x_bytes))
        });
        g.bench_function("r_ddh_cl/verify", |b| {
            b.iter(|| proof.verify(&setup, &g_qfi, &a, &b_qfi, &c_qfi))
        });
    }

    // R_el_cl — ElGamal + CL scalar multiply
    {
        use tecdsa_class_group::zk::r_el_cl::RElClProof;
        let gen = <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR;
        let eldk = k256::Scalar::from(42u64);
        let elek = gen * eldk;
        let gamma_bytes = 17u32.to_be_bytes().to_vec();
        let r_ec_bytes = 23u32.to_be_bytes().to_vec();
        let gamma_scalar = k256::Scalar::from(17u64);
        let r_scalar = k256::Scalar::from(23u64);
        let elg_0 = gen * r_scalar;
        let elg_1 = gen * gamma_scalar + elek * r_scalar;
        let ct = setup.encrypt_bytes(&pk, &55u32.to_be_bytes()).expect("enc");
        let (ck_0, ck_1) = setup.ct_components(&ct).expect("comp");
        let cgk_0 = setup.exp_bytes(&ck_0, &gamma_bytes).expect("exp");
        let cgk_1 = setup.exp_bytes(&ck_1, &gamma_bytes).expect("exp");
        let proof = RElClProof::prove(
            &mut setup,
            &gen,
            &elek,
            &elg_0,
            &elg_1,
            &ck_0,
            &ck_1,
            &cgk_0,
            &cgk_1,
            &gamma_bytes,
            &r_ec_bytes,
        )
        .expect("prove");
        assert!(
            proof
                .verify(&setup, &gen, &elek, &elg_0, &elg_1, &ck_0, &ck_1, &cgk_0, &cgk_1)
                .expect("verify"),
            "RElClProof fixture invalid"
        );
        g.bench_function("r_el_cl/prove", |b| {
            b.iter(|| {
                RElClProof::prove(
                    &mut setup,
                    &gen,
                    &elek,
                    &elg_0,
                    &elg_1,
                    &ck_0,
                    &ck_1,
                    &cgk_0,
                    &cgk_1,
                    &gamma_bytes,
                    &r_ec_bytes,
                )
            })
        });
        g.bench_function("r_el_cl/verify", |b| {
            b.iter(|| {
                proof.verify(
                    &setup, &gen, &elek, &elg_0, &elg_1, &ck_0, &ck_1, &cgk_0, &cgk_1,
                )
            })
        });
    }

    // R_ped_ec — Pedersen CL commitment + EC point
    {
        use elliptic_curve::group::GroupEncoding as _;
        use tecdsa_class_group::{nim::Nim, zk::r_ped_ec::RPedEcProof};
        let x_bytes = 42u32.to_be_bytes().to_vec();
        let mut nim = Nim::new(&mut setup);
        let encode_out = nim.encode_a(&x_bytes, &pk).expect("encode_a");
        let pe_a = encode_out.pe_a;
        let r_bytes_nim = encode_out.state.r_bytes.clone();
        let x_scalar = tecdsa_curve::conv::bytes_to_scalar::<Secp256k1>(&x_bytes);
        let big_v =
            <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR * x_scalar;
        let big_v_bytes = big_v.to_bytes().to_vec();
        let proof =
            RPedEcProof::prove(&mut setup, &pk, &pe_a, &big_v_bytes, &x_bytes, &r_bytes_nim)
                .expect("prove");
        assert!(
            proof
                .verify(&setup, &pk, &pe_a, &big_v_bytes)
                .expect("verify"),
            "RPedEcProof fixture invalid"
        );
        g.bench_function("r_ped_ec/prove", |b| {
            b.iter(|| {
                RPedEcProof::prove(&mut setup, &pk, &pe_a, &big_v_bytes, &x_bytes, &r_bytes_nim)
            })
        });
        g.bench_function("r_ped_ec/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &pe_a, &big_v_bytes))
        });
    }

    // R_aff_com — affine operation with commitment
    {
        use tecdsa_class_group::zk::r_aff_com::RAffComProof;
        let x_bytes = 5u32.to_be_bytes().to_vec();
        let y_bytes = 10u32.to_be_bytes().to_vec();
        let (r_sk2, _) = setup.keygen().expect("kg");
        let ct_in = setup.cl().encrypt_with_randomness(
            &pk,
            &Cleartext::from_mpz(setup.cl(), Mpz::from_str("100").expect("enc")).expect("enc"),
            &r_sk2,
        );
        let (r_sk3, _) = setup.keygen().expect("kg");
        let r1 = setup.sk_to_bytes(&r_sk3).expect("bytes");
        let q_bu = Mpz::from_str(SECP256K1_ORDER).unwrap();
        let m_out = (Mpz::from(5u32) * Mpz::from(100u32) + Mpz::from(10u32)).modulo(&q_bu);
        let r_out = Mpz::from(5u32) * r_sk2.as_mpz() + r_sk3.as_mpz();
        let ct_out = setup.cl().encrypt_with_randomness(
            &pk,
            &Cleartext::from_mpz(setup.cl(), m_out).unwrap(),
            &r_out,
        );
        let (r_sk4, _) = setup.keygen().expect("kg");
        let r2 = setup.sk_to_bytes(&r_sk4).expect("bytes");
        let r2_dec = Mpz::from_bytes_be(&r2);
        let h_r2 = setup.cl().power_of_h(&r2_dec);
        let f_x = setup.power_of_f("5").expect("f_x");
        let commitment = setup.compose(&h_r2, &f_x).expect("com");
        let proof = RAffComProof::prove(
            &mut setup,
            &pk,
            &ct_in,
            &ct_out,
            &commitment,
            &x_bytes,
            &y_bytes,
            &r1,
            &r2,
        )
        .expect("prove");
        assert!(
            proof
                .verify(&setup, &pk, &ct_in, &ct_out, &commitment)
                .expect("verify"),
            "RAffComProof fixture invalid"
        );
        g.bench_function("r_aff_com/prove", |b| {
            b.iter(|| {
                RAffComProof::prove(
                    &mut setup,
                    &pk,
                    &ct_in,
                    &ct_out,
                    &commitment,
                    &x_bytes,
                    &y_bytes,
                    &r1,
                    &r2,
                )
            })
        });
        g.bench_function("r_aff_com/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct_in, &ct_out, &commitment))
        });
    }

    // R_m_aff_dl — MtA affine DL with F-subgroup
    {
        use tecdsa_class_group::zk::r_m_aff_dl::RMAffDlProof;
        let x_bytes = 3u32.to_be_bytes().to_vec();
        let y_bytes = 7u32.to_be_bytes().to_vec();
        let (r_sk2, _) = setup.keygen().expect("kg");
        let r_base = setup.sk_to_bytes(&r_sk2).expect("bytes");
        let (r_sk3, _) = setup.keygen().expect("kg");
        let r_enc = setup.sk_to_bytes(&r_sk3).expect("bytes");
        let r_base_dec = Mpz::from_bytes_be(&r_base);
        let ct_in = setup.cl().encrypt_with_randomness(
            &pk,
            &Cleartext::from_mpz(setup.cl(), Mpz::from_str("100").unwrap()).unwrap(),
            &r_base_dec,
        );
        let q_bu = Mpz::from_str(tecdsa_class_group::cl::SECP256K1_ORDER).unwrap();
        let m_out = (Mpz::from(3u32) * Mpz::from(100u32) + Mpz::from(7u32)).modulo(&q_bu);
        let r_out = Mpz::from(3u32) * Mpz::from_bytes_be(&r_base) + Mpz::from_bytes_be(&r_enc);
        let ct_out = setup.cl().encrypt_with_randomness(
            &pk,
            &Cleartext::from_mpz(setup.cl(), m_out).unwrap(),
            &r_out,
        );
        let y_point = setup.power_of_f("7").expect("f^y");
        let proof = RMAffDlProof::prove(
            &mut setup, &pk, &ct_in, &ct_out, &y_point, &x_bytes, &y_bytes, &r_enc,
        )
        .expect("prove");
        assert!(
            proof
                .verify(&setup, &pk, &ct_in, &ct_out, &y_point)
                .expect("verify"),
            "RMAffDlProof fixture invalid"
        );
        g.bench_function("r_m_aff_dl/prove", |b| {
            b.iter(|| {
                RMAffDlProof::prove(
                    &mut setup, &pk, &ct_in, &ct_out, &y_point, &x_bytes, &y_bytes, &r_enc,
                )
            })
        });
        g.bench_function("r_m_aff_dl/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct_in, &ct_out, &y_point))
        });
    }

    // R_m_aff_dl_ec — MtA affine DL with EC checks
    {
        use tecdsa_class_group::zk::r_m_aff_dl_ec::RMAffDlEcProof;
        let gamma_bytes = 42u32.to_be_bytes().to_vec();
        let (r_sk2, _) = setup.keygen().expect("kg");
        let r_gamma = setup.sk_to_bytes(&r_sk2).expect("r");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &gamma_bytes, &r_gamma)
            .expect("enc");
        let (c1, c2) = setup.ct_components(&ct).expect("ct");
        let (r_sk3, _) = setup.keygen().expect("kg");
        let k_star = setup.sk_to_bytes(&r_sk3).expect("k");
        let beta_bytes = 17u32.to_be_bytes().to_vec();
        let q_bytes = setup.q_bytes().expect("q");
        let d1 = setup.exp_bytes(&c1, &k_star).expect("d1");
        let c2_k = setup.exp_bytes(&c2, &k_star).expect("c2k");
        // negate_mod_q inlined
        let q_bu = Mpz::from_bytes_be(&q_bytes);
        let beta_bu = Mpz::from_bytes_be(&beta_bytes);
        let neg_beta_bu = (&q_bu - &beta_bu.modulo(&q_bu)).modulo(&q_bu);
        let neg_beta = neg_beta_bu.to_bytes_be();
        let f_neg_beta = setup.power_of_f_bytes(&neg_beta).expect("f^-b");
        let d2 = setup.compose(&c2_k, &f_neg_beta).expect("d2");
        let k_scalar = tecdsa_curve::conv::bytes_to_scalar::<Secp256k1>(&k_star);
        let r_point =
            <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR * k_scalar;
        let beta_scalar = k256::Scalar::from(17u64);
        let b_point = <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR
            * beta_scalar;
        let proof = RMAffDlEcProof::prove(
            &mut setup,
            &c1,
            &c2,
            &d1,
            &d2,
            &r_point,
            &b_point,
            &k_star,
            &beta_bytes,
        )
        .expect("prove");
        assert!(
            proof
                .verify(&setup, &c1, &c2, &d1, &d2, &r_point, &b_point)
                .expect("verify"),
            "RMAffDlEcProof fixture invalid"
        );
        g.bench_function("r_m_aff_dl_ec/prove", |b| {
            b.iter(|| {
                RMAffDlEcProof::prove(
                    &mut setup,
                    &c1,
                    &c2,
                    &d1,
                    &d2,
                    &r_point,
                    &b_point,
                    &k_star,
                    &beta_bytes,
                )
            })
        });
        g.bench_function("r_m_aff_dl_ec/verify", |b| {
            b.iter(|| proof.verify(&setup, &c1, &c2, &d1, &d2, &r_point, &b_point))
        });
    }

    // R_sh — PVSS share consistency
    {
        use tecdsa_class_group::zk::r_sh::RShProof;
        let n = 3u16;
        let t = 2u16;
        let mut pks = Vec::new();
        for _ in 0..n {
            let (_, pk_i) = setup.keygen().expect("keygen");
            pks.push(pk_i);
        }
        let party_ids: Vec<u16> = (1..=n).collect();
        let pk_refs: Vec<&_> = pks.iter().collect();
        // Inline create_pvss_ciphertexts
        let q_bu = setup.cl().q().clone().into_inner();
        let (rho_sk, _) = setup.keygen().expect("kg");
        let rho_bytes = setup.sk_to_bytes(&rho_sk).expect("rho");
        let c1_sh = setup.power_of_h_bytes(&rho_bytes).expect("h^rho");
        let mut coeffs = Vec::new();
        for _ in 0..t {
            let (sk_c, _) = setup.keygen().expect("kg");
            let c_bytes = setup.sk_to_bytes(&sk_c).expect("c");
            coeffs.push(Integer::from_digits(&c_bytes, Order::Msf).modulo(&q_bu));
        }
        let mut c2s_sh = Vec::new();
        for (idx, &id) in party_ids.iter().enumerate() {
            let x = Integer::from(id);
            let mut val = Integer::ZERO;
            let mut x_pow = Integer::from(1u32);
            for coeff in &coeffs {
                val = (val + coeff * &x_pow).modulo(&q_bu);
                x_pow = (x_pow * &x).modulo(&q_bu);
            }
            let share_bytes = val.to_digits(Order::Msf);
            let pk_elt = pks[idx].elt();
            let pk_rho = setup.exp_bytes(pk_elt, &rho_bytes).expect("pk^rho");
            let f_v = setup.power_of_f_bytes(&share_bytes).expect("f^v");
            let c2 = setup.compose(&pk_rho, &f_v).expect("compose");
            c2s_sh.push(c2);
        }
        let c2_refs: Vec<&_> = c2s_sh.iter().collect();
        let proof = RShProof::prove(
            &mut setup, &party_ids, t, &pk_refs, &c1_sh, &c2_refs, &rho_bytes,
        )
        .expect("prove");
        assert!(
            proof
                .verify(&setup, &party_ids, t, &pk_refs, &c1_sh, &c2_refs)
                .expect("verify"),
            "RShProof fixture invalid"
        );
        g.bench_function("r_sh/prove", |b| {
            b.iter(|| {
                RShProof::prove(
                    &mut setup, &party_ids, t, &pk_refs, &c1_sh, &c2_refs, &rho_bytes,
                )
            })
        });
        g.bench_function("r_sh/verify", |b| {
            b.iter(|| proof.verify(&setup, &party_ids, t, &pk_refs, &c1_sh, &c2_refs))
        });
    }

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 4. Paillier self-authored ZK
// ═══════════════════════════════════════════════════════════════════════

fn paillier_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/paillier");
    g.sample_size(10);
    let rng = &mut thread_rng();

    let pf = &*PAILLIER;
    let dk = &pf.dk;
    let ek = &pf.ek;

    // correct_key_ni
    {
        use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
        let proof = NICorrectKeyProof::prove(dk, b"bench");
        assert!(
            proof.verify(ek, b"bench"),
            "NICorrectKeyProof fixture invalid"
        );
        g.bench_function("correct_key_ni/prove", |b| {
            b.iter(|| NICorrectKeyProof::prove(dk, b"bench"))
        });
        g.bench_function("correct_key_ni/verify", |b| {
            b.iter(|| proof.verify(ek, b"bench"))
        });
    }

    // homo_elgamal — relation: D = xH + rY, E = rG
    {
        use tecdsa_paillier::zk::homo_elgamal::{
            HomoElGamalProof, HomoElGamalStatement, HomoElGamalWitness,
        };
        let gen = C::generator();
        let h = gen * C::random_scalar(rng);
        let y_pt = gen * C::random_scalar(rng);
        let x = C::random_scalar(rng);
        let r = C::random_scalar(rng);
        let d = h * x + y_pt * r;
        let e_pt = gen * r;
        let stmt = HomoElGamalStatement::<C> {
            G: gen,
            H: h,
            Y: y_pt,
            D: d,
            E: e_pt,
        };
        let wit = HomoElGamalWitness::<C> { x, r };
        let proof = HomoElGamalProof::prove(&wit, &stmt, rng);
        proof
            .verify(&stmt)
            .expect("HomoElGamalProof fixture invalid");
        g.bench_function("homo_elgamal/prove", |b| {
            b.iter(|| HomoElGamalProof::prove(&wit, &stmt, rng))
        });
        g.bench_function("homo_elgamal/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // pi_eq
    {
        use tecdsa_paillier::{backend::Integer, zk::pi_eq::PiEqProof};

        let x1 = C::random_scalar(rng);
        let x1_bytes = scalar_to_bytes(&x1);
        let x1_point = C::generator() * x1;
        let q_int = tecdsa_curve::conv::curve_order::<C>();
        let t = q_int.sample_below_ref(rng);
        let x_hat_1 = Integer::from_bytes_msf(&x1_bytes) + &t * &q_int;
        let (ct, nonce) = paillier_encrypt(ek, &x_hat_1);
        let proof = PiEqProof::<C>::prove(b"bench", ek, dk, &ct, &x1_point, &x_hat_1, &nonce, rng);
        assert!(
            proof.verify(b"bench", ek, &ct, &x1_point),
            "PiEqProof fixture invalid"
        );
        g.bench_function("pi_eq/prove", |b| {
            b.iter(|| {
                PiEqProof::<C>::prove(b"bench", ek, dk, &ct, &x1_point, &x_hat_1, &nonce, rng)
            })
        });
        g.bench_function("pi_eq/verify", |b| {
            b.iter(|| proof.verify(b"bench", ek, &ct, &x1_point))
        });
    }

    // homo_mult — relation: c3 = c2^eta * r_c3^N mod N^2
    {
        use tecdsa_paillier::{
            backend::Integer,
            zk::homo_mult::{HomoMultProof, HomoMultStatement, HomoMultWitness},
        };
        let nt = &*NTILDE;
        let q = group_order();
        let eta = sample_below(&q);
        let (c1, r_c1) = paillier_encrypt(ek, &eta);
        let some_val = sample_below(&q);
        let (c2, _) = paillier_encrypt(ek, &some_val);
        let r_c3 = Integer::sample_in_mult_group_of(rng, ek.n());
        let c3 = {
            let c2_eta = c2
                .pow_mod_ref(&eta, ek.nn())
                .expect("base is invertible modulo n")
                .complete();
            let r_n = r_c3
                .pow_mod_ref(ek.n(), ek.nn())
                .expect("base is invertible modulo n")
                .complete();
            (c2_eta * r_n).modulo(ek.nn())
        };
        let stmt = HomoMultStatement {
            c1: c1.clone(),
            c2,
            c3,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1: nt.h1.clone(),
            h2: nt.h2.clone(),
            N_tilde: nt.n_tilde.clone(),
        };
        let wit = HomoMultWitness { eta, r_c1, r_c3 };
        let proof = HomoMultProof::prove::<C>(&wit, &stmt, rng);
        proof
            .verify::<C>(&stmt)
            .expect("HomoMultProof fixture invalid");
        g.bench_function("homo_mult/prove", |b| {
            b.iter(|| HomoMultProof::prove::<C>(&wit, &stmt, rng))
        });
        g.bench_function("homo_mult/verify", |b| b.iter(|| proof.verify::<C>(&stmt)));
    }

    // alice_range (MtA Alice proof)
    {
        use tecdsa_paillier::zk::mta_range::AliceProof;
        let nt = &*NTILDE;
        let q = group_order();
        let a = sample_below(&q);
        let (cipher, r) = paillier_encrypt(ek, &a);
        let ntilde = nt.to_mta_params();
        let proof = AliceProof::prove::<C>(&a, &cipher, ek.n(), ek.nn(), &ntilde, &r, rng);
        proof
            .verify::<C>(&cipher, ek.n(), ek.nn(), &ntilde)
            .expect("AliceProof fixture invalid");
        g.bench_function("alice_range/prove", |b| {
            b.iter(|| AliceProof::prove::<C>(&a, &cipher, ek.n(), ek.nn(), &ntilde, &r, rng))
        });
        g.bench_function("alice_range/verify", |b| {
            b.iter(|| proof.verify::<C>(&cipher, ek.n(), ek.nn(), &ntilde))
        });
    }

    // range_ni
    {
        use tecdsa_paillier::zk::range_ni::RangeProofNi;
        let q = group_order();
        let x = sample_below(&q);
        let (ct, r) = paillier_encrypt(ek, &x);
        let proof = RangeProofNi::prove(dk, ek, &ct, &x, &r, &q, rng).expect("range_ni prove");
        assert!(proof.verify(ek, &ct, &q), "RangeProofNi fixture invalid");
        g.bench_function("range_ni/prove", |b| {
            b.iter(|| RangeProofNi::prove(dk, ek, &ct, &x, &r, &q, rng))
        });
        g.bench_function("range_ni/verify", |b| b.iter(|| proof.verify(ek, &ct, &q)));
    }

    // pdl_slack
    {
        use tecdsa_paillier::zk::pdl_slack::{PdlSlackProof, PdlSlackStatement, PdlSlackWitness};
        let nt = &*NTILDE;
        let q = group_order();
        let x = sample_below(&q);
        let (ciphertext, r) = paillier_encrypt(ek, &x);
        let x_scalar = tecdsa_curve::conv::integer_to_scalar::<C>(&x);
        let gen = C::generator();
        let q_pt = gen * x_scalar;
        let stmt = PdlSlackStatement::<C> {
            ciphertext: ciphertext.clone(),
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q: q_pt,
            G: gen,
            h1: nt.h1.clone(),
            h2: nt.h2.clone(),
            N_tilde: nt.n_tilde.clone(),
        };
        let wit = PdlSlackWitness { x, r };
        let proof = PdlSlackProof::prove(&wit, &stmt, rng);
        proof.verify(&stmt).expect("PdlSlackProof fixture invalid");
        g.bench_function("pdl_slack/prove", |b| {
            b.iter(|| PdlSlackProof::prove(&wit, &stmt, rng))
        });
        g.bench_function("pdl_slack/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // pib — proves c_B = Enc(pk, b; r)
    {
        use tecdsa_paillier::zk::pia_pib::PiBProof;
        let q = group_order();
        let b_val = sample_below(&q);
        let (c_b, r_b) = paillier_encrypt(ek, &b_val);
        let proof = PiBProof::prove(ek, &c_b, &b_val, &r_b, &q, rng);
        assert!(proof.verify(ek, &c_b, &q), "PiBProof fixture invalid");
        g.bench_function("pib/prove", |b| {
            b.iter(|| PiBProof::prove(ek, &c_b, &b_val, &r_b, &q, rng))
        });
        g.bench_function("pib/verify", |b| b.iter(|| proof.verify(ek, &c_b, &q)));
    }

    // bob_ext — Bob's extended MtA range proof with EC check
    {
        use tecdsa_paillier::{backend::Integer, zk::mta_range::BobProofExt};
        let nt = &*NTILDE;
        let q = group_order();
        let ntilde = nt.to_mta_params();
        let a = sample_below(&q);
        let (enc_a, _) = paillier_encrypt(ek, &a);
        let b_val = sample_below(&q);
        let b_scalar = tecdsa_curve::conv::integer_to_scalar::<C>(&b_val);
        let x_pt = C::generator() * b_scalar;
        let beta_prim = sample_below(&Integer::from_bytes_msf(&ek.half_n().to_bytes_msf()));
        let r_bob = Integer::sample_in_mult_group_of(rng, ek.n());
        let b_times_enc_a = ek.omul(&b_val, &enc_a).expect("omul");
        let enc_beta = ek.encrypt_with(&beta_prim, &r_bob).expect("encrypt beta");
        let mta_out = ek.oadd(&b_times_enc_a, &enc_beta).expect("oadd");
        let proof = BobProofExt::<C>::prove(
            &enc_a,
            &mta_out,
            &b_val,
            &beta_prim,
            ek.n(),
            ek.nn(),
            &ntilde,
            &r_bob,
            rng,
        );
        proof
            .verify(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde, &x_pt)
            .expect("BobProofExt fixture invalid");
        g.bench_function("bob_ext/prove", |b| {
            b.iter(|| {
                BobProofExt::<C>::prove(
                    &enc_a,
                    &mta_out,
                    &b_val,
                    &beta_prim,
                    ek.n(),
                    ek.nn(),
                    &ntilde,
                    &r_bob,
                    rng,
                )
            })
        });
        g.bench_function("bob_ext/verify", |b| {
            b.iter(|| proof.verify(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde, &x_pt))
        });
    }

    // nonce_consist
    {
        use tecdsa_paillier::{
            backend::Integer,
            zk::nonce_consist::{NonceConsistProof, NonceConsistStatement, NonceConsistWitness},
        };
        let nt = &*NTILDE;
        let q = group_order();
        let gen = C::generator();
        let eta1 = sample_below(&q);
        let eta1_scalar = tecdsa_curve::conv::integer_to_scalar::<C>(&eta1);
        let r_i = gen * eta1_scalar;
        let rho = sample_below(&q);
        let (u_ct, _) = paillier_encrypt(ek, &rho);
        let eta2 = sample_below(&q);
        let r_c = Integer::sample_in_mult_group_of(rng, ek.n());
        let gamma_paillier = ek.n() + Integer::one();
        let w_i = {
            let u_eta1 = u_ct
                .pow_mod_ref(&eta1, ek.nn())
                .expect("base is invertible modulo n")
                .complete();
            let q_eta2 = q * &eta2;
            let g_q_eta2 = gamma_paillier
                .pow_mod_ref(&q_eta2, ek.nn())
                .expect("base is invertible modulo n")
                .complete();
            let r_c_n = r_c
                .pow_mod_ref(ek.n(), ek.nn())
                .expect("base is invertible modulo n")
                .complete();
            (u_eta1 * g_q_eta2 % ek.nn() * r_c_n).modulo(ek.nn())
        };
        let stmt = NonceConsistStatement::<C> {
            G: gen,
            r_i,
            w_i,
            u: u_ct,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1: nt.h1.clone(),
            h2: nt.h2.clone(),
            N_tilde: nt.n_tilde.clone(),
        };
        let wit = NonceConsistWitness { eta1, eta2, r_c };
        let proof = NonceConsistProof::prove(&wit, &stmt, rng);
        proof
            .verify(&stmt)
            .expect("NonceConsistProof fixture invalid");
        g.bench_function("nonce_consist/prove", |b| {
            b.iter(|| NonceConsistProof::prove(&wit, &stmt, rng))
        });
        g.bench_function("nonce_consist/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // pia — proves c_A = c_B^a * Enc(alpha'; r')
    {
        use tecdsa_paillier::{backend::Integer, zk::pia_pib::PiAProof};
        let q = group_order();
        let b_val = sample_below(&q);
        let (c_b, _) = paillier_encrypt(ek, &b_val);
        let a = sample_below(&q);
        let alpha_prime = sample_below(&q);
        let r_prime = Integer::sample_in_mult_group_of(rng, ek.n());
        let c_b_a = c_b
            .pow_mod_ref(&a, ek.nn())
            .expect("base is invertible modulo n")
            .complete();
        let enc_alpha = ek.encrypt_with(&alpha_prime, &r_prime).expect("enc");
        let c_a = (c_b_a * enc_alpha).modulo(ek.nn());
        let proof = PiAProof::prove(ek, &c_a, &c_b, &a, &alpha_prime, &r_prime, &q, rng);
        assert!(proof.verify(ek, &c_a, &c_b, &q), "PiAProof fixture invalid");
        g.bench_function("pia/prove", |b| {
            b.iter(|| PiAProof::prove(ek, &c_a, &c_b, &a, &alpha_prime, &r_prime, &q, rng))
        });
        g.bench_function("pia/verify", |b| {
            b.iter(|| proof.verify(ek, &c_a, &c_b, &q))
        });
    }

    // bob — Bob's MtA range proof (without EC check)
    {
        use tecdsa_paillier::{backend::Integer, zk::mta_range::BobProof};
        let nt = &*NTILDE;
        let q = group_order();
        let ntilde = nt.to_mta_params();
        let a = sample_below(&q);
        let (enc_a, _) = paillier_encrypt(ek, &a);
        let b_val = sample_below(&q);
        let beta_prim = sample_below(&Integer::from_bytes_msf(&ek.half_n().to_bytes_msf()));
        let r_bob = Integer::sample_in_mult_group_of(rng, ek.n());
        let b_times_enc_a = ek.omul(&b_val, &enc_a).expect("omul");
        let enc_beta = ek.encrypt_with(&beta_prim, &r_bob).expect("enc");
        let mta_out = ek.oadd(&b_times_enc_a, &enc_beta).expect("oadd");
        let (proof, _) = BobProof::prove::<C>(
            &enc_a,
            &mta_out,
            &b_val,
            &beta_prim,
            ek.n(),
            ek.nn(),
            &ntilde,
            &r_bob,
            false,
            rng,
        );
        proof
            .verify::<C>(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde)
            .expect("BobProof fixture invalid");
        g.bench_function("bob/prove", |b| {
            b.iter(|| {
                BobProof::prove::<C>(
                    &enc_a,
                    &mta_out,
                    &b_val,
                    &beta_prim,
                    ek.n(),
                    ek.nn(),
                    &ntilde,
                    &r_bob,
                    false,
                    rng,
                )
            })
        });
        g.bench_function("bob/verify", |b| {
            b.iter(|| proof.verify::<C>(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde))
        });
    }

    // pdl_transcript — full interactive PDL verification (5 steps)
    {
        use tecdsa_paillier::{backend::Integer, zk::pdl::pdl_verify};
        let x1 = C::random_scalar(rng);
        let q1 = C::generator() * x1;
        let x1_bytes = scalar_to_bytes(&x1);
        let x1_int = Integer::from_bytes_msf(&x1_bytes);
        let (c_key, _) = paillier_encrypt(ek, &x1_int);
        pdl_verify::<C>(dk, ek, &x1, &c_key, &q1, rng).expect("PDL transcript fixture invalid");
        g.bench_function("pdl_transcript/full", |b| {
            b.iter(|| pdl_verify::<C>(dk, ek, &x1, &c_key, &q1, rng))
        });
    }

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 4b. Upstream paillier-zk facade (CGGMP20 ZK proofs)
// ═══════════════════════════════════════════════════════════════════════

fn paillier_zk_facade(c: &mut Criterion) {
    use sha2::Sha256;
    use tecdsa_paillier::zk::{bridge::pedersen_to_aux, paillier_zk};

    #[derive(udigest::Digestable)]
    struct BenchTag(&'static str);

    let mut g = c.benchmark_group("zk/paillier_zk_facade");
    g.sample_size(10);
    let rng = &mut thread_rng();

    let pf = &*PAILLIER;
    let dk = &pf.dk;
    let ek = &pf.ek;
    let ped = &*PEDERSEN;
    let aux = pedersen_to_aux(&ped.params);
    let tag = BenchTag("bench");

    // Pi_enc
    {
        use paillier_zk::paillier_encryption_in_range as pi_enc;
        use tecdsa_paillier::backend::Integer;
        let plaintext = Integer::from(42);
        let (ct, nonce) = paillier_encrypt(ek, &plaintext);
        let data = pi_enc::Data {
            key: ek,
            ciphertext: &ct,
        };
        let pdata = pi_enc::PrivateData {
            plaintext: &plaintext,
            nonce: &nonce,
        };
        let security = pi_enc::SecurityParams {
            l: 256,
            epsilon: 512,
            q: group_order(),
        };
        let proof =
            pi_enc::non_interactive::prove::<Sha256>(&tag, &aux, data, pdata, &security, rng)
                .expect("pi_enc prove");
        pi_enc::non_interactive::verify::<Sha256>(&tag, &aux, data, &security, &proof)
            .expect("pi_enc verify");
        g.bench_function("pi_enc/prove", |b| {
            b.iter(|| {
                pi_enc::non_interactive::prove::<Sha256>(&tag, &aux, data, pdata, &security, rng)
            })
        });
        g.bench_function("pi_enc/verify", |b| {
            b.iter(|| {
                pi_enc::non_interactive::verify::<Sha256>(&tag, &aux, data, &security, &proof)
            })
        });
    }

    // Pi_fac
    {
        use paillier_zk::no_small_factor as pi_fac;
        let n = dk.n().clone();
        let p = dk.p().clone();
        let q_paillier = dk.q().clone();
        // `n` is this benchmark's own Paillier modulus (p*q > 0), so `sqrt_ref`
        // (which panics on negative input) cannot panic here.
        let n_root = n.sqrt_ref().complete();
        let data = pi_fac::Data {
            n: &n,
            n_root: &n_root,
        };
        let pdata = pi_fac::PrivateData {
            p: &p,
            q: &q_paillier,
        };
        let security = pi_fac::SecurityParams {
            l: 256,
            epsilon: 512,
        };
        let proof =
            pi_fac::non_interactive::prove::<Sha256>(&tag, &aux, data, pdata, &security, rng)
                .expect("pi_fac prove");
        pi_fac::non_interactive::verify::<Sha256>(&tag, &aux, data, &security, &proof)
            .expect("pi_fac verify");
        g.bench_function("pi_fac/prove", |b| {
            b.iter(|| {
                pi_fac::non_interactive::prove::<Sha256>(&tag, &aux, data, pdata, &security, rng)
            })
        });
        g.bench_function("pi_fac/verify", |b| {
            b.iter(|| {
                pi_fac::non_interactive::verify::<Sha256>(&tag, &aux, data, &security, &proof)
            })
        });
    }

    // Pi_mod (upstream paillier_blum_modulus)
    {
        use paillier_zk::paillier_blum_modulus as pi_mod_up;
        let n = dk.n().clone();
        let p = dk.p().clone();
        let q_p = dk.q().clone();
        let data = pi_mod_up::Data { n: &n };
        let pdata = pi_mod_up::PrivateData { p: &p, q: &q_p };
        let proof = pi_mod_up::non_interactive::prove::<80, Sha256>(&tag, data, pdata, rng)
            .expect("pi_mod_up prove");
        pi_mod_up::non_interactive::verify::<80, Sha256>(&tag, data, &proof, rng)
            .expect("pi_mod_up verify");
        g.bench_function("pi_mod_upstream/prove", |b| {
            b.iter(|| pi_mod_up::non_interactive::prove::<80, Sha256>(&tag, data, pdata, rng))
        });
        g.bench_function("pi_mod_upstream/verify", |b| {
            b.iter(|| pi_mod_up::non_interactive::verify::<80, Sha256>(&tag, data, &proof, rng))
        });
    }

    // Pi_aff_g — affine operation in range with group commitment
    {
        use paillier_zk::paillier_affine_operation_in_range as pi_aff;
        use tecdsa_paillier::{backend::Integer, zk::bridge::point_to_ge};

        type GE = generic_ec::curves::Secp256k1;
        let x_val = Integer::from(7);
        let y_val = Integer::from(13);
        let (ct_c, _nonce_c) = paillier_encrypt(ek, &Integer::from(100));
        let (ct_y, nonce_y) = paillier_encrypt(ek, &y_val);
        // D = C^x * Enc(y; rho) where rho is nonce_aff
        let nonce_aff = Integer::sample_in_mult_group_of(rng, ek.n());
        let d_val = {
            let c_x = ct_c
                .pow_mod_ref(&x_val, ek.nn())
                .expect("base is invertible modulo n")
                .complete();
            let enc_y = ek.encrypt_with(&y_val, &nonce_aff).expect("enc_y");
            (c_x * enc_y).modulo(ek.nn())
        };
        let x_scalar = tecdsa_curve::conv::integer_to_scalar::<C>(&x_val);
        let x_point_k256 = C::generator() * x_scalar;
        let x_ge = point_to_ge(&x_point_k256);
        let data = pi_aff::Data::<GE> {
            key_j: ek,
            key_i: ek,
            c: &ct_c,
            d: &d_val,
            y: &ct_y,
            x: &x_ge,
        };
        let pdata = pi_aff::PrivateData {
            x: &x_val,
            y: &y_val,
            nonce: &nonce_aff,
            nonce_y: &nonce_y,
        };
        let security = pi_aff::SecurityParams {
            l_x: 256,
            l_y: 1280,
            epsilon: 512,
        };
        let proof =
            pi_aff::non_interactive::prove::<GE, Sha256>(&tag, &aux, data, pdata, &security, rng)
                .expect("pi_aff prove");
        pi_aff::non_interactive::verify::<GE, Sha256>(&tag, &aux, data, &security, &proof)
            .expect("pi_aff verify");
        g.bench_function("pi_aff_g/prove", |b| {
            b.iter(|| {
                pi_aff::non_interactive::prove::<GE, Sha256>(
                    &tag, &aux, data, pdata, &security, rng,
                )
            })
        });
        g.bench_function("pi_aff_g/verify", |b| {
            b.iter(|| {
                pi_aff::non_interactive::verify::<GE, Sha256>(&tag, &aux, data, &security, &proof)
            })
        });
    }

    // Pi_elog — dlog with El-Gamal commitment
    {
        use paillier_zk::dlog_with_el_gamal_commitment as pi_elog;
        use tecdsa_paillier::zk::bridge::scalar_to_ge;
        type GE = generic_ec::curves::Secp256k1;
        let y_scalar = C::random_scalar(rng);
        let lambda_scalar = C::random_scalar(rng);
        let y_ge = scalar_to_ge(&y_scalar);
        let lambda_ge = scalar_to_ge(&lambda_scalar);
        let g_ge = generic_ec::Point::<GE>::generator();
        let h_ge = g_ge * generic_ec::Scalar::<GE>::random(rng);
        let x_ge = g_ge * y_ge;
        let l_ge = g_ge * lambda_ge;
        let m_ge = g_ge * y_ge + x_ge * lambda_ge;
        let y_pt = h_ge * y_ge;
        let data = pi_elog::Data::<GE> {
            l: &l_ge,
            m: &m_ge,
            x: &x_ge,
            y: &y_pt,
            h: &h_ge,
        };
        let pdata = pi_elog::PrivateData::<GE> {
            y: &y_ge,
            lambda: &lambda_ge,
        };
        let proof = pi_elog::non_interactive::prove::<GE, Sha256>(&tag, data, pdata, rng)
            .expect("pi_elog prove");
        pi_elog::non_interactive::verify::<GE, Sha256>(&tag, data, &proof).expect("pi_elog verify");
        g.bench_function("pi_elog/prove", |b| {
            b.iter(|| pi_elog::non_interactive::prove::<GE, Sha256>(&tag, data, pdata, rng))
        });
        g.bench_function("pi_elog/verify", |b| {
            b.iter(|| pi_elog::non_interactive::verify::<GE, Sha256>(&tag, data, &proof))
        });
    }

    // Pi_enc_elg — encryption in range with ElGamal
    {
        use paillier_zk::{
            paillier_encryption_in_range_with_el_gamal as pi_enc_elg, IntegerExt as _,
        };
        use tecdsa_paillier::backend::Integer;

        type GE = generic_ec::curves::Secp256k1;
        let security = pi_enc_elg::SecurityParams {
            l: 256,
            epsilon: 512,
        };
        let plaintext = Integer::from_rng_half_pm(rng, &Integer::two_pow(security.l as u32));
        let nonce = Integer::sample_in_mult_group_of(rng, ek.n());
        let ct = ek.encrypt_with(&plaintext, &nonce).expect("enc");
        let a_scalar = generic_ec::Scalar::<GE>::random(rng);
        let b_scalar_ge = generic_ec::Scalar::<GE>::random(rng);
        let g_ge = generic_ec::Point::<GE>::generator();
        let a_pt = g_ge * a_scalar;
        let b_pt = g_ge * b_scalar_ge;
        let x_pt = g_ge * (a_scalar * b_scalar_ge + plaintext.to_scalar());
        let pdata = pi_enc_elg::PrivateData::<GE> {
            plaintext: &plaintext,
            nonce: &nonce,
            b: &b_scalar_ge,
        };
        let data = pi_enc_elg::Data::<GE> {
            key: ek,
            ciphertext: &ct,
            a: &a_pt,
            b: &b_pt,
            x: &x_pt,
        };
        let proof = pi_enc_elg::non_interactive::prove::<GE, Sha256>(
            &tag, &aux, data, pdata, &security, rng,
        )
        .expect("pi_enc_elg prove");
        pi_enc_elg::non_interactive::verify::<GE, Sha256>(&tag, &aux, data, &proof, &security)
            .expect("pi_enc_elg verify");
        g.bench_function("pi_enc_elg/prove", |b| {
            b.iter(|| {
                pi_enc_elg::non_interactive::prove::<GE, Sha256>(
                    &tag, &aux, data, pdata, &security, rng,
                )
            })
        });
        g.bench_function("pi_enc_elg/verify", |b| {
            b.iter(|| {
                pi_enc_elg::non_interactive::verify::<GE, Sha256>(
                    &tag, &aux, data, &proof, &security,
                )
            })
        });
    }

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Joye-Libert ZK — Profile B: N=3072-bit, k=256
// ═══════════════════════════════════════════════════════════════════════

fn joye_libert_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/joye_libert");
    g.sample_size(10);
    let rng = &mut thread_rng();

    let jl = &*JL;
    let jl_pk = &jl.pk;
    let jl_sk = &jl.sk;
    let jl_x = &jl.x;

    // zkjl_enc
    {
        use tecdsa_joye_libert::zk::zkjl_enc::ZkJlEncProof;
        let m = Integer::from(42u64);
        let (ct, r) = tecdsa_joye_libert::enc_dec::encrypt(jl_pk, &m, rng);
        let proof = ZkJlEncProof::prove(jl_pk, &ct.c, &m, &r, jl_pk.k, rng);
        assert!(proof.verify(jl_pk, &ct.c), "ZkJlEncProof fixture invalid");
        g.bench_function("zkjl_enc/prove", |b| {
            b.iter(|| ZkJlEncProof::prove(jl_pk, &ct.c, &m, &r, jl_pk.k, rng))
        });
        g.bench_function("zkjl_enc/verify", |b| b.iter(|| proof.verify(jl_pk, &ct.c)));
    }

    // zkjlmod
    {
        use tecdsa_joye_libert::zk::zkjlmod::ZkJlModProof;
        let proof = ZkJlModProof::prove(jl_pk, jl_sk, jl_x, rng);
        assert!(proof.verify(), "ZkJlModProof fixture invalid");
        g.bench_function("zkjlmod/prove", |b| {
            b.iter(|| ZkJlModProof::prove(jl_pk, jl_sk, jl_x, rng))
        });
        g.bench_function("zkjlmod/verify", |b| b.iter(|| proof.verify()));
    }

    // zkjl_com — Pedersen commitment c = y^m * h^r mod N
    {
        use tecdsa_joye_libert::zk::zkjl_com::{jl_commit, ZkJlComProof};
        let m = Integer::from(42u32);
        let r = random_below(&jl_pk.n, rng);
        let c = jl_commit(jl_pk, &m, &r);
        let proof = ZkJlComProof::prove(jl_pk, &c, &m, &r, jl_pk.k, rng);
        assert!(proof.verify(jl_pk, &c), "ZkJlComProof fixture invalid");
        g.bench_function("zkjl_com/prove", |b| {
            b.iter(|| ZkJlComProof::prove(jl_pk, &c, &m, &r, jl_pk.k, rng))
        });
        g.bench_function("zkjl_com/verify", |b| b.iter(|| proof.verify(jl_pk, &c)));
    }

    // zkqr2k
    {
        use tecdsa_joye_libert::zk::zkqr2k::ZkQr2kProof;
        let proof = ZkQr2kProof::prove(&jl_pk.n, jl_pk.k, jl_x, &jl_pk.h, rng);
        assert!(proof.verify(), "ZkQr2kProof fixture invalid");
        g.bench_function("zkqr2k/prove", |b| {
            b.iter(|| ZkQr2kProof::prove(&jl_pk.n, jl_pk.k, jl_x, &jl_pk.h, rng))
        });
        g.bench_function("zkqr2k/verify", |b| b.iter(|| proof.verify()));
    }

    // zkqr2kdl
    {
        use tecdsa_joye_libert::zk::zkqr2kdl::ZkQr2kDlProof;
        let proof = ZkQr2kDlProof::prove(&jl_pk.n, jl_pk.k, &jl_sk.alpha, &jl_pk.h, &jl_pk.y, rng);
        assert!(proof.verify(), "ZkQr2kDlProof fixture invalid");
        g.bench_function("zkqr2kdl/prove", |b| {
            b.iter(|| {
                ZkQr2kDlProof::prove(&jl_pk.n, jl_pk.k, &jl_sk.alpha, &jl_pk.h, &jl_pk.y, rng)
            })
        });
        g.bench_function("zkqr2kdl/verify", |b| b.iter(|| proof.verify()));
    }

    // zkjl_equ — proves two commitments under different PKs encrypt the same value
    {
        use tecdsa_joye_libert::zk::{zkjl_com::jl_commit, zkjl_equ::ZkJlEquProof};
        let jl_ex = &*JL_EXTRA;
        let pk0 = &jl_ex.pk0;
        let m = Integer::from(42u32);
        let r1 = random_below(&jl_pk.n, rng);
        let r0 = random_below(&pk0.n, rng);
        let c = jl_commit(jl_pk, &m, &r1);
        let c_prime = jl_commit(pk0, &m, &r0);
        let proof = ZkJlEquProof::prove(jl_pk, pk0, &c, &c_prime, &m, &r1, &r0, jl_pk.k, rng);
        assert!(
            proof.verify(jl_pk, pk0, &c, &c_prime),
            "ZkJlEquProof fixture invalid"
        );
        g.bench_function("zkjl_equ/prove", |b| {
            b.iter(|| ZkJlEquProof::prove(jl_pk, pk0, &c, &c_prime, &m, &r1, &r0, jl_pk.k, rng))
        });
        g.bench_function("zkjl_equ/verify", |b| {
            b.iter(|| proof.verify(jl_pk, pk0, &c, &c_prime))
        });
    }

    // zkjl_aff — affine relation: c_aff = c^a * y^alpha * h^r mod N
    {
        use tecdsa_joye_libert::zk::zkjl_aff::ZkJlAffProof;
        let b_msg = Integer::from(7u32);
        let (ct_b, _) = tecdsa_joye_libert::enc_dec::encrypt(jl_pk, &b_msg, rng);
        let a = Integer::from(5u32);
        let alpha = Integer::from(13u32);
        let r_aff = random_below(&jl_pk.n, rng);
        let c_a = ct_b.c.pow_mod_ref(&a, &jl_pk.n).unwrap().complete();
        let y_alpha = jl_pk.y.pow_mod_ref(&alpha, &jl_pk.n).unwrap().complete();
        let h_r = jl_pk.h.pow_mod_ref(&r_aff, &jl_pk.n).unwrap().complete();
        let c_aff = (c_a * y_alpha * &h_r) % &jl_pk.n;
        let proof = ZkJlAffProof::prove(
            jl_pk, &ct_b.c, &c_aff, &a, &alpha, &r_aff, jl_pk.k, jl_pk.k, rng,
        );
        assert!(
            proof.verify(jl_pk, &ct_b.c, &c_aff),
            "ZkJlAffProof fixture invalid"
        );
        g.bench_function("zkjl_aff/prove", |b| {
            b.iter(|| {
                ZkJlAffProof::prove(
                    jl_pk, &ct_b.c, &c_aff, &a, &alpha, &r_aff, jl_pk.k, jl_pk.k, rng,
                )
            })
        });
        g.bench_function("zkjl_aff/verify", |b| {
            b.iter(|| proof.verify(jl_pk, &ct_b.c, &c_aff))
        });
    }

    // zkjlv_com — vector Pedersen commitment
    {
        use tecdsa_joye_libert::zk::zkjlv_com::{jl_vec_commit, ZkJlvComProof};
        let ell = 3;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = random_below(&jl_pk.n, rng);
            let y_i = jl_x.pow_mod_ref(&alpha_i, &jl_pk.n).unwrap().complete();
            y_vec.push(y_i);
        }
        let m_vec = vec![
            Integer::from(42u32),
            Integer::from(17u32),
            Integer::from(99u32),
        ];
        let b_bits_vec = vec![32u32, 32, 32];
        let r_vc = random_below(&jl_pk.n, rng);
        let c_vc = jl_vec_commit(jl_pk, &y_vec, &m_vec, &r_vc);
        let proof = ZkJlvComProof::prove(jl_pk, &y_vec, &c_vc, &m_vec, &r_vc, &b_bits_vec, rng);
        assert!(
            proof.verify(jl_pk, &y_vec, &c_vc),
            "ZkJlvComProof fixture invalid"
        );
        g.bench_function("zkjlv_com/prove", |b| {
            b.iter(|| ZkJlvComProof::prove(jl_pk, &y_vec, &c_vc, &m_vec, &r_vc, &b_bits_vec, rng))
        });
        g.bench_function("zkjlv_com/verify", |b| {
            b.iter(|| proof.verify(jl_pk, &y_vec, &c_vc))
        });
    }

    // zkjlv_equ — vector commitment + individual commitment equality
    {
        use tecdsa_joye_libert::zk::{
            zkjl_com::jl_commit, zkjlv_com::jl_vec_commit, zkjlv_equ::ZkJlvEquProof,
        };
        let jl_ex = &*JL_EXTRA;
        let pk0 = &jl_ex.pk0;
        let ell = 2;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = random_below(&jl_pk.n, rng);
            y_vec.push(jl_x.pow_mod_ref(&alpha_i, &jl_pk.n).unwrap().complete());
        }
        let m_vec = vec![Integer::from(42u32), Integer::from(17u32)];
        let b_bits_vec = vec![32u32, 32];
        let r1 = random_below(&jl_pk.n, rng);
        let c_ve = jl_vec_commit(jl_pk, &y_vec, &m_vec, &r1);
        let mut c_prime_vec = Vec::with_capacity(ell);
        let mut r0_vec = Vec::with_capacity(ell);
        for i in 0..ell {
            let r0 = random_below(&pk0.n, rng);
            c_prime_vec.push(jl_commit(pk0, &m_vec[i], &r0));
            r0_vec.push(r0);
        }
        let proof = ZkJlvEquProof::prove(
            jl_pk,
            pk0,
            &y_vec,
            &c_ve,
            &c_prime_vec,
            &m_vec,
            &r1,
            &r0_vec,
            &b_bits_vec,
            rng,
        );
        assert!(
            proof.verify(jl_pk, pk0, &y_vec, &c_ve, &c_prime_vec),
            "ZkJlvEquProof fixture invalid"
        );
        g.bench_function("zkjlv_equ/prove", |b| {
            b.iter(|| {
                ZkJlvEquProof::prove(
                    jl_pk,
                    pk0,
                    &y_vec,
                    &c_ve,
                    &c_prime_vec,
                    &m_vec,
                    &r1,
                    &r0_vec,
                    &b_bits_vec,
                    rng,
                )
            })
        });
        g.bench_function("zkjlv_equ/verify", |b| {
            b.iter(|| proof.verify(jl_pk, pk0, &y_vec, &c_ve, &c_prime_vec))
        });
    }

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 6. eVRF ZK (DLEQ)
// ═══════════════════════════════════════════════════════════════════════

fn evrf_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/evrf");
    let rng = &mut thread_rng();

    use tecdsa_evrf::{EvrfProof, EvrfSecretKey};
    let (sk, pk) = EvrfSecretKey::<C>::generate(rng);
    let input = b"bench-input";
    let (output, proof) = sk.eval(input, rng);
    assert!(
        proof.verify(&pk, input, &output),
        "EvrfProof fixture invalid"
    );

    g.bench_function("dleq/eval", |b| b.iter(|| sk.eval(input, rng)));
    g.bench_function("dleq/prove", |b| {
        b.iter(|| EvrfProof::prove(&sk, input, &output, rng))
    });
    g.bench_function("dleq/verify", |b| {
        b.iter(|| proof.verify(&pk, input, &output))
    });

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    curve_zk,
    pedersen_mod_zk,
    class_group_zk,
    paillier_zk,
    paillier_zk_facade,
    joye_libert_zk,
    evrf_zk,
);
criterion_main!(benches);
