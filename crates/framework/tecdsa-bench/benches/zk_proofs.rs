// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof microbenchmarks: prove + verify for every proof relation.
//!
//! Every fixture is validated with `assert!` before timing.
//! Naming follows `docs/superpowers/plans/2026-06-02-zk-proof-benchmarks.md`.

use criterion::{criterion_group, criterion_main, Criterion};
use k256::Secp256k1;
use rand_core::OsRng;
use tecdsa_bench::zk_fixtures::*;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::backend::Integer;

fn sample_below_int(bound: &Integer) -> Integer {
    bound.random_below_ref(&mut OsRng)
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Curve ZK
// ═══════════════════════════════════════════════════════════════════════

fn curve_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/curve");

    // DlogProof
    {
        use tecdsa_curve::zk::dlog::DlogProof;
        let x = random_scalar();
        let p = C::generator() * x;
        let r = random_scalar();
        let proof = DlogProof::<C>::prove(&x, &r, &p, b"bench");
        assert!(proof.verify(&p, b"bench"), "DlogProof fixture invalid");
        g.bench_function("dlog/prove", |b| {
            b.iter(|| DlogProof::<C>::prove(&x, &random_scalar(), &p, b"bench"))
        });
        g.bench_function("dlog/verify", |b| b.iter(|| proof.verify(&p, b"bench")));
    }

    // DdhProof
    {
        use tecdsa_curve::zk::ddh::{DdhProof, DdhStatement, DdhWitness};
        let w = random_scalar();
        let gen = C::generator();
        let a = gen * random_scalar();
        let b_pt = gen * w;
        let c_pt = a * w;
        let stmt = DdhStatement::<C> {
            g: gen,
            a,
            b: b_pt,
            c: c_pt,
        };
        let wit = DdhWitness::<C> { w };
        let proof = DdhProof::prove(&stmt, &wit, &mut OsRng);
        assert!(proof.verify(&stmt), "DdhProof fixture invalid");
        g.bench_function("ddh/prove", |b| {
            b.iter(|| DdhProof::prove(&stmt, &wit, &mut OsRng))
        });
        g.bench_function("ddh/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // EgexpProof
    {
        use tecdsa_curve::zk::egexp::{EgexpProof, EgexpStatement, EgexpWitness};
        let dk = random_scalar();
        let pk = C::generator() * dk;
        let x = random_scalar();
        let r = random_scalar();
        let a = C::generator() * r;
        let b_pt = pk * r + C::generator() * x;
        let stmt = EgexpStatement::<C> { p: pk, a, b: b_pt };
        let wit = EgexpWitness::<C> { x, r };
        let proof = EgexpProof::prove(&stmt, &wit, &mut OsRng);
        assert!(proof.verify(&stmt), "EgexpProof fixture invalid");
        g.bench_function("egexp/prove", |b| {
            b.iter(|| EgexpProof::prove(&stmt, &wit, &mut OsRng))
        });
        g.bench_function("egexp/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // ProdProof — relation: C=tG, D=tP+yG, E=yA+rG, F=yB+rP
    {
        use tecdsa_curve::zk::prod::{ProdProof, ProdStatement, ProdWitness};
        let gen = C::generator();
        let dk = random_scalar();
        let pk = gen * dk;
        let alpha = random_scalar();
        let a = gen * alpha;
        let b_pt = pk * alpha;
        let y = random_scalar();
        let t = random_scalar();
        let r = random_scalar();
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
        let proof = ProdProof::prove(&stmt, &wit, &mut OsRng);
        assert!(proof.verify(&stmt), "ProdProof fixture invalid");
        g.bench_function("prod/prove", |b| {
            b.iter(|| ProdProof::prove(&stmt, &wit, &mut OsRng))
        });
        g.bench_function("prod/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // ReProof — relation: A'=rG+sA, B'=rP+sB
    {
        use tecdsa_curve::zk::rerandom::{ReProof, ReStatement, ReWitness};
        let gen = C::generator();
        let p_pt = C::nums_pedersen_h();
        let r = random_scalar();
        let s = random_scalar();
        let a = gen * random_scalar();
        let b_pt = p_pt * random_scalar();
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
        let sigma = random_scalar();
        let tau = random_scalar();
        let proof = ReProof::prove(&stmt, &wit, &sigma, &tau);
        assert!(proof.verify(&stmt), "ReProof fixture invalid");
        g.bench_function("rerandom/prove", |b| {
            b.iter(|| {
                let s = random_scalar();
                let t = random_scalar();
                ReProof::prove(&stmt, &wit, &s, &t)
            })
        });
        g.bench_function("rerandom/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Pedersen-mod ZK (Pi_prm, Pi_mod) — toy 512-bit params
// ═══════════════════════════════════════════════════════════════════════

fn pedersen_mod_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/pedersen_mod");
    g.sample_size(10);

    use tecdsa_pedersen_mod::zk::{PiMod, PiPrm};
    use tecdsa_pedersen_mod::PedersenModParams;

    let (params, secret) = PedersenModParams::generate(512, &mut OsRng);

    let piprm_proof = PiPrm::prove(&params, &secret, &mut OsRng);
    assert!(piprm_proof.verify(&params), "PiPrm fixture invalid");
    g.bench_function("pi_prm/prove", |b| {
        b.iter(|| PiPrm::prove(&params, &secret, &mut OsRng))
    });
    g.bench_function("pi_prm/verify", |b| b.iter(|| piprm_proof.verify(&params)));

    let pimod_proof = PiMod::prove(&params, &secret, &mut OsRng).expect("pimod prove");
    assert!(
        pimod_proof.verify(&params, &mut OsRng),
        "PiMod fixture invalid"
    );
    g.bench_function("pi_mod/prove", |b| {
        b.iter(|| PiMod::prove(&params, &secret, &mut OsRng))
    });
    g.bench_function("pi_mod/verify", |b| {
        b.iter(|| pimod_proof.verify(&params, &mut OsRng))
    });

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 3. Class-group ZK
// ═══════════════════════════════════════════════════════════════════════

fn class_group_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/class_group");

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
        let x_scalar = random_scalar();
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

    // R_enc_pc
    {
        use tecdsa_class_group::zk::r_enc_pc::REncPcProof;
        let (r_sk, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_bytes)
            .expect("enc");
        let y = setup.power_of_f_bytes(&m_bytes).expect("f^m");
        let proof =
            REncPcProof::prove(&mut setup, &pk, &ct, &y, &m_bytes, &r_bytes).expect("prove");
        assert!(
            proof.verify(&setup, &pk, &ct, &y).expect("verify"),
            "REncPcProof fixture invalid"
        );
        g.bench_function("r_enc_pc/prove", |b| {
            b.iter(|| REncPcProof::prove(&mut setup, &pk, &ct, &y, &m_bytes, &r_bytes))
        });
        g.bench_function("r_enc_pc/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct, &y))
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
        let sk_dec = setup.sk_to_decimal(&sk).expect("sk_dec");
        let ct = setup.encrypt(&pk, "42").expect("encrypt");
        let (c1, c2) = setup.ct_components(&ct).expect("comp");
        let c1_sk = setup.exp(&c1, &sk_dec).expect("c1^sk");
        let c1_sk_inv = c1_sk.neg(setup.ctx()).expect("inv");
        let dec_result = setup.compose(&c2, &c1_sk_inv).expect("dec");
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

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 4. Paillier self-authored ZK
// ═══════════════════════════════════════════════════════════════════════

fn paillier_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/paillier");
    g.sample_size(10);

    let (dk, ek) = paillier_keys();

    // correct_key_ni
    {
        use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
        let proof = NICorrectKeyProof::prove(&dk, b"bench");
        assert!(
            proof.verify(&ek, b"bench"),
            "NICorrectKeyProof fixture invalid"
        );
        g.bench_function("correct_key_ni/prove", |b| {
            b.iter(|| NICorrectKeyProof::prove(&dk, b"bench"))
        });
        g.bench_function("correct_key_ni/verify", |b| {
            b.iter(|| proof.verify(&ek, b"bench"))
        });
    }

    // homo_elgamal — relation: D = xH + rY, E = rG
    {
        use tecdsa_paillier::zk::homo_elgamal::{
            HomoElGamalProof, HomoElGamalStatement, HomoElGamalWitness,
        };
        let gen = C::generator();
        let h = gen * random_scalar();
        let y_pt = gen * random_scalar();
        let x = random_scalar();
        let r = random_scalar();
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
        let proof = HomoElGamalProof::prove(&wit, &stmt, &mut OsRng);
        proof
            .verify(&stmt)
            .expect("HomoElGamalProof fixture invalid");
        g.bench_function("homo_elgamal/prove", |b| {
            b.iter(|| HomoElGamalProof::prove(&wit, &stmt, &mut OsRng))
        });
        g.bench_function("homo_elgamal/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // pi_eq
    {
        use tecdsa_paillier::zk::pi_eq::PiEqProof;
        let x1 = random_scalar();
        let x1_bytes = scalar_to_bytes(&x1);
        let x1_point = C::generator() * x1;
        let q_int = tecdsa_paillier::conv::group_order_integer::<C>();
        let t = sample_below_int(&q_int);
        let x_hat_1 = Integer::from_bytes_msf(&x1_bytes) + &t * &q_int;
        let (ct, nonce) = paillier_encrypt(&ek, &x_hat_1);
        let proof = PiEqProof::<C>::prove(
            b"bench", &ek, &dk, &ct, &x1_point, &x_hat_1, &nonce, &mut OsRng,
        );
        assert!(
            proof.verify(b"bench", &ek, &ct, &x1_point),
            "PiEqProof fixture invalid"
        );
        g.bench_function("pi_eq/prove", |b| {
            b.iter(|| {
                PiEqProof::<C>::prove(
                    b"bench", &ek, &dk, &ct, &x1_point, &x_hat_1, &nonce, &mut OsRng,
                )
            })
        });
        g.bench_function("pi_eq/verify", |b| {
            b.iter(|| proof.verify(b"bench", &ek, &ct, &x1_point))
        });
    }

    // homo_mult — relation: c3 = c2^eta * r_c3^N mod N^2
    {
        use tecdsa_paillier::zk::homo_mult::{HomoMultProof, HomoMultStatement, HomoMultWitness};
        let (n_tilde, h1, h2) = ntilde_params();
        let q = group_order();
        let eta = sample_below(&q);
        let (c1, r_c1) = paillier_encrypt(&ek, &eta);
        let some_val = sample_below(&q);
        let (c2, _) = paillier_encrypt(&ek, &some_val);
        let r_c3 = Integer::sample_in_mult_group_of(&mut OsRng, ek.n());
        let c3 = {
            let c2_eta = pow_mod_signed(&c2, &eta, ek.nn());
            let r_n = pow_mod_signed(&r_c3, ek.n(), ek.nn());
            (c2_eta * r_n).modulo(ek.nn())
        };
        let stmt = HomoMultStatement {
            c1: c1.clone(),
            c2,
            c3,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1,
            h2,
            N_tilde: n_tilde,
        };
        let wit = HomoMultWitness { eta, r_c1, r_c3 };
        let proof = HomoMultProof::prove::<C>(&wit, &stmt, &mut OsRng);
        proof
            .verify::<C>(&stmt)
            .expect("HomoMultProof fixture invalid");
        g.bench_function("homo_mult/prove", |b| {
            b.iter(|| HomoMultProof::prove::<C>(&wit, &stmt, &mut OsRng))
        });
        g.bench_function("homo_mult/verify", |b| b.iter(|| proof.verify::<C>(&stmt)));
    }

    // alice_range (MtA Alice proof)
    {
        use tecdsa_paillier::zk::mta_range::{AliceProof, NTildeParams};
        let (n_tilde, h1, h2) = ntilde_params();
        let q = group_order();
        let a = sample_below(&q);
        let (cipher, r) = paillier_encrypt(&ek, &a);
        let ntilde = NTildeParams {
            N_tilde: n_tilde,
            h1,
            h2,
        };
        let proof = AliceProof::prove::<C>(&a, &cipher, ek.n(), ek.nn(), &ntilde, &r, &mut OsRng);
        proof
            .verify::<C>(&cipher, ek.n(), ek.nn(), &ntilde)
            .expect("AliceProof fixture invalid");
        g.bench_function("alice_range/prove", |b| {
            b.iter(|| AliceProof::prove::<C>(&a, &cipher, ek.n(), ek.nn(), &ntilde, &r, &mut OsRng))
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
        let (ct, r) = paillier_encrypt(&ek, &x);
        let proof =
            RangeProofNi::prove(&dk, &ek, &ct, &x, &r, &q, &mut OsRng).expect("range_ni prove");
        assert!(proof.verify(&ek, &ct, &q), "RangeProofNi fixture invalid");
        g.bench_function("range_ni/prove", |b| {
            b.iter(|| RangeProofNi::prove(&dk, &ek, &ct, &x, &r, &q, &mut OsRng))
        });
        g.bench_function("range_ni/verify", |b| b.iter(|| proof.verify(&ek, &ct, &q)));
    }

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Joye-Libert ZK — toy 256-bit/k=32 params
// ═══════════════════════════════════════════════════════════════════════

fn joye_libert_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/joye_libert");
    g.sample_size(10);

    let (jl_pk, jl_sk, jl_x) = jl_keys();

    // zkjl_enc
    {
        use num_bigint::BigUint;
        use tecdsa_joye_libert::zk::zkjl_enc::ZkJlEncProof;
        let m = BigUint::from(42u64);
        let (ct, r) = tecdsa_joye_libert::enc_dec::encrypt(&jl_pk, &m, &mut OsRng);
        let proof = ZkJlEncProof::prove(&jl_pk, &ct.c, &m, &r, jl_pk.k, &mut OsRng);
        assert!(proof.verify(&jl_pk, &ct.c), "ZkJlEncProof fixture invalid");
        g.bench_function("zkjl_enc/prove", |b| {
            b.iter(|| ZkJlEncProof::prove(&jl_pk, &ct.c, &m, &r, jl_pk.k, &mut OsRng))
        });
        g.bench_function("zkjl_enc/verify", |b| {
            b.iter(|| proof.verify(&jl_pk, &ct.c))
        });
    }

    // zkjlmod
    {
        use tecdsa_joye_libert::zk::zkjlmod::ZkJlModProof;
        let proof = ZkJlModProof::prove(&jl_pk, &jl_sk, &jl_x, &mut OsRng);
        assert!(proof.verify(), "ZkJlModProof fixture invalid");
        g.bench_function("zkjlmod/prove", |b| {
            b.iter(|| ZkJlModProof::prove(&jl_pk, &jl_sk, &jl_x, &mut OsRng))
        });
        g.bench_function("zkjlmod/verify", |b| b.iter(|| proof.verify()));
    }

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 6. eVRF ZK (DLEQ)
// ═══════════════════════════════════════════════════════════════════════

fn evrf_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/evrf");

    use tecdsa_evrf::{EvrfProof, EvrfSecretKey};
    let (sk, pk) = EvrfSecretKey::<C>::generate(&mut OsRng);
    let input = b"bench-input";
    let (output, proof) = sk.eval(input, &mut OsRng);
    assert!(
        proof.verify(&pk, input, &output),
        "EvrfProof fixture invalid"
    );

    g.bench_function("dleq/eval", |b| b.iter(|| sk.eval(input, &mut OsRng)));
    g.bench_function("dleq/prove", |b| {
        b.iter(|| EvrfProof::prove(&sk, input, &output, &mut OsRng))
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
    joye_libert_zk,
    evrf_zk,
);
criterion_main!(benches);
