// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof microbenchmarks: prove + verify for every proof relation.

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
// 1. Curve ZK (DlogProof, DdhProof, EgexpProof, ProdProof, ReProof)
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
        g.bench_function("egexp/prove", |b| {
            b.iter(|| EgexpProof::prove(&stmt, &wit, &mut OsRng))
        });
        g.bench_function("egexp/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // ProdProof
    {
        use tecdsa_curve::zk::prod::{ProdProof, ProdStatement, ProdWitness};
        let p_pt = C::generator();
        let (y, t, r) = (random_scalar(), random_scalar(), random_scalar());
        let a = p_pt * random_scalar();
        let b_pt = p_pt * y;
        let c_pt = a * y;
        let d = p_pt * t;
        let e_pt = a * t;
        let f_pt = p_pt * r;
        let stmt = ProdStatement::<C> {
            p: p_pt,
            a,
            b: b_pt,
            c: c_pt,
            d,
            e_pt,
            f: f_pt,
        };
        let wit = ProdWitness::<C> { y, t, r };
        let proof = ProdProof::prove(&stmt, &wit, &mut OsRng);
        g.bench_function("prod/prove", |b| {
            b.iter(|| ProdProof::prove(&stmt, &wit, &mut OsRng))
        });
        g.bench_function("prod/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // ReProof
    {
        use tecdsa_curve::zk::rerandom::{ReProof, ReStatement, ReWitness};
        let gen = C::generator();
        let p_pt = gen * random_scalar();
        let r = random_scalar();
        let a = gen * random_scalar();
        let b_pt = p_pt * random_scalar();
        let a_prime = a + gen * r;
        let b_prime = b_pt + p_pt * r;
        let stmt = ReStatement::<C> {
            g: gen,
            p: p_pt,
            a,
            b: b_pt,
            a_prime,
            b_prime,
        };
        let wit = ReWitness::<C> {
            r,
            s: random_scalar(),
        };
        let sigma = random_scalar();
        let tau = random_scalar();
        let proof = ReProof::prove(&stmt, &wit, &sigma, &tau);
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
// 2. Pedersen-mod ZK (PiPrm, PiMod)
// ═══════════════════════════════════════════════════════════════════════

fn pedersen_mod_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/pedersen_mod");
    g.sample_size(10);

    use tecdsa_pedersen_mod::zk::{PiMod, PiPrm};
    use tecdsa_pedersen_mod::PedersenModParams;

    let (params, secret) = PedersenModParams::generate(512, &mut OsRng);

    let piprm_proof = PiPrm::prove(&params, &secret, &mut OsRng);
    g.bench_function("piprm/prove", |b| {
        b.iter(|| PiPrm::prove(&params, &secret, &mut OsRng))
    });
    g.bench_function("piprm/verify", |b| b.iter(|| piprm_proof.verify(&params)));

    let pimod_proof = PiMod::prove(&params, &secret, &mut OsRng).expect("pimod prove");
    g.bench_function("pimod/prove", |b| {
        b.iter(|| PiMod::prove(&params, &secret, &mut OsRng))
    });
    g.bench_function("pimod/verify", |b| {
        b.iter(|| pimod_proof.verify(&params, &mut OsRng))
    });

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 3. Class-group ZK (representative subset)
// ═══════════════════════════════════════════════════════════════════════

fn class_group_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/class_group");

    let (mut setup, sk, pk) = cl_setup_with_keys();
    let sk_bytes = setup.sk_to_bytes(&sk).expect("sk_bytes");
    let m_bytes = 42u32.to_be_bytes().to_vec();

    // REncProof
    {
        use tecdsa_class_group::zk::r_enc::REncProof;
        let (r_sk, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_bytes)
            .expect("enc");
        let proof =
            REncProof::prove(&mut setup, &pk, &ct, &m_bytes, &r_bytes).expect("r_enc prove");
        g.bench_function("r_enc/prove", |b| {
            b.iter(|| REncProof::prove(&mut setup, &pk, &ct, &m_bytes, &r_bytes))
        });
        g.bench_function("r_enc/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct))
        });
    }

    // RKeyProof
    {
        use tecdsa_class_group::zk::r_key::RKeyProof;
        let proof = RKeyProof::prove(&mut setup, &pk, &sk_bytes).expect("r_key prove");
        g.bench_function("r_key/prove", |b| {
            b.iter(|| RKeyProof::prove(&mut setup, &pk, &sk_bytes))
        });
        g.bench_function("r_key/verify", |b| b.iter(|| proof.verify(&setup, &pk)));
    }

    // RDlClProof
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
        g.bench_function("r_dl_cl/prove", |b| {
            b.iter(|| RDlClProof::prove(&mut setup, &x_point, &ct, &ct_x, &x_bytes))
        });
        g.bench_function("r_dl_cl/verify", |b| {
            b.iter(|| proof.verify(&setup, &x_point, &ct, &ct_x))
        });
    }

    // REncPcProof
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
        g.bench_function("r_enc_pc/prove", |b| {
            b.iter(|| REncPcProof::prove(&mut setup, &pk, &ct, &y, &m_bytes, &r_bytes))
        });
        g.bench_function("r_enc_pc/verify", |b| {
            b.iter(|| proof.verify(&setup, &pk, &ct, &y))
        });
    }

    // RPcDlProof
    {
        use tecdsa_class_group::zk::r_pc_dl::RPcDlProof;
        let y = setup.power_of_f_bytes(&m_bytes).expect("f^m");
        let proof = RPcDlProof::prove(&mut setup, &y, &m_bytes).expect("prove");
        g.bench_function("r_pc_dl/prove", |b| {
            b.iter(|| RPcDlProof::prove(&mut setup, &y, &m_bytes))
        });
        g.bench_function("r_pc_dl/verify", |b| b.iter(|| proof.verify(&setup, &y)));
    }

    // RShProof
    {
        use tecdsa_class_group::pvss_share::pvss_share_distribute;
        let party_ids: Vec<u16> = vec![1, 2, 3];
        let mut pks = Vec::new();
        for _ in 0..3 {
            let (_, pk_i) = setup.keygen().expect("keygen");
            pks.push(pk_i);
        }
        let pvss = pvss_share_distribute(&mut setup, &party_ids, &pks, 2, 0).expect("pvss");
        use tecdsa_class_group::pvss_share::pvss_share_verify;
        g.bench_function("r_sh/prove+distribute", |b| {
            b.iter(|| pvss_share_distribute(&mut setup, &party_ids, &pks, 2, 0))
        });
        g.bench_function("r_sh/verify", |b| {
            b.iter(|| {
                pvss_share_verify(
                    &setup,
                    &party_ids,
                    &pks,
                    2,
                    &pvss.c1,
                    &pvss.c2s,
                    &pvss.proof,
                )
            })
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

    // NICorrectKeyProof
    {
        use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
        let proof = NICorrectKeyProof::prove(&dk, b"bench");
        g.bench_function("correct_key/prove", |b| {
            b.iter(|| NICorrectKeyProof::prove(&dk, b"bench"))
        });
        g.bench_function("correct_key/verify", |b| {
            b.iter(|| proof.verify(&ek, b"bench"))
        });
    }

    // HomoElGamalProof
    {
        use tecdsa_paillier::zk::homo_elgamal::{
            HomoElGamalProof, HomoElGamalStatement, HomoElGamalWitness,
        };
        let x = random_scalar();
        let r = random_scalar();
        let gen = C::generator();
        let h = gen * random_scalar();
        let y = gen * x;
        let d = gen * r;
        let e_pt = h * r + gen * x;
        let stmt = HomoElGamalStatement::<C> {
            G: gen,
            H: h,
            Y: y,
            D: d,
            E: e_pt,
        };
        let wit = HomoElGamalWitness::<C> { x, r };
        let proof = HomoElGamalProof::prove(&wit, &stmt, &mut OsRng);
        g.bench_function("homo_elgamal/prove", |b| {
            b.iter(|| HomoElGamalProof::prove(&wit, &stmt, &mut OsRng))
        });
        g.bench_function("homo_elgamal/verify", |b| b.iter(|| proof.verify(&stmt)));
    }

    // PiEqProof
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

    g.finish();
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Joye-Libert ZK
// ═══════════════════════════════════════════════════════════════════════

fn joye_libert_zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk/joye_libert");
    g.sample_size(10);

    let (jl_pk, jl_sk, jl_x) = jl_keys();

    // ZkJlEncProof
    {
        use num_bigint::BigUint;
        use tecdsa_joye_libert::zk::zkjl_enc::ZkJlEncProof;
        let m = BigUint::from(42u64);
        let (ct, r) = tecdsa_joye_libert::enc_dec::encrypt(&jl_pk, &m, &mut OsRng);
        let proof = ZkJlEncProof::prove(&jl_pk, &ct.c, &m, &r, jl_pk.k, &mut OsRng);
        g.bench_function("zkjl_enc/prove", |b| {
            b.iter(|| ZkJlEncProof::prove(&jl_pk, &ct.c, &m, &r, jl_pk.k, &mut OsRng))
        });
        g.bench_function("zkjl_enc/verify", |b| {
            b.iter(|| proof.verify(&jl_pk, &ct.c))
        });
    }

    // ZkJlModProof
    {
        use tecdsa_joye_libert::zk::zkjlmod::ZkJlModProof;
        let proof = ZkJlModProof::prove(&jl_pk, &jl_sk, &jl_x, &mut OsRng);
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
// Entry point
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
