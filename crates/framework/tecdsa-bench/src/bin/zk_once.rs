// SPDX-License-Identifier: MIT OR Apache-2.0
//! One-shot ZK proof timing.
//!
//! This is intentionally not a statistical benchmark. It runs each operation
//! once with Profile B fixtures and prints TSV rows:
//!
//! family/proof/op<TAB>elapsed_ns<TAB>elapsed_human

use std::time::{Duration, Instant};

use k256::Secp256k1;
use num_bigint::RandBigInt;
use num_traits::Num as _;
use rand_core::OsRng;
use tecdsa_bench::zk_fixtures::*;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::backend::Integer;

fn sample_below_int(bound: &Integer) -> Integer {
    bound.random_below_ref(&mut OsRng)
}

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

fn main() {
    println!("name\telapsed_ns\telapsed");

    eprintln!("# setup");
    let paillier = time_once("setup/paillier_keys", PaillierFixture::generate);
    let ntilde = time_once("setup/ntilde_params", NTildeFixture::generate);
    let pedersen = time_once("setup/pedersen_mod_params", PedersenFixture::generate);
    let cl = time_once("setup/cl_setup", cl_setup_with_keys);
    let jl = time_once("setup/jl_keys", JlFixture::generate);
    let jl_extra = time_once("setup/jl_extra_keys", JlExtraFixture::generate);

    run_group("zk/curve", curve_zk_once);
    run_group("zk/pedersen_mod", || pedersen_mod_zk_once(&pedersen));
    run_group("zk/class_group", || class_group_zk_once(cl));
    run_group("zk/paillier", || paillier_zk_once(&paillier, &ntilde));
    run_group("zk/paillier_zk_facade", || {
        paillier_zk_facade_once(&paillier, &pedersen)
    });
    run_group("zk/joye_libert", || joye_libert_zk_once(&jl, &jl_extra));
    run_group("zk/evrf", evrf_zk_once);
}

fn run_group(name: &str, f: impl FnOnce()) {
    eprintln!("# {name}");
    f();
}

fn curve_zk_once() {
    {
        use tecdsa_curve::zk::dlog::DlogProof;
        let x = random_scalar();
        let p = C::generator() * x;
        let proof = time_once("zk/curve/dlog/prove", || {
            DlogProof::<C>::prove(&x, &random_scalar(), &p, b"bench")
        });
        time_once("zk/curve/dlog/verify", || proof.verify(&p, b"bench"));
    }

    {
        use tecdsa_curve::zk::ddh::{DdhProof, DdhStatement, DdhWitness};
        let w = random_scalar();
        let gen = C::generator();
        let a = gen * random_scalar();
        let stmt = DdhStatement::<C> {
            g: gen,
            a,
            b: gen * w,
            c: a * w,
        };
        let wit = DdhWitness::<C> { w };
        let proof = time_once("zk/curve/ddh/prove", || {
            DdhProof::prove(&stmt, &wit, &mut OsRng)
        });
        time_once("zk/curve/ddh/verify", || proof.verify(&stmt));
    }

    {
        use tecdsa_curve::zk::egexp::{EgexpProof, EgexpStatement, EgexpWitness};
        let dk = random_scalar();
        let pk = C::generator() * dk;
        let x = random_scalar();
        let r = random_scalar();
        let stmt = EgexpStatement::<C> {
            p: pk,
            a: C::generator() * r,
            b: pk * r + C::generator() * x,
        };
        let wit = EgexpWitness::<C> { x, r };
        let proof = time_once("zk/curve/egexp/prove", || {
            EgexpProof::prove(&stmt, &wit, &mut OsRng)
        });
        time_once("zk/curve/egexp/verify", || proof.verify(&stmt));
    }

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
        let stmt = ProdStatement::<C> {
            p: pk,
            a,
            b: b_pt,
            c: gen * t,
            d: pk * t + gen * y,
            e_pt: a * y + gen * r,
            f: b_pt * y + pk * r,
        };
        let wit = ProdWitness::<C> { y, t, r };
        let proof = time_once("zk/curve/prod/prove", || {
            ProdProof::prove(&stmt, &wit, &mut OsRng)
        });
        time_once("zk/curve/prod/verify", || proof.verify(&stmt));
    }

    {
        use tecdsa_curve::zk::rerandom::{ReProof, ReStatement, ReWitness};
        let gen = C::generator();
        let p_pt = C::nums_pedersen_h();
        let r = random_scalar();
        let s = random_scalar();
        let a = gen * random_scalar();
        let b = p_pt * random_scalar();
        let stmt = ReStatement::<C> {
            g: gen,
            p: p_pt,
            a,
            b,
            a_prime: gen * r + a * s,
            b_prime: p_pt * r + b * s,
        };
        let wit = ReWitness::<C> { r, s };
        let proof = time_once("zk/curve/rerandom/prove", || {
            ReProof::prove(&stmt, &wit, &random_scalar(), &random_scalar())
        });
        time_once("zk/curve/rerandom/verify", || proof.verify(&stmt));
    }
}

fn pedersen_mod_zk_once(ped: &PedersenFixture) {
    use tecdsa_pedersen_mod::zk::{PiMod, PiPrm};

    let params = &ped.params;
    let secret = &ped.secret;
    let piprm = time_once("zk/pedersen_mod/pi_prm/prove", || {
        PiPrm::prove(params, secret, &mut OsRng)
    });
    time_once("zk/pedersen_mod/pi_prm/verify", || piprm.verify(params));

    let pimod = time_once("zk/pedersen_mod/pi_mod/prove", || {
        PiMod::prove(params, secret, &mut OsRng).expect("pimod prove")
    });
    time_once("zk/pedersen_mod/pi_mod/verify", || {
        pimod.verify(params, &mut OsRng)
    });
}

fn class_group_zk_once(
    cl: (
        tecdsa_class_group::cl::ClSetup,
        tecdsa_class_group::cl::ClSecretKey,
        tecdsa_class_group::cl::ClPublicKey,
    ),
) {
    let (mut setup, sk, pk) = cl;
    let sk_bytes = setup.sk_to_bytes(&sk).expect("sk_bytes");
    let m_bytes = 42u32.to_be_bytes().to_vec();

    {
        use tecdsa_class_group::zk::r_enc::REncProof;
        let (r_sk, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_bytes)
            .expect("enc");
        let proof = time_once("zk/class_group/r_enc/prove", || {
            REncProof::prove(&mut setup, &pk, &ct, &m_bytes, &r_bytes).expect("r_enc prove")
        });
        time_once("zk/class_group/r_enc/verify", || {
            proof.verify(&setup, &pk, &ct).expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_key::RKeyProof;
        let proof = time_once("zk/class_group/r_key/prove", || {
            RKeyProof::prove(&mut setup, &pk, &sk_bytes).expect("r_key prove")
        });
        time_once("zk/class_group/r_key/verify", || {
            proof.verify(&setup, &pk).expect("verify")
        });
    }

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
        let proof = time_once("zk/class_group/r_dl_cl/prove", || {
            RDlClProof::prove(&mut setup, &x_point, &ct, &ct_x, &x_bytes).expect("prove")
        });
        time_once("zk/class_group/r_dl_cl/verify", || {
            proof.verify(&setup, &x_point, &ct, &ct_x).expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_enc_pc::REncPcProof;
        let (r_sk, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_bytes)
            .expect("enc");
        let y = setup.power_of_f_bytes(&m_bytes).expect("f^m");
        let proof = time_once("zk/class_group/r_enc_pc/prove", || {
            REncPcProof::prove(&mut setup, &pk, &ct, &y, &m_bytes, &r_bytes).expect("prove")
        });
        time_once("zk/class_group/r_enc_pc/verify", || {
            proof.verify(&setup, &pk, &ct, &y).expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_pc_dl::RPcDlProof;
        let y = setup.power_of_f_bytes(&m_bytes).expect("f^m");
        let proof = time_once("zk/class_group/r_pc_dl/prove", || {
            RPcDlProof::prove(&mut setup, &y, &m_bytes).expect("prove")
        });
        time_once("zk/class_group/r_pc_dl/verify", || {
            proof.verify(&setup, &y).expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_dec_dl::RDecDlProof;
        let (r_sk, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_bytes)
            .expect("enc");
        let (c1, _c2) = setup.ct_components(&ct).expect("comp");
        let pd = setup.exp_bytes(&c1, &sk_bytes).expect("pd");
        let proof = time_once("zk/class_group/r_dec_dl/prove", || {
            RDecDlProof::prove(&mut setup, &pk, &ct, &pd, &sk_bytes).expect("prove")
        });
        time_once("zk/class_group/r_dec_dl/verify", || {
            proof.verify(&setup, &pk, &ct, &pd).expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_cl_kwlg::RClKwlgProof;
        let proof = time_once("zk/class_group/r_cl_kwlg/prove", || {
            RClKwlgProof::prove(&mut setup, &pk, &sk_bytes).expect("prove")
        });
        time_once("zk/class_group/r_cl_kwlg/verify", || {
            proof.verify(&setup, &pk).expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_bint::RBintProof;
        let x_bytes = 42u32.to_be_bytes().to_vec();
        let y = setup.power_of_h("42").expect("h^x");
        let bound = setup.secretkey_bound_bytes().expect("bound");
        let proof = time_once("zk/class_group/r_bint/prove", || {
            RBintProof::prove(&mut setup, &y, &x_bytes).expect("prove")
        });
        time_once("zk/class_group/r_bint/verify", || {
            proof.verify(&setup, &y, &bound).expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_com_kwlg::RComKwlgProof;
        let (r_sk2, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk2).expect("r_bytes");
        let fm = setup.power_of_f_bytes(&m_bytes).expect("f^m");
        let hr = setup.power_of_h_bytes(&r_bytes).expect("h^r");
        let commit = setup.compose(&fm, &hr).expect("compose");
        let proof = time_once("zk/class_group/r_com_kwlg/prove", || {
            RComKwlgProof::prove(&mut setup, &commit, &m_bytes, &r_bytes).expect("prove")
        });
        time_once("zk/class_group/r_com_kwlg/verify", || {
            proof.verify(&setup, &commit).expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_gdec_cl::RGdecClProof;
        let sk_dec = sk.to_string();
        let ct = setup.encrypt(&pk, "42").expect("encrypt");
        let (c1, c2) = setup.ct_components(&ct).expect("comp");
        let mut c1_sk = setup.exp(&c1, &sk_dec).expect("c1^sk");
        c1_sk.neg();
        let dec_result = setup.compose(&c2, &c1_sk).expect("dec");
        let proof = time_once("zk/class_group/r_gdec_cl/prove", || {
            RGdecClProof::prove(&mut setup, &pk, &ct, &dec_result, &sk_bytes).expect("prove")
        });
        time_once("zk/class_group/r_gdec_cl/verify", || {
            proof.verify(&setup, &pk, &ct, &dec_result).expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_cl_dl::RClDlProof;
        let x_bytes = 77u32.to_be_bytes().to_vec();
        let (r_sk2, _) = setup.keygen().expect("keygen");
        let r_bytes = setup.sk_to_bytes(&r_sk2).expect("r_bytes");
        let ct = setup
            .encrypt_with_r_bytes(&pk, &x_bytes, &r_bytes)
            .expect("enc");
        let y = setup.power_of_f_bytes(&x_bytes).expect("f^x");
        let proof = time_once("zk/class_group/r_cl_dl/prove", || {
            RClDlProof::prove(&mut setup, &pk, &ct, &y, &x_bytes, &r_bytes).expect("prove")
        });
        time_once("zk/class_group/r_cl_dl/verify", || {
            proof.verify(&setup, &pk, &ct, &y).expect("verify")
        });
    }

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
        let proof = time_once("zk/class_group/r_cl_dl_ec/prove", || {
            RClDlEcProof::prove(&mut setup, &pk, &ct, &big_v_bytes, &v_bytes, &r_bytes)
                .expect("prove")
        });
        time_once("zk/class_group/r_cl_dl_ec/verify", || {
            proof
                .verify(&setup, &pk, &ct, &big_v_bytes)
                .expect("verify")
        });
    }

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
        let proof = time_once("zk/class_group/r_ddh_cl/prove", || {
            RDdhClProof::prove(&mut setup, &g_qfi, &a, &b_qfi, &c_qfi, &x_bytes).expect("prove")
        });
        time_once("zk/class_group/r_ddh_cl/verify", || {
            proof
                .verify(&setup, &g_qfi, &a, &b_qfi, &c_qfi)
                .expect("verify")
        });
    }

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
        let proof = time_once("zk/class_group/r_el_cl/prove", || {
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
            .expect("prove")
        });
        time_once("zk/class_group/r_el_cl/verify", || {
            proof
                .verify(
                    &setup, &gen, &elek, &elg_0, &elg_1, &ck_0, &ck_1, &cgk_0, &cgk_1,
                )
                .expect("verify")
        });
    }

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
        let proof = time_once("zk/class_group/r_ped_ec/prove", || {
            RPedEcProof::prove(&mut setup, &pk, &pe_a, &big_v_bytes, &x_bytes, &r_bytes_nim)
                .expect("prove")
        });
        time_once("zk/class_group/r_ped_ec/verify", || {
            proof
                .verify(&setup, &pk, &pe_a, &big_v_bytes)
                .expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_aff_com::RAffComProof;
        let x_bytes = 5u32.to_be_bytes().to_vec();
        let y_bytes = 10u32.to_be_bytes().to_vec();
        let (r_sk2, _) = setup.keygen().expect("kg");
        let r_base = setup.sk_to_bytes(&r_sk2).expect("bytes");
        let r_base_dec = num_bigint::BigUint::from_bytes_be(&r_base).to_str_radix(10);
        let ct_in = setup.encrypt_with_r(&pk, "100", &r_base_dec).expect("enc");
        let (r_sk3, _) = setup.keygen().expect("kg");
        let r1 = setup.sk_to_bytes(&r_sk3).expect("bytes");
        let q_bu = num_bigint::BigUint::from_str_radix(tecdsa_class_group::cl::SECP256K1_ORDER, 10)
            .expect("q");
        let m_out = (num_bigint::BigUint::from(5u32) * num_bigint::BigUint::from(100u32)
            + num_bigint::BigUint::from(10u32))
            % &q_bu;
        let r_out = (num_bigint::BigUint::from(5u32) * num_bigint::BigUint::from_bytes_be(&r_base)
            + num_bigint::BigUint::from_bytes_be(&r1))
        .to_str_radix(10);
        let ct_out = setup
            .encrypt_with_r(&pk, &m_out.to_str_radix(10), &r_out)
            .expect("enc_out");
        let (r_sk4, _) = setup.keygen().expect("kg");
        let r2 = setup.sk_to_bytes(&r_sk4).expect("bytes");
        let r2_dec = num_bigint::BigUint::from_bytes_be(&r2).to_str_radix(10);
        let h_r2 = setup.power_of_h(&r2_dec).expect("h_r2");
        let f_x = setup.power_of_f("5").expect("f_x");
        let commitment = setup.compose(&h_r2, &f_x).expect("com");
        let proof = time_once("zk/class_group/r_aff_com/prove", || {
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
            .expect("prove")
        });
        time_once("zk/class_group/r_aff_com/verify", || {
            proof
                .verify(&setup, &pk, &ct_in, &ct_out, &commitment)
                .expect("verify")
        });
    }

    {
        use tecdsa_class_group::zk::r_m_aff_dl::RMAffDlProof;
        let x_bytes = 3u32.to_be_bytes().to_vec();
        let y_bytes = 7u32.to_be_bytes().to_vec();
        let (r_sk2, _) = setup.keygen().expect("kg");
        let r_base = setup.sk_to_bytes(&r_sk2).expect("bytes");
        let (r_sk3, _) = setup.keygen().expect("kg");
        let r_enc = setup.sk_to_bytes(&r_sk3).expect("bytes");
        let r_base_dec = num_bigint::BigUint::from_bytes_be(&r_base).to_str_radix(10);
        let ct_in = setup.encrypt_with_r(&pk, "100", &r_base_dec).expect("enc");
        let q_bu = num_bigint::BigUint::from_str_radix(tecdsa_class_group::cl::SECP256K1_ORDER, 10)
            .expect("q");
        let m_out = (num_bigint::BigUint::from(3u32) * num_bigint::BigUint::from(100u32)
            + num_bigint::BigUint::from(7u32))
            % &q_bu;
        let r_out = (num_bigint::BigUint::from(3u32) * num_bigint::BigUint::from_bytes_be(&r_base)
            + num_bigint::BigUint::from_bytes_be(&r_enc))
        .to_str_radix(10);
        let ct_out = setup
            .encrypt_with_r(&pk, &m_out.to_str_radix(10), &r_out)
            .expect("enc_out");
        let y_point = setup.power_of_f("7").expect("f^y");
        let proof = time_once("zk/class_group/r_m_aff_dl/prove", || {
            RMAffDlProof::prove(
                &mut setup, &pk, &ct_in, &ct_out, &y_point, &x_bytes, &y_bytes, &r_enc,
            )
            .expect("prove")
        });
        time_once("zk/class_group/r_m_aff_dl/verify", || {
            proof
                .verify(&setup, &pk, &ct_in, &ct_out, &y_point)
                .expect("verify")
        });
    }

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
        let q_bu = num_bigint::BigUint::from_bytes_be(&q_bytes);
        let beta_bu = num_bigint::BigUint::from_bytes_be(&beta_bytes);
        let neg_beta_bu = (&q_bu - &beta_bu % &q_bu) % &q_bu;
        let neg_beta = neg_beta_bu.to_bytes_be();
        let f_neg_beta = setup.power_of_f_bytes(&neg_beta).expect("f^-b");
        let d2 = setup.compose(&c2_k, &f_neg_beta).expect("d2");
        let k_scalar = tecdsa_curve::conv::bytes_to_scalar::<Secp256k1>(&k_star);
        let r_point =
            <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR * k_scalar;
        let beta_scalar = k256::Scalar::from(17u64);
        let b_point = <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR
            * beta_scalar;
        let proof = time_once("zk/class_group/r_m_aff_dl_ec/prove", || {
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
            .expect("prove")
        });
        time_once("zk/class_group/r_m_aff_dl_ec/verify", || {
            proof
                .verify(&setup, &c1, &c2, &d1, &d2, &r_point, &b_point)
                .expect("verify")
        });
    }

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
        let q_bu = num_bigint::BigUint::from_bytes_be(&setup.q_bytes().expect("q"));
        let (rho_sk, _) = setup.keygen().expect("kg");
        let rho_bytes = setup.sk_to_bytes(&rho_sk).expect("rho");
        let c1_sh = setup.power_of_h_bytes(&rho_bytes).expect("h^rho");
        let mut coeffs = Vec::new();
        for _ in 0..t {
            let (sk_c, _) = setup.keygen().expect("kg");
            let c_bytes = setup.sk_to_bytes(&sk_c).expect("c");
            coeffs.push(num_bigint::BigUint::from_bytes_be(&c_bytes) % &q_bu);
        }
        let mut c2s_sh = Vec::new();
        for (idx, &id) in party_ids.iter().enumerate() {
            let x = num_bigint::BigUint::from(id);
            let mut val = num_bigint::BigUint::ZERO;
            let mut x_pow = num_bigint::BigUint::from(1u32);
            for coeff in &coeffs {
                val = (&val + coeff * &x_pow) % &q_bu;
                x_pow = (&x_pow * &x) % &q_bu;
            }
            let share_bytes = val.to_bytes_be();
            let pk_elt = pks[idx].elt();
            let pk_rho = setup.exp_bytes(pk_elt, &rho_bytes).expect("pk^rho");
            let f_v = setup.power_of_f_bytes(&share_bytes).expect("f^v");
            let c2 = setup.compose(&pk_rho, &f_v).expect("compose");
            c2s_sh.push(c2);
        }
        let c2_refs: Vec<&_> = c2s_sh.iter().collect();
        let proof = time_once("zk/class_group/r_sh/prove", || {
            RShProof::prove(
                &mut setup, &party_ids, t, &pk_refs, &c1_sh, &c2_refs, &rho_bytes,
            )
            .expect("prove")
        });
        time_once("zk/class_group/r_sh/verify", || {
            proof
                .verify(&setup, &party_ids, t, &pk_refs, &c1_sh, &c2_refs)
                .expect("verify")
        });
    }
}

fn paillier_zk_once(pf: &PaillierFixture, nt: &NTildeFixture) {
    let dk = &pf.dk;
    let ek = &pf.ek;

    {
        use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
        let proof = time_once("zk/paillier/correct_key_ni/prove", || {
            NICorrectKeyProof::prove(dk, b"bench")
        });
        time_once("zk/paillier/correct_key_ni/verify", || {
            proof.verify(ek, b"bench")
        });
    }

    {
        use tecdsa_paillier::zk::homo_elgamal::{
            HomoElGamalProof, HomoElGamalStatement, HomoElGamalWitness,
        };
        let gen = C::generator();
        let h = gen * random_scalar();
        let y_pt = gen * random_scalar();
        let x = random_scalar();
        let r = random_scalar();
        let stmt = HomoElGamalStatement::<C> {
            G: gen,
            H: h,
            Y: y_pt,
            D: h * x + y_pt * r,
            E: gen * r,
        };
        let wit = HomoElGamalWitness::<C> { x, r };
        let proof = time_once("zk/paillier/homo_elgamal/prove", || {
            HomoElGamalProof::prove(&wit, &stmt, &mut OsRng)
        });
        time_once("zk/paillier/homo_elgamal/verify", || {
            proof.verify(&stmt).expect("homo_elgamal verify")
        });
    }

    {
        use tecdsa_paillier::zk::pi_eq::PiEqProof;
        let x1 = random_scalar();
        let x1_bytes = scalar_to_bytes(&x1);
        let x1_point = C::generator() * x1;
        let q = group_order();
        let t = sample_below_int(&q);
        let x_hat_1 = Integer::from_bytes_msf(&x1_bytes) + &t * &q;
        let (ct, nonce) = paillier_encrypt(ek, &x_hat_1);
        let proof = time_once("zk/paillier/pi_eq/prove", || {
            PiEqProof::<C>::prove(
                b"bench", ek, dk, &ct, &x1_point, &x_hat_1, &nonce, &mut OsRng,
            )
        });
        time_once("zk/paillier/pi_eq/verify", || {
            proof.verify(b"bench", ek, &ct, &x1_point)
        });
    }

    {
        use tecdsa_paillier::zk::homo_mult::{HomoMultProof, HomoMultStatement, HomoMultWitness};
        let q = group_order();
        let eta = sample_below(&q);
        let (c1, r_c1) = paillier_encrypt(ek, &eta);
        let some_val = sample_below(&q);
        let (c2, _) = paillier_encrypt(ek, &some_val);
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
            h1: nt.h1.clone(),
            h2: nt.h2.clone(),
            N_tilde: nt.n_tilde.clone(),
        };
        let wit = HomoMultWitness { eta, r_c1, r_c3 };
        let proof = time_once("zk/paillier/homo_mult/prove", || {
            HomoMultProof::prove::<C>(&wit, &stmt, &mut OsRng)
        });
        time_once("zk/paillier/homo_mult/verify", || {
            proof.verify::<C>(&stmt).expect("homo_mult verify")
        });
    }

    {
        use tecdsa_paillier::zk::mta_range::AliceProof;
        let q = group_order();
        let a = sample_below(&q);
        let (cipher, r) = paillier_encrypt(ek, &a);
        let ntilde = nt.to_mta_params();
        let proof = time_once("zk/paillier/alice_range/prove", || {
            AliceProof::prove::<C>(&a, &cipher, ek.n(), ek.nn(), &ntilde, &r, &mut OsRng)
        });
        time_once("zk/paillier/alice_range/verify", || {
            proof
                .verify::<C>(&cipher, ek.n(), ek.nn(), &ntilde)
                .expect("alice_range verify")
        });
    }

    {
        use tecdsa_paillier::zk::range_ni::RangeProofNi;
        let q = group_order();
        let x = sample_below(&q);
        let (ct, r) = paillier_encrypt(ek, &x);
        let proof = time_once("zk/paillier/range_ni/prove", || {
            RangeProofNi::prove(dk, ek, &ct, &x, &r, &q, &mut OsRng).expect("range_ni prove")
        });
        time_once("zk/paillier/range_ni/verify", || proof.verify(ek, &ct, &q));
    }

    {
        use tecdsa_paillier::zk::pdl_slack::{PdlSlackProof, PdlSlackStatement, PdlSlackWitness};
        let q = group_order();
        let x = sample_below(&q);
        let (ciphertext, r) = paillier_encrypt(ek, &x);
        let x_scalar = tecdsa_paillier::conv::integer_to_scalar::<C>(&x);
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
        let proof = time_once("zk/paillier/pdl_slack/prove", || {
            PdlSlackProof::prove(&wit, &stmt, &mut OsRng)
        });
        time_once("zk/paillier/pdl_slack/verify", || {
            proof.verify(&stmt).expect("pdl_slack verify")
        });
    }

    {
        use tecdsa_paillier::zk::pia_pib::PiBProof;
        let q = group_order();
        let b_val = sample_below(&q);
        let (c_b, r_b) = paillier_encrypt(ek, &b_val);
        let proof = time_once("zk/paillier/pib/prove", || {
            PiBProof::prove(ek, &c_b, &b_val, &r_b, &q, &mut OsRng)
        });
        time_once("zk/paillier/pib/verify", || proof.verify(ek, &c_b, &q));
    }

    {
        use tecdsa_paillier::zk::mta_range::BobProofExt;
        let q = group_order();
        let ntilde = nt.to_mta_params();
        let a = sample_below(&q);
        let (enc_a, _) = paillier_encrypt(ek, &a);
        let b_val = sample_below(&q);
        let b_scalar = tecdsa_paillier::conv::integer_to_scalar::<C>(&b_val);
        let x_pt = C::generator() * b_scalar;
        let beta_prim = sample_below(&Integer::from_bytes_msf(&ek.half_n().to_bytes_msf()));
        let r_bob = Integer::sample_in_mult_group_of(&mut OsRng, ek.n());
        let b_times_enc_a = ek.omul(&b_val, &enc_a).expect("omul");
        let enc_beta = ek.encrypt_with(&beta_prim, &r_bob).expect("encrypt beta");
        let mta_out = ek.oadd(&b_times_enc_a, &enc_beta).expect("oadd");
        let proof = time_once("zk/paillier/bob_ext/prove", || {
            BobProofExt::<C>::prove(
                &enc_a,
                &mta_out,
                &b_val,
                &beta_prim,
                ek.n(),
                ek.nn(),
                &ntilde,
                &r_bob,
                &mut OsRng,
            )
        });
        time_once("zk/paillier/bob_ext/verify", || {
            proof
                .verify(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde, &x_pt)
                .expect("bob_ext verify")
        });
    }

    {
        use tecdsa_paillier::zk::nonce_consist::{
            NonceConsistProof, NonceConsistStatement, NonceConsistWitness,
        };
        let q = group_order();
        let gen = C::generator();
        let eta1 = sample_below(&q);
        let eta1_scalar = tecdsa_paillier::conv::integer_to_scalar::<C>(&eta1);
        let r_i = gen * eta1_scalar;
        let rho = sample_below(&q);
        let (u_ct, _) = paillier_encrypt(ek, &rho);
        let eta2 = sample_below(&q);
        let r_c = Integer::sample_in_mult_group_of(&mut OsRng, ek.n());
        let gamma_paillier = ek.n() + Integer::one();
        let w_i = {
            let u_eta1 = pow_mod_signed(&u_ct, &eta1, ek.nn());
            let q_eta2 = &q * &eta2;
            let g_q_eta2 = pow_mod_signed(&gamma_paillier, &q_eta2, ek.nn());
            let r_c_n = pow_mod_signed(&r_c, ek.n(), ek.nn());
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
        let proof = time_once("zk/paillier/nonce_consist/prove", || {
            NonceConsistProof::prove(&wit, &stmt, &mut OsRng)
        });
        time_once("zk/paillier/nonce_consist/verify", || {
            proof.verify(&stmt).expect("nonce_consist verify")
        });
    }

    {
        use tecdsa_paillier::zk::pia_pib::PiAProof;
        let q = group_order();
        let b_val = sample_below(&q);
        let (c_b, _) = paillier_encrypt(ek, &b_val);
        let a = sample_below(&q);
        let alpha_prime = sample_below(&q);
        let r_prime = Integer::sample_in_mult_group_of(&mut OsRng, ek.n());
        let c_b_a = pow_mod_signed(&c_b, &a, ek.nn());
        let enc_alpha = ek.encrypt_with(&alpha_prime, &r_prime).expect("enc");
        let c_a = (c_b_a * enc_alpha).modulo(ek.nn());
        let proof = time_once("zk/paillier/pia/prove", || {
            PiAProof::prove(ek, &c_a, &c_b, &a, &alpha_prime, &r_prime, &q, &mut OsRng)
        });
        time_once("zk/paillier/pia/verify", || {
            proof.verify(ek, &c_a, &c_b, &q)
        });
    }

    {
        use tecdsa_paillier::zk::mta_range::BobProof;
        let q = group_order();
        let ntilde = nt.to_mta_params();
        let a = sample_below(&q);
        let (enc_a, _) = paillier_encrypt(ek, &a);
        let b_val = sample_below(&q);
        let beta_prim = sample_below(&Integer::from_bytes_msf(&ek.half_n().to_bytes_msf()));
        let r_bob = Integer::sample_in_mult_group_of(&mut OsRng, ek.n());
        let b_times_enc_a = ek.omul(&b_val, &enc_a).expect("omul");
        let enc_beta = ek.encrypt_with(&beta_prim, &r_bob).expect("enc");
        let mta_out = ek.oadd(&b_times_enc_a, &enc_beta).expect("oadd");
        let (proof, _) = time_once("zk/paillier/bob/prove", || {
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
                &mut OsRng,
            )
        });
        time_once("zk/paillier/bob/verify", || {
            proof
                .verify::<C>(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde)
                .expect("bob verify")
        });
    }

    {
        use tecdsa_paillier::zk::pdl::pdl_verify;
        let x1 = random_scalar();
        let q1 = C::generator() * x1;
        let x1_int = Integer::from_bytes_msf(&scalar_to_bytes(&x1));
        let (c_key, _) = paillier_encrypt(ek, &x1_int);
        time_once("zk/paillier/pdl_transcript/full", || {
            pdl_verify::<C>(dk, ek, &x1, &c_key, &q1, &mut OsRng)
                .expect("PDL transcript fixture invalid")
        });
    }
}

fn paillier_zk_facade_once(pf: &PaillierFixture, ped: &PedersenFixture) {
    use sha2::Sha256;
    use tecdsa_paillier::zk::{
        bridge::{pedersen_to_aux, point_to_ge, scalar_to_ge},
        paillier_zk,
    };

    #[derive(udigest::Digestable)]
    struct BenchTag(&'static str);

    let dk = &pf.dk;
    let ek = &pf.ek;
    let aux = pedersen_to_aux(&ped.params);
    let tag = BenchTag("bench");

    {
        use paillier_zk::paillier_encryption_in_range as pi_enc;
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
        let proof = time_once("zk/paillier_zk_facade/pi_enc/prove", || {
            pi_enc::non_interactive::prove::<Sha256>(&tag, &aux, data, pdata, &security, &mut OsRng)
                .expect("pi_enc prove")
        });
        time_once("zk/paillier_zk_facade/pi_enc/verify", || {
            pi_enc::non_interactive::verify::<Sha256>(&tag, &aux, data, &security, &proof)
                .expect("pi_enc verify")
        });
    }

    {
        use paillier_zk::no_small_factor as pi_fac;
        let n = dk.n().clone();
        let p = dk.p().clone();
        let q = dk.q().clone();
        let n_root = n.sqrt_ref().expect("sqrt");
        let data = pi_fac::Data {
            n: &n,
            n_root: &n_root,
        };
        let pdata = pi_fac::PrivateData { p: &p, q: &q };
        let security = pi_fac::SecurityParams {
            l: 256,
            epsilon: 512,
        };
        let proof = time_once("zk/paillier_zk_facade/pi_fac/prove", || {
            pi_fac::non_interactive::prove::<Sha256>(&tag, &aux, data, pdata, &security, &mut OsRng)
                .expect("pi_fac prove")
        });
        time_once("zk/paillier_zk_facade/pi_fac/verify", || {
            pi_fac::non_interactive::verify::<Sha256>(&tag, &aux, data, &security, &proof)
                .expect("pi_fac verify")
        });
    }

    {
        use paillier_zk::paillier_blum_modulus as pi_mod;
        let n = dk.n().clone();
        let p = dk.p().clone();
        let q = dk.q().clone();
        let data = pi_mod::Data { n: &n };
        let pdata = pi_mod::PrivateData { p: &p, q: &q };
        let proof = time_once("zk/paillier_zk_facade/pi_mod_upstream/prove", || {
            pi_mod::non_interactive::prove::<80, Sha256>(&tag, data, pdata, &mut OsRng)
                .expect("pi_mod prove")
        });
        time_once("zk/paillier_zk_facade/pi_mod_upstream/verify", || {
            pi_mod::non_interactive::verify::<80, Sha256>(&tag, data, &proof, &mut OsRng)
                .expect("pi_mod verify")
        });
    }

    {
        use paillier_zk::paillier_affine_operation_in_range as pi_aff;
        type GE = generic_ec::curves::Secp256k1;
        let x_val = Integer::from(7);
        let y_val = Integer::from(13);
        let (ct_c, _) = paillier_encrypt(ek, &Integer::from(100));
        let (ct_y, nonce_y) = paillier_encrypt(ek, &y_val);
        let nonce_aff = Integer::sample_in_mult_group_of(&mut OsRng, ek.n());
        let d_val = {
            let c_x = pow_mod_signed(&ct_c, &x_val, ek.nn());
            let enc_y = ek.encrypt_with(&y_val, &nonce_aff).expect("enc_y");
            (c_x * enc_y).modulo(ek.nn())
        };
        let x_scalar = tecdsa_paillier::conv::integer_to_scalar::<C>(&x_val);
        let x_point = C::generator() * x_scalar;
        let x_ge = point_to_ge(&x_point);
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
            l_y: 256,
            epsilon: 512,
        };
        let proof = time_once("zk/paillier_zk_facade/pi_aff_g/prove", || {
            pi_aff::non_interactive::prove::<GE, Sha256>(
                &tag, &aux, data, pdata, &security, &mut OsRng,
            )
            .expect("pi_aff prove")
        });
        time_once("zk/paillier_zk_facade/pi_aff_g/verify", || {
            pi_aff::non_interactive::verify::<GE, Sha256>(&tag, &aux, data, &security, &proof)
                .expect("pi_aff verify")
        });
    }

    {
        use paillier_zk::dlog_with_el_gamal_commitment as pi_elog;
        type GE = generic_ec::curves::Secp256k1;
        let y = scalar_to_ge(&random_scalar());
        let lambda = scalar_to_ge(&random_scalar());
        let g = generic_ec::Point::<GE>::generator();
        let h = g * generic_ec::Scalar::<GE>::random(&mut OsRng);
        let x = g * y;
        let l = g * lambda;
        let m = g * y + x * lambda;
        let y_pt = h * y;
        let data = pi_elog::Data::<GE> {
            l: &l,
            m: &m,
            x: &x,
            y: &y_pt,
            h: &h,
        };
        let pdata = pi_elog::PrivateData::<GE> {
            y: &y,
            lambda: &lambda,
        };
        let proof = time_once("zk/paillier_zk_facade/pi_elog/prove", || {
            pi_elog::non_interactive::prove::<GE, Sha256>(&tag, data, pdata, &mut OsRng)
                .expect("pi_elog prove")
        });
        time_once("zk/paillier_zk_facade/pi_elog/verify", || {
            pi_elog::non_interactive::verify::<GE, Sha256>(&tag, data, &proof)
                .expect("pi_elog verify")
        });
    }

    {
        use paillier_zk::{
            paillier_encryption_in_range_with_el_gamal as pi_enc_elg, IntegerExt as _,
        };
        type GE = generic_ec::curves::Secp256k1;
        let security = pi_enc_elg::SecurityParams {
            l: 256,
            epsilon: 512,
        };
        let plaintext = Integer::from_rng_half_pm(&mut OsRng, &(Integer::one() << security.l));
        let nonce = Integer::sample_in_mult_group_of(&mut OsRng, ek.n());
        let ct = ek.encrypt_with(&plaintext, &nonce).expect("enc");
        let a = generic_ec::Scalar::<GE>::random(&mut OsRng);
        let b = generic_ec::Scalar::<GE>::random(&mut OsRng);
        let g = generic_ec::Point::<GE>::generator();
        let a_pt = g * a;
        let b_pt = g * b;
        let x_pt = g * (a * b + plaintext.to_scalar());
        let data = pi_enc_elg::Data::<GE> {
            key: ek,
            ciphertext: &ct,
            a: &a_pt,
            b: &b_pt,
            x: &x_pt,
        };
        let pdata = pi_enc_elg::PrivateData::<GE> {
            plaintext: &plaintext,
            nonce: &nonce,
            b: &b,
        };
        let proof = time_once("zk/paillier_zk_facade/pi_enc_elg/prove", || {
            pi_enc_elg::non_interactive::prove::<GE, Sha256>(
                &tag, &aux, data, pdata, &security, &mut OsRng,
            )
            .expect("pi_enc_elg prove")
        });
        time_once("zk/paillier_zk_facade/pi_enc_elg/verify", || {
            pi_enc_elg::non_interactive::verify::<GE, Sha256>(&tag, &aux, data, &proof, &security)
                .expect("pi_enc_elg verify")
        });
    }
}

fn joye_libert_zk_once(jl: &JlFixture, jl_ex: &JlExtraFixture) {
    let jl_pk = &jl.pk;
    let jl_sk = &jl.sk;
    let jl_x = &jl.x;

    {
        use num_bigint::BigUint;
        use tecdsa_joye_libert::zk::zkjl_enc::ZkJlEncProof;
        let m = BigUint::from(42u64);
        let (ct, r) = tecdsa_joye_libert::enc_dec::encrypt(jl_pk, &m, &mut OsRng);
        let proof = time_once("zk/joye_libert/zkjl_enc/prove", || {
            ZkJlEncProof::prove(jl_pk, &ct.c, &m, &r, jl_pk.k, &mut OsRng)
        });
        time_once("zk/joye_libert/zkjl_enc/verify", || {
            proof.verify(jl_pk, &ct.c)
        });
    }

    {
        use tecdsa_joye_libert::zk::zkjlmod::ZkJlModProof;
        let proof = time_once("zk/joye_libert/zkjlmod/prove", || {
            ZkJlModProof::prove(jl_pk, jl_sk, jl_x, &mut OsRng)
        });
        time_once("zk/joye_libert/zkjlmod/verify", || proof.verify());
    }

    {
        use num_bigint::BigUint;
        use tecdsa_joye_libert::zk::zkjl_com::{jl_commit, ZkJlComProof};
        let m = BigUint::from(42u32);
        let r = OsRng.gen_biguint_below(&jl_pk.n);
        let c = jl_commit(jl_pk, &m, &r);
        let proof = time_once("zk/joye_libert/zkjl_com/prove", || {
            ZkJlComProof::prove(jl_pk, &c, &m, &r, jl_pk.k, &mut OsRng)
        });
        time_once("zk/joye_libert/zkjl_com/verify", || proof.verify(jl_pk, &c));
    }

    {
        use tecdsa_joye_libert::zk::zkqr2k::ZkQr2kProof;
        let proof = time_once("zk/joye_libert/zkqr2k/prove", || {
            ZkQr2kProof::prove(&jl_pk.n, jl_pk.k, jl_x, &jl_pk.h, &mut OsRng)
        });
        time_once("zk/joye_libert/zkqr2k/verify", || proof.verify());
    }

    {
        use tecdsa_joye_libert::zk::zkqr2kdl::ZkQr2kDlProof;
        let proof = time_once("zk/joye_libert/zkqr2kdl/prove", || {
            ZkQr2kDlProof::prove(
                &jl_pk.n,
                jl_pk.k,
                &jl_sk.alpha,
                &jl_pk.h,
                &jl_pk.y,
                &mut OsRng,
            )
        });
        time_once("zk/joye_libert/zkqr2kdl/verify", || proof.verify());
    }

    {
        use num_bigint::BigUint;
        use tecdsa_joye_libert::zk::{zkjl_com::jl_commit, zkjl_equ::ZkJlEquProof};
        let pk0 = &jl_ex.pk0;
        let m = BigUint::from(42u32);
        let r1 = OsRng.gen_biguint_below(&jl_pk.n);
        let r0 = OsRng.gen_biguint_below(&pk0.n);
        let c = jl_commit(jl_pk, &m, &r1);
        let c_prime = jl_commit(pk0, &m, &r0);
        let proof = time_once("zk/joye_libert/zkjl_equ/prove", || {
            ZkJlEquProof::prove(jl_pk, pk0, &c, &c_prime, &m, &r1, &r0, jl_pk.k, &mut OsRng)
        });
        time_once("zk/joye_libert/zkjl_equ/verify", || {
            proof.verify(jl_pk, pk0, &c, &c_prime)
        });
    }

    {
        use num_bigint::BigUint;
        use tecdsa_joye_libert::zk::zkjl_aff::ZkJlAffProof;
        let b_msg = BigUint::from(7u32);
        let (ct_b, _) = tecdsa_joye_libert::enc_dec::encrypt(jl_pk, &b_msg, &mut OsRng);
        let a = BigUint::from(5u32);
        let alpha = BigUint::from(13u32);
        let r_aff = OsRng.gen_biguint_below(&jl_pk.n);
        let c_a = ct_b.c.modpow(&a, &jl_pk.n);
        let y_alpha = jl_pk.y.modpow(&alpha, &jl_pk.n);
        let h_r = jl_pk.h.modpow(&r_aff, &jl_pk.n);
        let c_aff = (&c_a * &y_alpha % &jl_pk.n) * &h_r % &jl_pk.n;
        let proof = time_once("zk/joye_libert/zkjl_aff/prove", || {
            ZkJlAffProof::prove(
                jl_pk, &ct_b.c, &c_aff, &a, &alpha, &r_aff, jl_pk.k, jl_pk.k, &mut OsRng,
            )
        });
        time_once("zk/joye_libert/zkjl_aff/verify", || {
            proof.verify(jl_pk, &ct_b.c, &c_aff)
        });
    }

    {
        use num_bigint::BigUint;
        use tecdsa_joye_libert::zk::zkjlv_com::{jl_vec_commit, ZkJlvComProof};
        let ell = 3;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = OsRng.gen_biguint_below(&jl_pk.n);
            let y_i = jl_x.modpow(&alpha_i, &jl_pk.n);
            y_vec.push(y_i);
        }
        let m_vec = vec![
            BigUint::from(42u32),
            BigUint::from(17u32),
            BigUint::from(99u32),
        ];
        let b_bits_vec = vec![32u32, 32, 32];
        let r_vc = OsRng.gen_biguint_below(&jl_pk.n);
        let c_vc = jl_vec_commit(jl_pk, &y_vec, &m_vec, &r_vc);
        let proof = time_once("zk/joye_libert/zkjlv_com/prove", || {
            ZkJlvComProof::prove(jl_pk, &y_vec, &c_vc, &m_vec, &r_vc, &b_bits_vec, &mut OsRng)
        });
        time_once("zk/joye_libert/zkjlv_com/verify", || {
            proof.verify(jl_pk, &y_vec, &c_vc)
        });
    }

    {
        use num_bigint::BigUint;
        use tecdsa_joye_libert::zk::{
            zkjl_com::jl_commit, zkjlv_com::jl_vec_commit, zkjlv_equ::ZkJlvEquProof,
        };
        let pk0 = &jl_ex.pk0;
        let ell = 2;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = OsRng.gen_biguint_below(&jl_pk.n);
            y_vec.push(jl_x.modpow(&alpha_i, &jl_pk.n));
        }
        let m_vec = vec![BigUint::from(42u32), BigUint::from(17u32)];
        let b_bits_vec = vec![32u32, 32];
        let r1 = OsRng.gen_biguint_below(&jl_pk.n);
        let c_ve = jl_vec_commit(jl_pk, &y_vec, &m_vec, &r1);
        let mut c_prime_vec = Vec::with_capacity(ell);
        let mut r0_vec = Vec::with_capacity(ell);
        for i in 0..ell {
            let r0 = OsRng.gen_biguint_below(&pk0.n);
            c_prime_vec.push(jl_commit(pk0, &m_vec[i], &r0));
            r0_vec.push(r0);
        }
        let proof = time_once("zk/joye_libert/zkjlv_equ/prove", || {
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
                &mut OsRng,
            )
        });
        time_once("zk/joye_libert/zkjlv_equ/verify", || {
            proof.verify(jl_pk, pk0, &y_vec, &c_ve, &c_prime_vec)
        });
    }
}

fn evrf_zk_once() {
    use tecdsa_evrf::{EvrfProof, EvrfSecretKey};
    let (sk, pk) = EvrfSecretKey::<C>::generate(&mut OsRng);
    let input = b"bench-input";
    let (output, proof) = time_once("zk/evrf/dleq/eval", || sk.eval(input, &mut OsRng));
    time_once("zk/evrf/dleq/prove", || {
        EvrfProof::prove(&sk, input, &output, &mut OsRng)
    });
    time_once("zk/evrf/dleq/verify", || proof.verify(&pk, input, &output));
}
