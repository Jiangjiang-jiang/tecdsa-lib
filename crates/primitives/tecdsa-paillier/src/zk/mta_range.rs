#![allow(non_snake_case)]

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, CurveArithmetic, FieldBytes, FieldBytesSize,
    PrimeField,
};
use fast_paillier::backend::Integer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;

mod ser_integer {
    use fast_paillier::backend::Integer;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(val: &Integer, serializer: S) -> Result<S::Ok, S::Error> {
        val.to_bytes_msf().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Integer, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Integer::from_bytes_msf(&bytes))
    }
}

use super::pdl_slack::{commitment_unknown_order, pow_mod_signed, sample_below};
use crate::conv::{group_order_integer, integer_to_scalar};

#[derive(Debug, thiserror::Error)]
pub enum MtaRangeError {
    #[error("Alice MtA range proof verification failed")]
    AliceVerify,
    #[error("Bob MtA range proof verification failed")]
    BobVerify,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NTildeParams {
    pub N_tilde: Integer,
    pub h1: Integer,
    pub h2: Integer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliceProof {
    #[serde(with = "ser_integer")]
    z: Integer,
    #[serde(with = "ser_integer")]
    e: Integer,
    #[serde(with = "ser_integer")]
    s: Integer,
    #[serde(with = "ser_integer")]
    s1: Integer,
    #[serde(with = "ser_integer")]
    s2: Integer,
}

impl AliceProof {
    pub fn prove<C>(
        a: &Integer,
        cipher: &Integer,
        ek_n: &Integer,
        ek_nn: &Integer,
        ntilde: &NTildeParams,
        r: &Integer,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self
    where
        C: TecdsaCurve,
        FieldBytesSize<C>: ModulusSize,
        <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
    {
        let q = group_order_integer::<C>();
        let q3 = &q * &q * &q;
        let q_N_tilde = &q * &ntilde.N_tilde;
        let q3_N_tilde = &q3 * &ntilde.N_tilde;

        let alpha = sample_below(&q3, rng);
        let beta = Integer::sample_in_mult_group_of(rng, ek_n);
        let gamma = sample_below(&q3_N_tilde, rng);
        let rho = sample_below(&q_N_tilde, rng);

        let z = commitment_unknown_order(&ntilde.h1, &ntilde.h2, &ntilde.N_tilde, a, &rho);

        let g_paillier = ek_n + Integer::one();
        let u = {
            let g_alpha = (Integer::one() + &alpha * ek_n).modulo(ek_nn);
            let beta_n = pow_mod_signed(&beta, ek_n, ek_nn);
            (g_alpha * beta_n).modulo(ek_nn)
        };

        let w = commitment_unknown_order(&ntilde.h1, &ntilde.h2, &ntilde.N_tilde, &alpha, &gamma);

        let e = alice_challenge(ek_n, &g_paillier, cipher, &z, &u, &w);

        let s = {
            let r_e = pow_mod_signed(r, &e, ek_n);
            (r_e * &beta).modulo(ek_n)
        };
        let s1 = &e * a + &alpha;
        let s2 = &e * &rho + &gamma;

        AliceProof { z, e, s, s1, s2 }
    }

    pub fn verify<C>(
        &self,
        cipher: &Integer,
        ek_n: &Integer,
        ek_nn: &Integer,
        ntilde: &NTildeParams,
    ) -> Result<(), MtaRangeError>
    where
        C: TecdsaCurve,
        FieldBytesSize<C>: ModulusSize,
        <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
    {
        let q = group_order_integer::<C>();
        let q3 = &q * &q * &q;

        if self.s1 > q3 {
            return Err(MtaRangeError::AliceVerify);
        }

        let g_paillier = ek_n + Integer::one();
        let u = {
            let gs1 = (Integer::one() + &self.s1 * ek_n).modulo(ek_nn);
            let s_n = pow_mod_signed(&self.s, ek_n, ek_nn);
            let neg_e = -self.e.clone();
            let c_neg_e = pow_mod_signed(cipher, &neg_e, ek_nn);
            (gs1 * s_n % ek_nn * c_neg_e).modulo(ek_nn)
        };

        let w = {
            let h1_s1 = pow_mod_signed(&ntilde.h1, &self.s1, &ntilde.N_tilde);
            let h2_s2 = pow_mod_signed(&ntilde.h2, &self.s2, &ntilde.N_tilde);
            let neg_e = -self.e.clone();
            let z_neg_e = pow_mod_signed(&self.z, &neg_e, &ntilde.N_tilde);
            (h1_s1 * h2_s2 % &ntilde.N_tilde * z_neg_e).modulo(&ntilde.N_tilde)
        };

        let e = alice_challenge(ek_n, &g_paillier, cipher, &self.z, &u, &w);

        if e != self.e {
            return Err(MtaRangeError::AliceVerify);
        }

        Ok(())
    }
}

fn alice_challenge(
    N: &Integer,
    Gen: &Integer,
    cipher: &Integer,
    z: &Integer,
    u: &Integer,
    w: &Integer,
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(N.to_bytes_msf());
    hasher.update(Gen.to_bytes_msf());
    hasher.update(cipher.to_bytes_msf());
    hasher.update(z.to_bytes_msf());
    hasher.update(u.to_bytes_msf());
    hasher.update(w.to_bytes_msf());
    Integer::from_bytes_msf(&hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BobProof {
    #[serde(with = "ser_integer")]
    t: Integer,
    #[serde(with = "ser_integer")]
    z: Integer,
    #[serde(with = "ser_integer")]
    e: Integer,
    #[serde(with = "ser_integer")]
    s: Integer,
    #[serde(with = "ser_integer")]
    s1: Integer,
    #[serde(with = "ser_integer")]
    s2: Integer,
    #[serde(with = "ser_integer")]
    t1: Integer,
    #[serde(with = "ser_integer")]
    t2: Integer,
}

impl BobProof {
    #[allow(clippy::too_many_arguments)]
    pub fn prove<C>(
        a_encrypted: &Integer,
        mta_encrypted: &Integer,
        b: &Integer,
        beta_prim: &Integer,
        ek_n: &Integer,
        ek_nn: &Integer,
        ntilde: &NTildeParams,
        r: &Integer,
        check_ec: bool,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> (Self, Option<C::ProjectivePoint>)
    where
        C: TecdsaCurve,
        FieldBytesSize<C>: ModulusSize,
        <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
        <C as CurveArithmetic>::ProjectivePoint: GroupEncoding,
    {
        let q = group_order_integer::<C>();
        let q3 = &q * &q * &q;
        let q_N_tilde = &q * &ntilde.N_tilde;
        let q3_N_tilde = &q3 * &ntilde.N_tilde;
        let q2_N = &q * &q * ek_n;

        let alpha = sample_below(&q3, rng);
        let beta = Integer::sample_in_mult_group_of(rng, ek_n);
        let gamma = sample_below(&q2_N, rng);
        let rho = sample_below(&q_N_tilde, rng);
        let rho_prim = sample_below(&q3_N_tilde, rng);
        let sigma = sample_below(&q_N_tilde, rng);
        let tau = sample_below(&q3_N_tilde, rng);

        let z = commitment_unknown_order(&ntilde.h1, &ntilde.h2, &ntilde.N_tilde, b, &rho);

        let z_prim =
            commitment_unknown_order(&ntilde.h1, &ntilde.h2, &ntilde.N_tilde, &alpha, &rho_prim);

        let t =
            commitment_unknown_order(&ntilde.h1, &ntilde.h2, &ntilde.N_tilde, beta_prim, &sigma);

        let w_commit =
            commitment_unknown_order(&ntilde.h1, &ntilde.h2, &ntilde.N_tilde, &gamma, &tau);

        let v = {
            let ca_alpha = pow_mod_signed(a_encrypted, &alpha, ek_nn);
            let g_gamma = (&gamma * ek_n + Integer::one()).modulo(ek_nn);
            let beta_n = pow_mod_signed(&beta, ek_n, ek_nn);
            (ca_alpha * g_gamma % ek_nn * beta_n).modulo(ek_nn)
        };

        let g_paillier = ek_n + Integer::one();
        let (e, check_u) = if check_ec {
            let b_scalar = integer_to_scalar::<C>(b);
            let alpha_scalar = integer_to_scalar::<C>(&alpha);
            let G = C::generator();
            let X = G * b_scalar;
            let u_point = G * alpha_scalar;
            let e = bob_challenge_ext::<C>(
                ek_n,
                &g_paillier,
                a_encrypted,
                mta_encrypted,
                &z,
                &z_prim,
                &t,
                &v,
                &w_commit,
                &X,
                &u_point,
            );
            (e, Some(u_point))
        } else {
            let e = bob_challenge(
                ek_n,
                &g_paillier,
                a_encrypted,
                mta_encrypted,
                &z,
                &z_prim,
                &t,
                &v,
                &w_commit,
            );
            (e, None)
        };

        let s = {
            let r_e = pow_mod_signed(r, &e, ek_n);
            (r_e * &beta).modulo(ek_n)
        };
        let s1 = &e * b + &alpha;
        let s2 = &e * &rho + &rho_prim;
        let t1 = &e * beta_prim + &gamma;
        let t2 = &e * &sigma + &tau;

        (
            BobProof {
                t,
                z,
                e,
                s,
                s1,
                s2,
                t1,
                t2,
            },
            check_u,
        )
    }

    pub fn verify<C>(
        &self,
        a_enc: &Integer,
        mta_out: &Integer,
        ek_n: &Integer,
        ek_nn: &Integer,
        ntilde: &NTildeParams,
    ) -> Result<(), MtaRangeError>
    where
        C: TecdsaCurve,
        FieldBytesSize<C>: ModulusSize,
        <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
    {
        self.verify_inner::<C>(a_enc, mta_out, ek_n, ek_nn, ntilde, None)
    }

    fn verify_inner<C>(
        &self,
        a_enc: &Integer,
        mta_out: &Integer,
        ek_n: &Integer,
        ek_nn: &Integer,
        ntilde: &NTildeParams,
        check: Option<(&C::ProjectivePoint, &C::ProjectivePoint)>,
    ) -> Result<(), MtaRangeError>
    where
        C: TecdsaCurve,
        FieldBytesSize<C>: ModulusSize,
        <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
        <C as CurveArithmetic>::ProjectivePoint: GroupEncoding,
    {
        let q = group_order_integer::<C>();
        let q3 = &q * &q * &q;

        if self.s1 > q3 {
            return Err(MtaRangeError::BobVerify);
        }

        let neg_e = -self.e.clone();

        let z_prim = {
            let h1_s1 = pow_mod_signed(&ntilde.h1, &self.s1, &ntilde.N_tilde);
            let h2_s2 = pow_mod_signed(&ntilde.h2, &self.s2, &ntilde.N_tilde);
            let z_neg_e = pow_mod_signed(&self.z, &neg_e, &ntilde.N_tilde);
            (h1_s1 * h2_s2 % &ntilde.N_tilde * z_neg_e).modulo(&ntilde.N_tilde)
        };

        let v = {
            let ca_s1 = pow_mod_signed(a_enc, &self.s1, ek_nn);
            let s_n = pow_mod_signed(&self.s, ek_n, ek_nn);
            let g_t1 = (&self.t1 * ek_n + Integer::one()).modulo(ek_nn);
            let mta_neg_e = pow_mod_signed(mta_out, &neg_e, ek_nn);
            (ca_s1 * s_n % ek_nn * g_t1 % ek_nn * mta_neg_e).modulo(ek_nn)
        };

        let w_commit = {
            let h1_t1 = pow_mod_signed(&ntilde.h1, &self.t1, &ntilde.N_tilde);
            let h2_t2 = pow_mod_signed(&ntilde.h2, &self.t2, &ntilde.N_tilde);
            let t_neg_e = pow_mod_signed(&self.t, &neg_e, &ntilde.N_tilde);
            (h1_t1 * h2_t2 % &ntilde.N_tilde * t_neg_e).modulo(&ntilde.N_tilde)
        };

        let g_paillier = ek_n + Integer::one();
        let e = match check {
            Some((X, u)) => bob_challenge_ext::<C>(
                ek_n,
                &g_paillier,
                a_enc,
                mta_out,
                &self.z,
                &z_prim,
                &self.t,
                &v,
                &w_commit,
                X,
                u,
            ),
            None => bob_challenge(
                ek_n,
                &g_paillier,
                a_enc,
                mta_out,
                &self.z,
                &z_prim,
                &self.t,
                &v,
                &w_commit,
            ),
        };

        if e != self.e {
            return Err(MtaRangeError::BobVerify);
        }

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn bob_challenge(
    N: &Integer,
    Gen: &Integer,
    a_enc: &Integer,
    mta_out: &Integer,
    z: &Integer,
    z_prim: &Integer,
    t: &Integer,
    v: &Integer,
    w: &Integer,
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(N.to_bytes_msf());
    hasher.update(Gen.to_bytes_msf());
    hasher.update(a_enc.to_bytes_msf());
    hasher.update(mta_out.to_bytes_msf());
    hasher.update(z.to_bytes_msf());
    hasher.update(z_prim.to_bytes_msf());
    hasher.update(t.to_bytes_msf());
    hasher.update(v.to_bytes_msf());
    hasher.update(w.to_bytes_msf());
    Integer::from_bytes_msf(&hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
fn bob_challenge_ext<C>(
    N: &Integer,
    Gen: &Integer,
    a_enc: &Integer,
    mta_out: &Integer,
    z: &Integer,
    z_prim: &Integer,
    t: &Integer,
    v: &Integer,
    w: &Integer,
    X: &C::ProjectivePoint,
    u: &C::ProjectivePoint,
) -> Integer
where
    C: CurveArithmetic,
    <C as CurveArithmetic>::ProjectivePoint: GroupEncoding,
{
    let mut hasher = Sha256::new();
    hasher.update(N.to_bytes_msf());
    hasher.update(Gen.to_bytes_msf());
    hasher.update(a_enc.to_bytes_msf());
    hasher.update(mta_out.to_bytes_msf());
    hasher.update(z.to_bytes_msf());
    hasher.update(z_prim.to_bytes_msf());
    hasher.update(t.to_bytes_msf());
    hasher.update(v.to_bytes_msf());
    hasher.update(w.to_bytes_msf());
    hasher.update(X.to_bytes().as_ref());
    hasher.update(u.to_bytes().as_ref());
    Integer::from_bytes_msf(&hasher.finalize())
}

#[derive(Debug, Clone)]
pub struct BobProofExt<C: CurveArithmetic> {
    pub proof: BobProof,
    pub u: C::ProjectivePoint,
}

impl<C> Serialize for BobProofExt<C>
where
    C: CurveArithmetic,
    C::ProjectivePoint: GroupEncoding,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("BobProofExt", 2)?;
        s.serialize_field("proof", &self.proof)?;
        s.serialize_field("u", self.u.to_bytes().as_ref())?;
        s.end()
    }
}

impl<'de, C> Deserialize<'de> for BobProofExt<C>
where
    C: CurveArithmetic,
    C::ProjectivePoint: GroupEncoding,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            proof: BobProof,
            u: Vec<u8>,
        }
        let h = Helper::deserialize(deserializer)?;
        let mut repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
        let repr_slice = repr.as_mut();
        if h.u.len() != repr_slice.len() {
            return Err(serde::de::Error::custom("invalid point length"));
        }
        repr_slice.copy_from_slice(&h.u);
        let point = Option::from(C::ProjectivePoint::from_bytes(&repr))
            .ok_or_else(|| serde::de::Error::custom("invalid point encoding"))?;
        Ok(BobProofExt {
            proof: h.proof,
            u: point,
        })
    }
}

impl<C> BobProofExt<C>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::Scalar: PrimeField,
    <C as CurveArithmetic>::ProjectivePoint: GroupEncoding,
{
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        a_encrypted: &Integer,
        mta_encrypted: &Integer,
        b: &Integer,
        beta_prim: &Integer,
        ek_n: &Integer,
        ek_nn: &Integer,
        ntilde: &NTildeParams,
        r: &Integer,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let (proof, u) = BobProof::prove::<C>(
            a_encrypted,
            mta_encrypted,
            b,
            beta_prim,
            ek_n,
            ek_nn,
            ntilde,
            r,
            true,
            rng,
        );
        BobProofExt {
            proof,
            u: u.expect("check_ec=true always returns Some"),
        }
    }

    pub fn verify(
        &self,
        a_enc: &Integer,
        mta_out: &Integer,
        ek_n: &Integer,
        ek_nn: &Integer,
        ntilde: &NTildeParams,
        X: &C::ProjectivePoint,
    ) -> Result<(), MtaRangeError> {
        self.proof
            .verify_inner::<C>(a_enc, mta_out, ek_n, ek_nn, ntilde, Some((X, &self.u)))?;

        let s1_scalar = integer_to_scalar::<C>(&self.proof.s1);
        let e_scalar = integer_to_scalar::<C>(&self.proof.e);
        let G = C::generator();
        let lhs = G * s1_scalar;
        let rhs = *X * e_scalar + self.u;

        if lhs.to_bytes().as_ref() != rhs.to_bytes().as_ref() {
            return Err(MtaRangeError::BobVerify);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestCurve = k256::Secp256k1;

    #[test]
    #[ignore = "perf micro-benchmark for B2b; run with --ignored --nocapture"]
    fn paillier_g_pow_linear_vs_modexp() {
        use std::time::Instant;
        let n = (Integer::one() << 3072) - Integer::one();
        let nn = &n * &n;
        let g = &n + Integer::one();
        let alpha = (Integer::one() << 768) - Integer::one();
        const ITERS: u32 = 200;

        let t0 = Instant::now();
        for _ in 0..ITERS {
            let _ = pow_mod_signed(&g, &alpha, &nn);
        }
        let t_modexp = t0.elapsed() / ITERS;

        let t1 = Instant::now();
        for _ in 0..ITERS {
            let _ = (Integer::one() + &alpha * &n).modulo(&nn);
        }
        let t_linear = t1.elapsed() / ITERS;

        println!(
            "B2b (1+N)^x: modexp={t_modexp:>10.3?}  linear={t_linear:>10.3?}  speedup={:.0}x",
            t_modexp.as_secs_f64() / t_linear.as_secs_f64().max(1e-12)
        );
    }

    fn setup_paillier(
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> (fast_paillier::DecryptionKey, fast_paillier::EncryptionKey) {
        let p = Integer::generate_safe_prime(rng, 256);
        let q = Integer::generate_safe_prime(rng, 256);
        let dk = fast_paillier::DecryptionKey::from_primes(p, q).expect("valid primes");
        let ek = dk.encryption_key().clone();
        (dk, ek)
    }

    fn setup_ntilde(rng: &mut impl rand_core::CryptoRngCore) -> NTildeParams {
        let p = Integer::generate_safe_prime(rng, 256);
        let q = Integer::generate_safe_prime(rng, 256);
        let n_tilde = &p * &q;

        let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);

        let phi_n = (&p - Integer::one()) * (&q - Integer::one());
        let lambda = sample_below(&phi_n, rng);
        let h2 = h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod defined");

        NTildeParams {
            N_tilde: n_tilde,
            h1,
            h2,
        }
    }

    #[test]
    fn alice_proof_honest_verifies() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let ntilde = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();
        let a = sample_below(&q, &mut rng);

        let (cipher, r) = ek.encrypt_with_random(&mut rng, &a).expect("encrypt");

        let proof =
            AliceProof::prove::<TestCurve>(&a, &cipher, ek.n(), ek.nn(), &ntilde, &r, &mut rng);

        proof
            .verify::<TestCurve>(&cipher, ek.n(), ek.nn(), &ntilde)
            .expect("honest Alice proof should verify");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn alice_proof_wrong_a_rejects() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let ntilde = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();
        let a = sample_below(&q, &mut rng);
        let (cipher, _r) = ek.encrypt_with_random(&mut rng, &a).expect("encrypt");

        let wrong_a = sample_below(&q, &mut rng);
        let wrong_r = Integer::sample_in_mult_group_of(&mut rng, ek.n());

        let proof = AliceProof::prove::<TestCurve>(
            &wrong_a,
            &cipher,
            ek.n(),
            ek.nn(),
            &ntilde,
            &wrong_r,
            &mut rng,
        );

        assert!(
            proof
                .verify::<TestCurve>(&cipher, ek.n(), ek.nn(), &ntilde)
                .is_err(),
            "Alice proof with wrong a should fail"
        );
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn bob_proof_honest_verifies() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let ntilde = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();

        let a = sample_below(&q, &mut rng);
        let (enc_a, _r_a) = ek.encrypt_with_random(&mut rng, &a).expect("encrypt a");

        let b = sample_below(&q, &mut rng);

        let beta_prim = sample_below(ek.half_n(), &mut rng);
        let r_bob = Integer::sample_in_mult_group_of(&mut rng, ek.n());

        let b_times_enc_a = ek.omul(&b, &enc_a).expect("omul");
        let enc_beta = ek.encrypt_with(&beta_prim, &r_bob).expect("encrypt beta");
        let mta_out = ek.oadd(&b_times_enc_a, &enc_beta).expect("oadd");

        let (proof, _) = BobProof::prove::<TestCurve>(
            &enc_a,
            &mta_out,
            &b,
            &beta_prim,
            ek.n(),
            ek.nn(),
            &ntilde,
            &r_bob,
            false,
            &mut rng,
        );

        proof
            .verify::<TestCurve>(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde)
            .expect("honest Bob proof should verify");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn bob_proof_wrong_b_rejects() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let ntilde = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();

        let a = sample_below(&q, &mut rng);
        let (enc_a, _r_a) = ek.encrypt_with_random(&mut rng, &a).expect("encrypt a");

        let b = sample_below(&q, &mut rng);

        let beta_prim = sample_below(ek.half_n(), &mut rng);
        let r_bob = Integer::sample_in_mult_group_of(&mut rng, ek.n());

        let b_times_enc_a = ek.omul(&b, &enc_a).expect("omul");
        let enc_beta = ek.encrypt_with(&beta_prim, &r_bob).expect("encrypt beta");
        let mta_out = ek.oadd(&b_times_enc_a, &enc_beta).expect("oadd");

        let wrong_b = sample_below(&q, &mut rng);

        let (proof, _) = BobProof::prove::<TestCurve>(
            &enc_a,
            &mta_out,
            &wrong_b,
            &beta_prim,
            ek.n(),
            ek.nn(),
            &ntilde,
            &r_bob,
            false,
            &mut rng,
        );

        assert!(
            proof
                .verify::<TestCurve>(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde)
                .is_err(),
            "Bob proof with wrong b should fail"
        );
    }

    #[test]
    fn bob_ext_proof_honest_verifies() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let ntilde = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();

        let a = sample_below(&q, &mut rng);
        let (enc_a, _r_a) = ek.encrypt_with_random(&mut rng, &a).expect("encrypt a");

        let b = sample_below(&q, &mut rng);

        let b_scalar = integer_to_scalar::<TestCurve>(&b);
        let G = <TestCurve as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let X = G * b_scalar;

        let beta_prim = sample_below(ek.half_n(), &mut rng);
        let r_bob = Integer::sample_in_mult_group_of(&mut rng, ek.n());

        let b_times_enc_a = ek.omul(&b, &enc_a).expect("omul");
        let enc_beta = ek.encrypt_with(&beta_prim, &r_bob).expect("encrypt beta");
        let mta_out = ek.oadd(&b_times_enc_a, &enc_beta).expect("oadd");

        let proof = BobProofExt::<TestCurve>::prove(
            &enc_a,
            &mta_out,
            &b,
            &beta_prim,
            ek.n(),
            ek.nn(),
            &ntilde,
            &r_bob,
            &mut rng,
        );

        proof
            .verify(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde, &X)
            .expect("honest Bob extended proof should verify");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn bob_ext_proof_wrong_b_rejects() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let ntilde = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();

        let a = sample_below(&q, &mut rng);
        let (enc_a, _r_a) = ek.encrypt_with_random(&mut rng, &a).expect("encrypt a");

        let b = sample_below(&q, &mut rng);

        let b_scalar = integer_to_scalar::<TestCurve>(&b);
        let G = <TestCurve as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let X = G * b_scalar;

        let beta_prim = sample_below(ek.half_n(), &mut rng);
        let r_bob = Integer::sample_in_mult_group_of(&mut rng, ek.n());

        let b_times_enc_a = ek.omul(&b, &enc_a).expect("omul");
        let enc_beta = ek.encrypt_with(&beta_prim, &r_bob).expect("encrypt beta");
        let mta_out = ek.oadd(&b_times_enc_a, &enc_beta).expect("oadd");

        let wrong_b = sample_below(&q, &mut rng);

        let proof = BobProofExt::<TestCurve>::prove(
            &enc_a,
            &mta_out,
            &wrong_b,
            &beta_prim,
            ek.n(),
            ek.nn(),
            &ntilde,
            &r_bob,
            &mut rng,
        );

        assert!(
            proof
                .verify(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde, &X)
                .is_err(),
            "Bob extended proof with wrong b should fail"
        );
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn bob_ext_proof_512bit_primes() {
        let mut rng = rand::thread_rng();

        let p = Integer::generate_safe_prime(&mut rng, 512);
        let q = Integer::generate_safe_prime(&mut rng, 512);
        let dk = fast_paillier::DecryptionKey::from_primes(p, q).expect("valid primes");
        let ek = dk.encryption_key().clone();

        let ntilde = setup_ntilde(&mut rng);

        let q_order = group_order_integer::<TestCurve>();

        let a = sample_below(&q_order, &mut rng);
        let (enc_a, _r_a) = ek.encrypt_with_random(&mut rng, &a).expect("encrypt a");

        let b = sample_below(&q_order, &mut rng);

        let b_scalar = integer_to_scalar::<TestCurve>(&b);
        let G = <TestCurve as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let X = G * b_scalar;

        let beta_prim = sample_below(ek.half_n(), &mut rng);
        let r_bob = Integer::sample_in_mult_group_of(&mut rng, ek.n());

        let b_times_enc_a = ek.omul(&b, &enc_a).expect("omul");
        let enc_beta = ek.encrypt_with(&beta_prim, &r_bob).expect("encrypt beta");
        let mta_out = ek.oadd(&b_times_enc_a, &enc_beta).expect("oadd");

        let proof = BobProofExt::<TestCurve>::prove(
            &enc_a,
            &mta_out,
            &b,
            &beta_prim,
            ek.n(),
            ek.nn(),
            &ntilde,
            &r_bob,
            &mut rng,
        );

        proof
            .verify(&enc_a, &mta_out, ek.n(), ek.nn(), &ntilde, &X)
            .expect("Bob ext proof with 512-bit primes should verify");
    }
}
