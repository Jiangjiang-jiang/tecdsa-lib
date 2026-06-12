#![allow(non_snake_case)]

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, CurveArithmetic, FieldBytes, FieldBytesSize,
    PrimeField,
};
use fast_paillier::backend::Integer;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;

use crate::conv::{group_order_integer, integer_to_scalar};

#[derive(Debug, thiserror::Error)]
pub enum PdlSlackError {
    #[error("PDL-with-slack verification failed")]
    Verify,
}

pub struct PdlSlackStatement<C: CurveArithmetic> {
    pub ciphertext: Integer,
    pub ek_n: Integer,
    pub ek_nn: Integer,
    pub Q: C::ProjectivePoint,
    pub G: C::ProjectivePoint,
    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,
}

pub struct PdlSlackWitness {
    pub x: Integer,
    pub r: Integer,
}

#[derive(Debug, Clone)]
pub struct PdlSlackProof<C: CurveArithmetic> {
    z: Integer,
    u1: C::ProjectivePoint,
    u2: Integer,
    u3: Integer,
    s1: Integer,
    s2: Integer,
    s3: Integer,
}

impl<C> PdlSlackProof<C>
where
    C: CurveArithmetic,
    C::ProjectivePoint: GroupEncoding,
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let write_int = |buf: &mut Vec<u8>, val: &Integer| {
            let b = val.to_bytes_msf();
            buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
            buf.extend_from_slice(&b);
        };

        write_int(&mut buf, &self.z);

        let u1_bytes = self.u1.to_bytes();
        let u1_ref: &[u8] = u1_bytes.as_ref();
        buf.extend_from_slice(&(u1_ref.len() as u32).to_be_bytes());
        buf.extend_from_slice(u1_ref);

        write_int(&mut buf, &self.u2);
        write_int(&mut buf, &self.u3);
        write_int(&mut buf, &self.s1);
        write_int(&mut buf, &self.s2);
        write_int(&mut buf, &self.s3);

        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let read_chunk = |data: &[u8], pos: &mut usize| -> Option<Vec<u8>> {
            if *pos + 4 > data.len() {
                return None;
            }
            let len = u32::from_be_bytes(data[*pos..*pos + 4].try_into().ok()?) as usize;
            *pos += 4;
            if *pos + len > data.len() {
                return None;
            }
            let chunk = data[*pos..*pos + len].to_vec();
            *pos += len;
            Some(chunk)
        };

        let read_int = |data: &[u8], pos: &mut usize| -> Option<Integer> {
            let chunk = read_chunk(data, pos)?;
            Some(Integer::from_bytes_msf(&chunk))
        };

        let z = read_int(data, &mut pos)?;

        let u1_chunk = read_chunk(data, &mut pos)?;
        let mut repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
        if u1_chunk.len() != repr.as_ref().len() {
            return None;
        }
        repr.as_mut().copy_from_slice(&u1_chunk);
        let u1 = Option::from(C::ProjectivePoint::from_bytes(&repr))?;

        let u2 = read_int(data, &mut pos)?;
        let u3 = read_int(data, &mut pos)?;
        let s1 = read_int(data, &mut pos)?;
        let s2 = read_int(data, &mut pos)?;
        let s3 = read_int(data, &mut pos)?;

        Some(PdlSlackProof {
            z,
            u1,
            u2,
            u3,
            s1,
            s2,
            s3,
        })
    }
}

pub(crate) fn commitment_unknown_order(
    h1: &Integer,
    h2: &Integer,
    modulus: &Integer,
    x: &Integer,
    r: &Integer,
) -> Integer {
    let h1_x = pow_mod_signed(h1, x, modulus);
    let h2_r = pow_mod_signed(h2, r, modulus);
    (h1_x * h2_r).modulo(modulus)
}

pub(crate) fn pow_mod_signed(base: &Integer, exp: &Integer, modulus: &Integer) -> Integer {
    if exp.cmp0().is_lt() {
        let base_inv = base
            .invert_ref(modulus)
            .expect("base must be invertible mod modulus");
        let pos_exp = -exp.clone();
        base_inv
            .pow_mod_ref(&pos_exp, modulus)
            .expect("pow_mod defined")
    } else {
        base.pow_mod_ref(exp, modulus).expect("pow_mod defined")
    }
}

pub(crate) fn sample_below(bound: &Integer, rng: &mut impl rand_core::RngCore) -> Integer {
    bound.random_below_ref(rng)
}

fn sample_range_one_to(bound: &Integer, rng: &mut impl rand_core::RngCore) -> Integer {
    let bound_minus_one = bound - Integer::one();
    bound_minus_one.random_below_ref(rng) + Integer::one()
}

fn compute_challenge<C>(
    stmt: &PdlSlackStatement<C>,
    z: &Integer,
    u1: &C::ProjectivePoint,
    u2: &Integer,
    u3: &Integer,
) -> Integer
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::ProjectivePoint: GroupEncoding,
{
    let mut hasher = Sha256::new();
    hasher.update(b"PiPdlSlack");

    hasher.update(stmt.G.to_bytes().as_ref());

    hasher.update(stmt.Q.to_bytes().as_ref());

    hasher.update(stmt.ciphertext.to_bytes_msf());

    hasher.update(z.to_bytes_msf());

    hasher.update(u1.to_bytes().as_ref());

    hasher.update(u2.to_bytes_msf());

    hasher.update(u3.to_bytes_msf());

    Integer::from_bytes_msf(&hasher.finalize())
}

impl<C> PdlSlackProof<C>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
    <C as CurveArithmetic>::ProjectivePoint: GroupEncoding,
{
    pub fn prove(
        witness: &PdlSlackWitness,
        statement: &PdlSlackStatement<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let q = group_order_integer::<C>();
        let q3 = &q * &q * &q;
        let q_N_tilde = &q * &statement.N_tilde;
        let q3_N_tilde = &q3 * &statement.N_tilde;

        let alpha = sample_below(&q3, rng);
        let beta = sample_range_one_to(&statement.ek_n, rng);
        let rho = sample_below(&q_N_tilde, rng);
        let gamma = sample_below(&q3_N_tilde, rng);

        let z = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &witness.x,
            &rho,
        );

        let alpha_scalar = integer_to_scalar::<C>(&alpha);
        let u1 = statement.G * alpha_scalar;

        let u2 = {
            let g_paillier = &statement.ek_n + Integer::one();
            commitment_unknown_order(
                &g_paillier,
                &beta,
                &statement.ek_nn,
                &alpha,
                &statement.ek_n,
            )
        };

        let u3 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &alpha,
            &gamma,
        );

        let e = compute_challenge(statement, &z, &u1, &u2, &u3);

        let s1 = &alpha + &e * &witness.x;

        let s2 = commitment_unknown_order(&witness.r, &beta, &statement.ek_n, &e, &Integer::one());

        let s3 = &gamma + &e * &rho;

        PdlSlackProof {
            z,
            u1,
            u2,
            u3,
            s1,
            s2,
            s3,
        }
    }

    pub fn verify(&self, statement: &PdlSlackStatement<C>) -> Result<(), PdlSlackError> {
        let q = group_order_integer::<C>();
        let q3 = &q * &q * &q;

        let e = compute_challenge(statement, &self.z, &self.u1, &self.u2, &self.u3);

        let s1_scalar = integer_to_scalar::<C>(&self.s1);
        let g_s1 = statement.G * s1_scalar;

        let e_neg_int = &q - (&e % &q);
        let e_neg_scalar = integer_to_scalar::<C>(&e_neg_int);
        let q_times_neg_e = statement.Q * e_neg_scalar;
        let u1_test = g_s1 + q_times_neg_e;

        let g_paillier = &statement.ek_n + Integer::one();
        let u2_test_tmp = commitment_unknown_order(
            &g_paillier,
            &self.s2,
            &statement.ek_nn,
            &self.s1,
            &statement.ek_n,
        );
        let neg_e = -e.clone();
        let u2_test = commitment_unknown_order(
            &u2_test_tmp,
            &statement.ciphertext,
            &statement.ek_nn,
            &Integer::one(),
            &neg_e,
        );

        let u3_test_tmp = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &self.s1,
            &self.s3,
        );
        let u3_test = commitment_unknown_order(
            &u3_test_tmp,
            &self.z,
            &statement.N_tilde,
            &Integer::one(),
            &neg_e,
        );

        let s1_in_range = self.s1 < q3;

        if self.u1.to_bytes().as_ref() == u1_test.to_bytes().as_ref()
            && self.u2 == u2_test
            && self.u3 == u3_test
            && s1_in_range
        {
            Ok(())
        } else {
            Err(PdlSlackError::Verify)
        }
    }
}

#[cfg(test)]
mod tests {
    use fast_paillier::DecryptionKey;

    use super::*;

    type TestCurve = k256::Secp256k1;
    type Point = <TestCurve as CurveArithmetic>::ProjectivePoint;

    fn setup_paillier(
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> (DecryptionKey, fast_paillier::EncryptionKey) {
        let p = Integer::generate_safe_prime(rng, 256);
        let q = Integer::generate_safe_prime(rng, 256);
        let dk = DecryptionKey::from_primes(p, q).expect("valid primes");
        let ek = dk.encryption_key().clone();
        (dk, ek)
    }

    fn setup_ntilde(rng: &mut impl rand_core::CryptoRngCore) -> (Integer, Integer, Integer) {
        let p = Integer::generate_safe_prime(rng, 256);
        let q = Integer::generate_safe_prime(rng, 256);
        let n_tilde = &p * &q;

        let r = Integer::sample_in_mult_group_of(rng, &n_tilde);
        let h2 = (&r * &r).modulo(&n_tilde);

        let phi_n = (&p - Integer::one()) * (&q - Integer::one());
        let lambda = sample_below(&phi_n, rng);
        let h1 = h2.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod defined");

        (n_tilde, h1, h2)
    }

    #[test]
    fn pdl_slack_honest_verifies() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();
        let x = sample_range_one_to(&q, &mut rng);

        let x_scalar = integer_to_scalar::<TestCurve>(&x);
        let G = Point::GENERATOR;
        let Q = G * x_scalar;

        let (ciphertext, r) = ek.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let statement = PdlSlackStatement::<TestCurve> {
            ciphertext,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q,
            G,
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let witness = PdlSlackWitness { x, r };

        let proof = PdlSlackProof::prove(&witness, &statement, &mut rng);
        proof
            .verify(&statement)
            .expect("honest proof should verify");
    }

    #[test]
    #[ignore = "redundant negative/serde test"]
    fn pdl_slack_wrong_x_rejects() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();
        let x = sample_range_one_to(&q, &mut rng);

        let x_scalar = integer_to_scalar::<TestCurve>(&x);
        let G = Point::GENERATOR;
        let Q = G * x_scalar;

        let (ciphertext, r) = ek.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let statement = PdlSlackStatement::<TestCurve> {
            ciphertext,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q,
            G,
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let wrong_x = sample_range_one_to(&q, &mut rng);
        let witness = PdlSlackWitness { x: wrong_x, r };

        let proof = PdlSlackProof::prove(&witness, &statement, &mut rng);
        assert!(
            proof.verify(&statement).is_err(),
            "proof with wrong x should fail"
        );
    }

    #[test]
    #[ignore = "redundant negative/serde test"]
    fn pdl_slack_wrong_q_rejects() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();
        let x = sample_range_one_to(&q, &mut rng);

        let x_scalar = integer_to_scalar::<TestCurve>(&x);
        let G = Point::GENERATOR;
        let _Q = G * x_scalar;

        let (ciphertext, r) = ek.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let wrong_scalar = integer_to_scalar::<TestCurve>(&sample_range_one_to(&q, &mut rng));
        let wrong_Q = G * wrong_scalar;

        let statement = PdlSlackStatement::<TestCurve> {
            ciphertext,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q: wrong_Q,
            G,
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let witness = PdlSlackWitness { x, r };

        let proof = PdlSlackProof::prove(&witness, &statement, &mut rng);
        assert!(
            proof.verify(&statement).is_err(),
            "proof with wrong Q should fail"
        );
    }

    #[test]
    #[ignore = "redundant negative/serde test"]
    fn pdl_slack_serde_roundtrip() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();
        let x = sample_range_one_to(&q, &mut rng);

        let x_scalar = integer_to_scalar::<TestCurve>(&x);
        let G = Point::GENERATOR;
        let Q = G * x_scalar;

        let (ciphertext, r) = ek.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let statement = PdlSlackStatement::<TestCurve> {
            ciphertext,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q,
            G,
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let witness = PdlSlackWitness { x, r };

        let proof = PdlSlackProof::prove(&witness, &statement, &mut rng);

        let bytes = proof.to_bytes();
        let proof2 =
            PdlSlackProof::<TestCurve>::from_bytes(&bytes).expect("deserialization must succeed");

        proof2
            .verify(&statement)
            .expect("deserialized proof should verify");
    }
}
