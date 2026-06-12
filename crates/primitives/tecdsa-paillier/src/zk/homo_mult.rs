#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytes, FieldBytesSize, PrimeField};
use fast_paillier::backend::Integer;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;

use super::pdl_slack::{commitment_unknown_order, pow_mod_signed, sample_below};
use crate::conv::group_order_integer;

#[derive(Debug, thiserror::Error)]
pub enum HomoMultError {
    #[error("HomoMult (Pi_1) verification failed")]
    Verify,
}

pub struct HomoMultStatement {
    pub c1: Integer,
    pub c2: Integer,
    pub c3: Integer,
    pub ek_n: Integer,
    pub ek_nn: Integer,
    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,
}

pub struct HomoMultWitness {
    pub eta: Integer,
    pub r_c1: Integer,
    pub r_c3: Integer,
}

#[derive(Debug, Clone)]
pub struct HomoMultProof {
    z: Integer,
    u2: Integer,
    u3: Integer,
    v: Integer,
    s1: Integer,
    s2: Integer,
    s3: Integer,
    t_c: Integer,
}

impl HomoMultProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let fields = [
            &self.z, &self.u2, &self.u3, &self.v, &self.s1, &self.s2, &self.s3, &self.t_c,
        ];
        let mut buf = Vec::new();
        for f in &fields {
            let b = f.to_bytes_msf();
            buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
            buf.extend_from_slice(&b);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let mut read_int = || -> Option<Integer> {
            if pos + 4 > data.len() {
                return None;
            }
            let len = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            if pos + len > data.len() {
                return None;
            }
            let val = Integer::from_bytes_msf(&data[pos..pos + len]);
            pos += len;
            Some(val)
        };
        let z = read_int()?;
        let u2 = read_int()?;
        let u3 = read_int()?;
        let v = read_int()?;
        let s1 = read_int()?;
        let s2 = read_int()?;
        let s3 = read_int()?;
        let t_c = read_int()?;
        Some(HomoMultProof {
            z,
            u2,
            u3,
            v,
            s1,
            s2,
            s3,
            t_c,
        })
    }
}

fn compute_challenge(
    stmt: &HomoMultStatement,
    z: &Integer,
    u2: &Integer,
    u3: &Integer,
    v: &Integer,
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"PiHomoMult");

    hasher.update(stmt.c1.to_bytes_msf());
    hasher.update(stmt.c2.to_bytes_msf());
    hasher.update(stmt.c3.to_bytes_msf());
    hasher.update(stmt.ek_n.to_bytes_msf());
    hasher.update(z.to_bytes_msf());
    hasher.update(u2.to_bytes_msf());
    hasher.update(u3.to_bytes_msf());
    hasher.update(v.to_bytes_msf());

    Integer::from_bytes_msf(&hasher.finalize())
}

impl HomoMultProof {
    pub fn prove<C>(
        witness: &HomoMultWitness,
        statement: &HomoMultStatement,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self
    where
        C: TecdsaCurve,
        FieldBytesSize<C>: ModulusSize,
        <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
    {
        let q = group_order_integer::<C>();
        let q3 = &q * &q * &q;
        let q_N_tilde = &q * &statement.N_tilde;
        let q3_N_tilde = &q3 * &statement.N_tilde;

        let alpha = sample_below(&q3, rng);
        let beta = Integer::sample_in_mult_group_of(rng, &statement.ek_n);
        let gamma = sample_below(&q3_N_tilde, rng);
        let rho = sample_below(&q_N_tilde, rng);
        let mu = Integer::sample_in_mult_group_of(rng, &statement.ek_n);

        let z = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &witness.eta,
            &rho,
        );

        let _gamma_paillier = &statement.ek_n + Integer::one();
        let u2 = {
            let g_alpha = (Integer::one() + &alpha * &statement.ek_n).modulo(&statement.ek_nn);
            let beta_n = pow_mod_signed(&beta, &statement.ek_n, &statement.ek_nn);
            (g_alpha * beta_n).modulo(&statement.ek_nn)
        };

        let u3 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &alpha,
            &gamma,
        );

        let v = {
            let c2_alpha = pow_mod_signed(&statement.c2, &alpha, &statement.ek_nn);
            let mu_n = pow_mod_signed(&mu, &statement.ek_n, &statement.ek_nn);
            (c2_alpha * mu_n).modulo(&statement.ek_nn)
        };

        let e = compute_challenge(statement, &z, &u2, &u3, &v);

        let s1 = &e * &witness.eta + &alpha;

        let s2 = {
            let r_e = pow_mod_signed(&witness.r_c1, &e, &statement.ek_n);
            (r_e * &beta).modulo(&statement.ek_n)
        };

        let s3 = &e * &rho + &gamma;

        let t_c = {
            let r_e = pow_mod_signed(&witness.r_c3, &e, &statement.ek_n);
            (r_e * &mu).modulo(&statement.ek_n)
        };

        HomoMultProof {
            z,
            u2,
            u3,
            v,
            s1,
            s2,
            s3,
            t_c,
        }
    }

    pub fn verify<C>(&self, statement: &HomoMultStatement) -> Result<(), HomoMultError>
    where
        C: TecdsaCurve,
        FieldBytesSize<C>: ModulusSize,
        <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
    {
        let q = group_order_integer::<C>();
        let q3 = &q * &q * &q;

        let e = compute_challenge(statement, &self.z, &self.u2, &self.u3, &self.v);
        let neg_e = -e.clone();

        let _gamma_paillier = &statement.ek_n + Integer::one();
        let u2_check = {
            let g_s1 = (Integer::one() + &self.s1 * &statement.ek_n).modulo(&statement.ek_nn);
            let s2_n = pow_mod_signed(&self.s2, &statement.ek_n, &statement.ek_nn);
            let c1_neg_e = pow_mod_signed(&statement.c1, &neg_e, &statement.ek_nn);
            (g_s1 * s2_n % &statement.ek_nn * c1_neg_e).modulo(&statement.ek_nn)
        };

        let u3_check = {
            let h1_s1 = pow_mod_signed(&statement.h1, &self.s1, &statement.N_tilde);
            let h2_s3 = pow_mod_signed(&statement.h2, &self.s3, &statement.N_tilde);
            let z_neg_e = pow_mod_signed(&self.z, &neg_e, &statement.N_tilde);
            (h1_s1 * h2_s3 % &statement.N_tilde * z_neg_e).modulo(&statement.N_tilde)
        };

        let v_check = {
            let c2_s1 = pow_mod_signed(&statement.c2, &self.s1, &statement.ek_nn);
            let tc_n = pow_mod_signed(&self.t_c, &statement.ek_n, &statement.ek_nn);
            let c3_neg_e = pow_mod_signed(&statement.c3, &neg_e, &statement.ek_nn);
            (c2_s1 * tc_n % &statement.ek_nn * c3_neg_e).modulo(&statement.ek_nn)
        };

        let s1_in_range = self.s1 < q3;

        if self.u2 == u2_check && self.u3 == u3_check && self.v == v_check && s1_in_range {
            Ok(())
        } else {
            Err(HomoMultError::Verify)
        }
    }
}

#[cfg(test)]
mod tests {
    use fast_paillier::DecryptionKey;

    use super::*;

    type TestCurve = k256::Secp256k1;

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
    fn homo_mult_honest_verifies() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();

        let eta = sample_below(&q, &mut rng);

        let (c1, r_c1) = ek.encrypt_with_random(&mut rng, &eta).expect("encrypt c1");

        let some_value = sample_below(&q, &mut rng);
        let (c2, _r_c2) = ek
            .encrypt_with_random(&mut rng, &some_value)
            .expect("encrypt c2");

        let r_c3 = Integer::sample_in_mult_group_of(&mut rng, ek.n());
        let c3 = {
            let c2_eta = pow_mod_signed(&c2, &eta, ek.nn());
            let r_c3_n = pow_mod_signed(&r_c3, ek.n(), ek.nn());
            (c2_eta * r_c3_n).modulo(ek.nn())
        };

        let statement = HomoMultStatement {
            c1,
            c2,
            c3,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let witness = HomoMultWitness { eta, r_c1, r_c3 };

        let proof = HomoMultProof::prove::<TestCurve>(&witness, &statement, &mut rng);
        proof
            .verify::<TestCurve>(&statement)
            .expect("honest HomoMult proof should verify");
    }

    #[test]
    fn homo_mult_wrong_eta_rejects() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = group_order_integer::<TestCurve>();

        let eta = sample_below(&q, &mut rng);
        let (c1, r_c1) = ek.encrypt_with_random(&mut rng, &eta).expect("encrypt c1");

        let some_value = sample_below(&q, &mut rng);
        let (c2, _r_c2) = ek
            .encrypt_with_random(&mut rng, &some_value)
            .expect("encrypt c2");

        let r_c3 = Integer::sample_in_mult_group_of(&mut rng, ek.n());
        let c3 = {
            let c2_eta = pow_mod_signed(&c2, &eta, ek.nn());
            let r_c3_n = pow_mod_signed(&r_c3, ek.n(), ek.nn());
            (c2_eta * r_c3_n).modulo(ek.nn())
        };

        let statement = HomoMultStatement {
            c1,
            c2,
            c3,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let wrong_eta = sample_below(&q, &mut rng);
        let witness = HomoMultWitness {
            eta: wrong_eta,
            r_c1,
            r_c3,
        };

        let proof = HomoMultProof::prove::<TestCurve>(&witness, &statement, &mut rng);
        assert!(
            proof.verify::<TestCurve>(&statement).is_err(),
            "HomoMult proof with wrong eta should fail"
        );
    }
}
