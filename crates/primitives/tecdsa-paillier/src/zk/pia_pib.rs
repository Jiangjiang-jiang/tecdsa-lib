#![allow(non_snake_case)]

use fast_paillier::{backend::Integer, EncryptionKey};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

const KAPPA: u32 = 80;

const TAU: u32 = 256;

pub struct PiBProof {
    pub A: Integer,
    pub z1: Integer,
    pub z2: Integer,
}

impl PiBProof {
    pub fn prove(
        ek: &EncryptionKey,
        c_B: &Integer,
        b: &Integer,
        r: &Integer,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let n = ek.n();

        let sample_bound = q * &Integer::u_pow_u(2, TAU + KAPPA);

        let alpha = sample_bound.random_below_ref(rng);

        let beta = Integer::sample_in_mult_group_of(rng, n);

        let A = ek
            .encrypt_with(&alpha, &beta)
            .expect("alpha is in valid range for encryption");

        let e = compute_challenge_pib(n, q, c_B, &A);

        let z1 = &alpha + &e * b;

        let r_to_e = r
            .pow_mod_ref(&e, n)
            .expect("modular exponentiation should succeed");
        let z2 = (&beta * &r_to_e).modulo(n);

        PiBProof { A, z1, z2 }
    }

    #[must_use]
    pub fn verify(&self, ek: &EncryptionKey, c_B: &Integer, q: &Integer) -> bool {
        let n = ek.n();
        let n2 = ek.nn();

        let e = compute_challenge_pib(n, q, c_B, &self.A);

        let upper_bound = q * &Integer::u_pow_u(2, TAU + KAPPA) + q * &Integer::u_pow_u(2, KAPPA);
        let z1_in_range = self.z1.cmp0().is_ge() && self.z1 <= upper_bound;

        let z2_valid = self.z2.in_mult_group_of(n);

        let lhs = paillier_encrypt_raw(n, n2, &self.z1, &self.z2);

        let c_B_to_e = c_B
            .pow_mod_ref(&e, n2)
            .expect("modular exponentiation should succeed");
        let rhs = (&self.A * &c_B_to_e).modulo(n2);

        z1_in_range && z2_valid && lhs == rhs
    }
}

pub struct PiAProof {
    pub A: Integer,
    pub z1: Integer,
    pub z2: Integer,
    pub z3: Integer,
}

impl PiAProof {
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        ek: &EncryptionKey,
        c_A: &Integer,
        c_B: &Integer,
        a: &Integer,
        alpha_prime: &Integer,
        r_prime: &Integer,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let n = ek.n();
        let nn = ek.nn();

        let K = q * q * &Integer::u_pow_u(2, TAU + 2 * KAPPA);

        let gamma_bound = q * &Integer::u_pow_u(2, TAU + KAPPA);
        let delta_bound = &K * &Integer::u_pow_u(2, TAU + KAPPA);

        let gamma = gamma_bound.random_below_ref(rng);

        let delta = delta_bound.random_below_ref(rng);

        let mu = Integer::sample_in_mult_group_of(rng, n);

        let c_B_gamma = c_B
            .pow_mod_ref(&gamma, nn)
            .expect("modular exponentiation should succeed");
        let enc_delta = paillier_encrypt_raw(n, nn, &delta, &mu);
        let A = (&c_B_gamma * &enc_delta).modulo(nn);

        let e = compute_challenge_pia(n, q, c_A, c_B, &A);

        let z1 = &gamma + &e * a;

        let z2 = &delta + &e * alpha_prime;

        let r_prime_to_e = r_prime
            .pow_mod_ref(&e, n)
            .expect("modular exponentiation should succeed");
        let z3 = (&mu * &r_prime_to_e).modulo(n);

        PiAProof { A, z1, z2, z3 }
    }

    #[must_use]
    pub fn verify(&self, ek: &EncryptionKey, c_A: &Integer, c_B: &Integer, q: &Integer) -> bool {
        let n = ek.n();
        let nn = ek.nn();

        let K = q * q * &Integer::u_pow_u(2, TAU + 2 * KAPPA);

        let e = compute_challenge_pia(n, q, c_A, c_B, &self.A);

        let z1_upper = q * &Integer::u_pow_u(2, TAU + KAPPA) + q * &Integer::u_pow_u(2, KAPPA);
        let z1_in_range = self.z1.cmp0().is_ge() && self.z1 <= z1_upper;

        let z2_upper = &K * &Integer::u_pow_u(2, TAU + KAPPA) + &K * &Integer::u_pow_u(2, KAPPA);
        let z2_in_range = self.z2.cmp0().is_ge() && self.z2 <= z2_upper;

        let z3_valid = self.z3.in_mult_group_of(n);

        let c_B_z1 = c_B
            .pow_mod_ref(&self.z1, nn)
            .expect("modular exponentiation should succeed");
        let enc_z2 = paillier_encrypt_raw(n, nn, &self.z2, &self.z3);
        let lhs = (&c_B_z1 * &enc_z2).modulo(nn);

        let c_A_e = c_A
            .pow_mod_ref(&e, nn)
            .expect("modular exponentiation should succeed");
        let rhs = (&self.A * &c_A_e).modulo(nn);

        z1_in_range && z2_in_range && z3_valid && lhs == rhs
    }
}

pub(crate) fn paillier_encrypt_raw(n: &Integer, nn: &Integer, x: &Integer, r: &Integer) -> Integer {
    let one_plus_xN = (Integer::one() + x * n).modulo(nn);
    let r_to_N = r
        .pow_mod_ref(n, nn)
        .expect("modular exponentiation should succeed");
    (&one_plus_xN * &r_to_N).modulo(nn)
}

fn compute_challenge_pib(n: &Integer, q: &Integer, c_B: &Integer, A: &Integer) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"xal21-pi-b");
    hasher.update(n.to_bytes_msf());
    hasher.update(q.to_bytes_msf());
    hasher.update(c_B.to_bytes_msf());
    hasher.update(A.to_bytes_msf());
    let hash = hasher.finalize();

    let hash_int = Integer::from_bytes_msf(&hash);
    let modulus = Integer::u_pow_u(2, KAPPA);
    hash_int.modulo(&modulus)
}

fn compute_challenge_pia(
    n: &Integer,
    q: &Integer,
    c_A: &Integer,
    c_B: &Integer,
    A: &Integer,
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"xal21-pi-a");
    hasher.update(n.to_bytes_msf());
    hasher.update(q.to_bytes_msf());
    hasher.update(c_A.to_bytes_msf());
    hasher.update(c_B.to_bytes_msf());
    hasher.update(A.to_bytes_msf());
    let hash = hasher.finalize();

    let hash_int = Integer::from_bytes_msf(&hash);
    let modulus = Integer::u_pow_u(2, KAPPA);
    hash_int.modulo(&modulus)
}
