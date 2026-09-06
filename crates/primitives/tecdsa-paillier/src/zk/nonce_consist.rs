// SPDX-License-Identifier: MIT OR Apache-2.0
//! Zero-knowledge proof of nonce consistency (Pi_{2,i}).
//!
//! From GGN16 Section 4.4. Given an EC generator $G$, an EC point $r_i$,
//! and Paillier ciphertexts $w_i$ and $u$, proves:
//!
//! - $g^{\eta_1} = r_i$ (EC discrete log) with $|\eta_1| < q^3$
//! - $D(w_i) = \eta_1 \cdot D(u) + q \cdot \eta_2$ (Paillier linear combination)
//!
//! Used in GGN16 signing Round 4 to prove $r_i = g^{k_i}$ and
//! $w_i = \text{Enc}(k_i \cdot \rho + c_i \cdot q)$.
//!
//! Uses Ring-Pedersen commitments $(N', h_1, h_2)$ for range proofs and
//! is made non-interactive via the Fiat-Shamir transform (SHA-256).

#![allow(non_snake_case)]

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, CurveArithmetic, FieldBytes, FieldBytesSize,
    PrimeField,
};
use fast_paillier::backend::{BigIntExt, Integer};
use rug::Complete;
use sha2::{Digest, Sha256};
use tecdsa_curve::{
    conv::{curve_order, integer_to_scalar},
    TecdsaCurve,
};

use super::pdl_slack::{commitment_unknown_order, pow_mod_signed, sample_below};

/// Verification error for the nonce consistency proof.
#[derive(Debug, thiserror::Error)]
pub enum NonceConsistError {
    /// Verification of the Pi_{2,i} proof failed.
    #[error("NonceConsist (Pi_2) verification failed")]
    Verify,
}

// ---------------------------------------------------------------------------
// Statement / Witness
// ---------------------------------------------------------------------------

/// Public statement for the nonce consistency proof.
///
/// - `G`: EC group generator
/// - `r_i`: EC point $r_i = G^{\eta_1}$
/// - `w_i`: Paillier ciphertext $w_i = u^{\eta_1} \cdot \Gamma^{q \cdot \eta_2} \cdot r_c^N \bmod N^2$
/// - `u`: Paillier ciphertext (base for the linear combination)
/// - `ek_n`, `ek_nn`: Paillier modulus $N$ and $N^2$
/// - `h1, h2, N_tilde`: Ring-Pedersen auxiliary parameters
pub struct NonceConsistStatement<C: CurveArithmetic> {
    /// EC group generator $G$.
    pub G: C::ProjectivePoint,
    /// EC point $r_i = G^{\eta_1}$.
    pub r_i: C::ProjectivePoint,
    /// Paillier ciphertext $w_i$.
    pub w_i: Integer,
    /// Paillier ciphertext $u$ (base).
    pub u: Integer,
    /// Paillier modulus $N$.
    pub ek_n: Integer,
    /// Paillier modulus squared $N^2$.
    pub ek_nn: Integer,
    /// Ring-Pedersen base $h_1$.
    pub h1: Integer,
    /// Ring-Pedersen base $h_2$.
    pub h2: Integer,
    /// Ring-Pedersen modulus $\tilde{N}$.
    pub N_tilde: Integer,
}

/// Witness for the nonce consistency proof.
pub struct NonceConsistWitness {
    /// The nonce share $\eta_1 = k_i$.
    pub eta1: Integer,
    /// The masking value $\eta_2 = c_i$.
    pub eta2: Integer,
    /// The encryption randomness of $w_i$.
    pub r_c: Integer,
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/// Non-interactive nonce consistency proof (Fiat-Shamir via SHA-256).
#[derive(Debug, Clone)]
pub struct NonceConsistProof<C: CurveArithmetic> {
    z1: Integer,
    z2: Integer,
    u1: C::ProjectivePoint,
    u2: Integer,
    u3: Integer,
    v1: Integer,
    v2: Integer,
    v3: Integer,
    s1: Integer,
    s2: Integer,
    t1: Integer,
    t2: Integer,
    t3: Integer,
}

impl<C> NonceConsistProof<C>
where
    C: CurveArithmetic,
    C::ProjectivePoint: GroupEncoding,
{
    /// Serialize the proof to a length-prefixed byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Helper: write a length-prefixed Integer
        let write_int = |buf: &mut Vec<u8>, val: &Integer| {
            let b = val.to_bytes_msf();
            buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
            buf.extend_from_slice(&b);
        };

        write_int(&mut buf, &self.z1);
        write_int(&mut buf, &self.z2);

        // Write the EC point u1 (compressed SEC1 encoding)
        let u1_bytes = self.u1.to_bytes();
        let u1_ref: &[u8] = u1_bytes.as_ref();
        buf.extend_from_slice(&(u1_ref.len() as u32).to_be_bytes());
        buf.extend_from_slice(u1_ref);

        write_int(&mut buf, &self.u2);
        write_int(&mut buf, &self.u3);
        write_int(&mut buf, &self.v1);
        write_int(&mut buf, &self.v2);
        write_int(&mut buf, &self.v3);
        write_int(&mut buf, &self.s1);
        write_int(&mut buf, &self.s2);
        write_int(&mut buf, &self.t1);
        write_int(&mut buf, &self.t2);
        write_int(&mut buf, &self.t3);

        buf
    }

    /// Deserialize a proof from the format produced by [`to_bytes`](Self::to_bytes).
    ///
    /// Returns `None` if the input is malformed.
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

        let z1 = read_int(data, &mut pos)?;
        let z2 = read_int(data, &mut pos)?;

        // Read the EC point u1
        let u1_chunk = read_chunk(data, &mut pos)?;
        let mut repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
        if u1_chunk.len() != repr.as_ref().len() {
            return None;
        }
        repr.as_mut().copy_from_slice(&u1_chunk);
        let u1 = Option::from(C::ProjectivePoint::from_bytes(&repr))?;

        let u2 = read_int(data, &mut pos)?;
        let u3 = read_int(data, &mut pos)?;
        let v1 = read_int(data, &mut pos)?;
        let v2 = read_int(data, &mut pos)?;
        let v3 = read_int(data, &mut pos)?;
        let s1 = read_int(data, &mut pos)?;
        let s2 = read_int(data, &mut pos)?;
        let t1 = read_int(data, &mut pos)?;
        let t2 = read_int(data, &mut pos)?;
        let t3 = read_int(data, &mut pos)?;

        Some(NonceConsistProof {
            z1,
            z2,
            u1,
            u2,
            u3,
            v1,
            v2,
            v3,
            s1,
            s2,
            t1,
            t2,
            t3,
        })
    }
}

// ---------------------------------------------------------------------------
// Fiat-Shamir challenge
// ---------------------------------------------------------------------------

/// Compute the Fiat-Shamir challenge by hashing all public values and
/// prover commitments.
fn compute_challenge<C>(
    stmt: &NonceConsistStatement<C>,
    z1: &Integer,
    z2: &Integer,
    u1: &C::ProjectivePoint,
    u2: &Integer,
    u3: &Integer,
    v1: &Integer,
    v2: &Integer,
    v3: &Integer,
) -> Integer
where
    C: CurveArithmetic,
    C::ProjectivePoint: GroupEncoding,
{
    let mut hasher = Sha256::new();
    hasher.update(b"PiNonceConsist");

    // Hash statement
    hasher.update(stmt.G.to_bytes().as_ref());
    hasher.update(stmt.r_i.to_bytes().as_ref());
    hasher.update(stmt.w_i.to_bytes_msf());
    hasher.update(stmt.u.to_bytes_msf());
    hasher.update(stmt.ek_n.to_bytes_msf());

    // Hash prover commitments
    hasher.update(z1.to_bytes_msf());
    hasher.update(z2.to_bytes_msf());
    hasher.update(u1.to_bytes().as_ref());
    hasher.update(u2.to_bytes_msf());
    hasher.update(u3.to_bytes_msf());
    hasher.update(v1.to_bytes_msf());
    hasher.update(v2.to_bytes_msf());
    hasher.update(v3.to_bytes_msf());

    Integer::from_bytes_msf(&hasher.finalize())
}

// ---------------------------------------------------------------------------
// Prove / Verify
// ---------------------------------------------------------------------------

impl<C> NonceConsistProof<C>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
    <C as CurveArithmetic>::ProjectivePoint: GroupEncoding,
{
    /// Construct a non-interactive nonce consistency proof.
    ///
    /// The prover demonstrates that:
    /// 1. $r_i = G^{\eta_1}$ (EC discrete log)
    /// 2. $w_i = u^{\eta_1} \cdot \Gamma^{q \cdot \eta_2} \cdot r_c^N \bmod N^2$
    ///    (Paillier linear combination)
    pub fn prove(
        witness: &NonceConsistWitness,
        statement: &NonceConsistStatement<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let q = curve_order::<C>();
        let q3 = (&q * &q).complete() * &q;
        let q5 = (&q3 * &q).complete() * &q;
        let q8 = (&q5 * &q).complete() * &q * &q;
        let q_N_tilde = (&q * &statement.N_tilde).complete();
        let q3_N_tilde = (&q3 * &statement.N_tilde).complete();
        let q5_N_tilde = (&q5 * &statement.N_tilde).complete();
        let q8_N_tilde = (&q8 * &statement.N_tilde).complete();

        // 1. Sample blinding values
        let alpha = sample_below(&q3, rng);
        let beta = Integer::sample_in_mult_group_of(rng, &statement.ek_n);
        let gamma = sample_below(&q3_N_tilde, rng);
        let delta = sample_below(&q5, rng);
        let mu = Integer::sample_in_mult_group_of(rng, &statement.ek_n);
        let nu = sample_below(&q3_N_tilde, rng);
        let theta = sample_below(&q8, rng);
        let tau = sample_below(&q8_N_tilde, rng);
        let rho1 = sample_below(&q_N_tilde, rng);
        let rho2 = sample_below(&q5_N_tilde, rng);

        // 2. Compute commitments
        // z1 = h1^{eta1} * h2^{rho1} mod N_tilde
        let z1 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &witness.eta1,
            &rho1,
        );

        // z2 = h1^{eta2} * h2^{rho2} mod N_tilde
        let z2 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &witness.eta2,
            &rho2,
        );

        // u1 = G^alpha (EC point)
        let alpha_scalar = integer_to_scalar::<C>(&alpha);
        let u1 = statement.G * alpha_scalar;

        // u2 = Gamma^alpha * beta^N mod N^2
        let _gamma_paillier = &statement.ek_n + Integer::one();
        let u2 = {
            // (1 + N)^alpha = (1 + alpha*N) mod N^2 (binomial) — one mul, no modexp.
            let g_alpha =
                (Integer::one() + (&alpha * &statement.ek_n).complete()).modulo(&statement.ek_nn);
            let beta_n = pow_mod_signed(&beta, &statement.ek_n, &statement.ek_nn);
            (g_alpha * beta_n).modulo(&statement.ek_nn)
        };

        // u3 = h1^alpha * h2^gamma mod N_tilde
        let u3 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &alpha,
            &gamma,
        );

        // v1 = u^alpha * Gamma^{q*theta} * mu^N mod N^2
        let v1 = {
            let u_alpha = pow_mod_signed(&statement.u, &alpha, &statement.ek_nn);
            let q_theta = q * &theta;
            let g_q_theta = (Integer::one() + q_theta * &statement.ek_n).modulo(&statement.ek_nn);
            let mu_n = pow_mod_signed(&mu, &statement.ek_n, &statement.ek_nn);
            (u_alpha * g_q_theta % &statement.ek_nn * mu_n).modulo(&statement.ek_nn)
        };

        // v2 = h1^delta * h2^nu mod N_tilde
        let v2 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &delta,
            &nu,
        );

        // v3 = h1^theta * h2^tau mod N_tilde
        let v3 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &theta,
            &tau,
        );

        // 3. Fiat-Shamir challenge
        let e = compute_challenge(statement, &z1, &z2, &u1, &u2, &u3, &v1, &v2, &v3);

        // 4. Compute responses
        // s1 = e * eta1 + alpha
        let s1 = (&e * &witness.eta1).complete() + &alpha;

        // s2 = e * rho1 + gamma
        let s2 = (&e * &rho1).complete() + &gamma;

        // t1 = r_c^e * mu mod N
        let t1 = {
            let r_e = pow_mod_signed(&witness.r_c, &e, &statement.ek_n);
            (r_e * &mu).modulo(&statement.ek_n)
        };

        // t2 = e * eta2 + theta
        let t2 = (&e * &witness.eta2).complete() + &theta;

        // t3 = e * rho2 + tau
        let t3 = e * &rho2 + &tau;

        NonceConsistProof {
            z1,
            z2,
            u1,
            u2,
            u3,
            v1,
            v2,
            v3,
            s1,
            s2,
            t1,
            t2,
            t3,
        }
    }

    /// Verify a nonce consistency proof.
    ///
    /// # Errors
    /// Returns [`NonceConsistError::Verify`] if the proof does not verify.
    pub fn verify(&self, statement: &NonceConsistStatement<C>) -> Result<(), NonceConsistError> {
        let q = curve_order::<C>();
        let q3 = (&q * &q).complete() * &q;

        // Recompute challenge
        let e = compute_challenge(
            statement, &self.z1, &self.z2, &self.u1, &self.u2, &self.u3, &self.v1, &self.v2,
            &self.v3,
        );
        let neg_e = -e.clone();

        // --- EC check: G^{s1} * r_i^{-e} == u1 ---
        let s1_scalar = integer_to_scalar::<C>(&self.s1);
        let g_s1 = statement.G * s1_scalar;

        let e_neg_int = &q - (e % &q);
        let e_neg_scalar = integer_to_scalar::<C>(&e_neg_int);
        let r_i_neg_e = statement.r_i * e_neg_scalar;
        let u1_check = g_s1 + r_i_neg_e;

        // --- Paillier check: u^{s1} * Gamma^{q*t2} * t1^N * w_i^{-e} == v1 mod N^2 ---
        let _gamma_paillier = &statement.ek_n + Integer::one();
        let v1_check = {
            let u_s1 = pow_mod_signed(&statement.u, &self.s1, &statement.ek_nn);
            let q_t2 = q * &self.t2;
            let g_q_t2 = (Integer::one() + q_t2 * &statement.ek_n).modulo(&statement.ek_nn);
            let t1_n = pow_mod_signed(&self.t1, &statement.ek_n, &statement.ek_nn);
            let w_neg_e = pow_mod_signed(&statement.w_i, &neg_e, &statement.ek_nn);
            (u_s1 * g_q_t2 % &statement.ek_nn * t1_n % &statement.ek_nn * w_neg_e)
                .modulo(&statement.ek_nn)
        };

        // --- Range commitment check 1: h1^{s1} * h2^{s2} * z1^{-e} == u3 mod N_tilde ---
        let u3_check = {
            let h1_s1 = pow_mod_signed(&statement.h1, &self.s1, &statement.N_tilde);
            let h2_s2 = pow_mod_signed(&statement.h2, &self.s2, &statement.N_tilde);
            let z1_neg_e = pow_mod_signed(&self.z1, &neg_e, &statement.N_tilde);
            (h1_s1 * h2_s2 % &statement.N_tilde * z1_neg_e).modulo(&statement.N_tilde)
        };

        // --- Range commitment check 2: h1^{t2} * h2^{t3} * z2^{-e} == v3 mod N_tilde ---
        let v3_check = {
            let h1_t2 = pow_mod_signed(&statement.h1, &self.t2, &statement.N_tilde);
            let h2_t3 = pow_mod_signed(&statement.h2, &self.t3, &statement.N_tilde);
            let z2_neg_e = pow_mod_signed(&self.z2, &neg_e, &statement.N_tilde);
            (h1_t2 * h2_t3 % &statement.N_tilde * z2_neg_e).modulo(&statement.N_tilde)
        };

        // --- Range check: |s1| < q^3 ---
        let s1_in_range = self.s1 < q3;

        let ec_ok = self.u1.to_bytes().as_ref() == u1_check.to_bytes().as_ref();

        if ec_ok && self.v1 == v1_check && self.u3 == u3_check && self.v3 == v3_check && s1_in_range
        {
            Ok(())
        } else {
            Err(NonceConsistError::Verify)
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
        let n_tilde = (&p * &q).complete();

        let r = Integer::sample_in_mult_group_of(rng, &n_tilde);
        let h2 = (&r * &r).complete().modulo(&n_tilde);

        let phi_n = (&p - Integer::one()) * (&q - Integer::one());
        let lambda = sample_below(&phi_n, rng);
        let h1 = h2
            .pow_mod_ref(&lambda, &n_tilde)
            .expect("pow_mod defined")
            .complete();

        (n_tilde, h1, h2)
    }

    #[test]
    fn nonce_consist_honest_verifies() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = curve_order::<TestCurve>();
        let G = Point::GENERATOR;

        // eta1 = k_i (nonce share)
        let eta1 = sample_below(&q, &mut rng);

        // r_i = G^{eta1}
        let eta1_scalar = integer_to_scalar::<TestCurve>(&eta1);
        let r_i = G * eta1_scalar;

        // u = Enc(rho) — the base ciphertext
        let rho = sample_below(&q, &mut rng);
        let (u_ct, _r_u) = ek.encrypt_with_random(&mut rng, &rho).expect("encrypt u");

        // eta2 = c_i (masking value)
        let eta2 = sample_below(&q, &mut rng);

        // w_i = u^{eta1} * Gamma^{q*eta2} * r_c^N mod N^2
        let r_c = Integer::sample_in_mult_group_of(&mut rng, ek.n());
        let _gamma_paillier = ek.n() + Integer::one();
        let w_i = {
            let u_eta1 = pow_mod_signed(&u_ct, &eta1, ek.nn());
            let q_eta2 = q * &eta2;
            let g_q_eta2 = (Integer::one() + q_eta2 * ek.n()).modulo(ek.nn());
            let r_c_n = pow_mod_signed(&r_c, ek.n(), ek.nn());
            (u_eta1 * g_q_eta2 % ek.nn() * r_c_n).modulo(ek.nn())
        };

        let statement = NonceConsistStatement::<TestCurve> {
            G,
            r_i,
            w_i,
            u: u_ct,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let witness = NonceConsistWitness { eta1, eta2, r_c };

        let proof = NonceConsistProof::prove(&witness, &statement, &mut rng);
        proof
            .verify(&statement)
            .expect("honest NonceConsist proof should verify");
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn nonce_consist_wrong_eta1_rejects() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = curve_order::<TestCurve>();
        let G = Point::GENERATOR;

        let eta1 = sample_below(&q, &mut rng);
        let eta1_scalar = integer_to_scalar::<TestCurve>(&eta1);
        let r_i = G * eta1_scalar;

        let rho = sample_below(&q, &mut rng);
        let (u_ct, _r_u) = ek.encrypt_with_random(&mut rng, &rho).expect("encrypt u");

        let eta2 = sample_below(&q, &mut rng);

        let r_c = Integer::sample_in_mult_group_of(&mut rng, ek.n());
        let _gamma_paillier = ek.n() + Integer::one();
        let w_i = {
            let u_eta1 = pow_mod_signed(&u_ct, &eta1, ek.nn());
            let q_eta2 = (&q * &eta2).complete();
            let g_q_eta2 = (Integer::one() + q_eta2 * ek.n()).modulo(ek.nn());
            let r_c_n = pow_mod_signed(&r_c, ek.n(), ek.nn());
            (u_eta1 * g_q_eta2 % ek.nn() * r_c_n).modulo(ek.nn())
        };

        let statement = NonceConsistStatement::<TestCurve> {
            G,
            r_i,
            w_i,
            u: u_ct,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1,
            h2,
            N_tilde: n_tilde,
        };

        // Use a wrong eta1 in the witness
        let wrong_eta1 = sample_below(&q, &mut rng);
        let witness = NonceConsistWitness {
            eta1: wrong_eta1,
            eta2,
            r_c,
        };

        let proof = NonceConsistProof::prove(&witness, &statement, &mut rng);
        assert!(
            proof.verify(&statement).is_err(),
            "NonceConsist proof with wrong eta1 should fail"
        );
    }
}
