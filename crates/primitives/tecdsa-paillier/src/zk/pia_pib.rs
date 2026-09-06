// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(non_snake_case)]
//! PiB and PiA range proofs for the Paillier-based MtA (XAL+21, Appendix C.2).
//!
//! Two proof systems used by the simple (non-Ring-Pedersen) Paillier MtA:
//!
//! - **PiB** (`R_PwR`): proves that a Paillier ciphertext encrypts a value in
//!   range `[0, q)`.
//! - **PiA** (`R'_AffRan`): proves that an affine homomorphic operation was
//!   performed correctly, with both the scalar and additive mask in range.
//!
//! Security parameters:
//! - `tau = 256` (secp256k1 curve order bits)
//! - `kappa = 80` (statistical security parameter)
//! - `K = q^2 * 2^{tau + 2*kappa}` (range for alpha')

use fast_paillier::{
    backend::{BigIntExt, Integer},
    EncryptionKey,
};
use rand_core::CryptoRngCore;
use rug::Complete;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Security parameters
// ---------------------------------------------------------------------------

/// Statistical security parameter (kappa).
const KAPPA: u32 = 80;

/// Curve order bit-length (tau) for secp256k1.
const TAU: u32 = 256;

// ---------------------------------------------------------------------------
// PiB: Paillier encryption with range proof (R_PwR)
// ---------------------------------------------------------------------------

/// PiB proof: proves knowledge of plaintext and randomness for a Paillier
/// ciphertext, with a range check on the plaintext.
///
/// Relation: `R_PwR = {(N, q, c; x, r) | c = Enc(pk, x; r) AND x in Z_q}`
pub struct PiBProof {
    /// Commitment ciphertext `A = Enc(pk, alpha; beta)`.
    pub A: Integer,
    /// Response `z1 = alpha + e * b` (integer arithmetic, no mod).
    pub z1: Integer,
    /// Response `z2 = beta * r^e mod N`.
    pub z2: Integer,
}

impl PiBProof {
    /// Create a PiB proof.
    ///
    /// Proves: `c_B = Enc(pk, b; r)` with `b in [0, q)`.
    ///
    /// # Arguments
    /// - `ek`: Paillier encryption key
    /// - `c_B`: the ciphertext to prove about
    /// - `b`: the plaintext value
    /// - `r`: the encryption nonce
    /// - `q`: the curve order
    /// - `rng`: cryptographic RNG
    pub fn prove(
        ek: &EncryptionKey,
        c_B: &Integer,
        b: &Integer,
        r: &Integer,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let n = ek.n();

        // Sampling range: q * 2^{tau + kappa}
        let sample_bound = q * Integer::u_pow_u(2, TAU + KAPPA).complete();

        // alpha <- Z_{q * 2^{tau+kappa}}
        let alpha = sample_bound.sample_below_ref(rng);

        // beta <- Z*_N
        let beta = Integer::sample_in_mult_group_of(rng, n);

        // A = Enc(pk, alpha; beta) = beta^N * (1+N)^alpha mod N^2
        let A = ek
            .encrypt_with(&alpha, &beta)
            .expect("alpha is in valid range for encryption");

        // Challenge: e = H("xal21-pi-b", N, q, c_B, A) mod 2^kappa
        let e = compute_challenge_pib(n, q, c_B, &A);

        // z1 = alpha + e * b (integer arithmetic)
        let z1 = &alpha + (&e * b).complete();

        // z2 = beta * r^e mod N
        let r_to_e = r
            .pow_mod_ref(&e, n)
            .expect("modular exponentiation should succeed")
            .complete();
        let z2 = (beta * r_to_e).modulo(n);

        PiBProof { A, z1, z2 }
    }

    /// Verify a PiB proof.
    ///
    /// Checks:
    /// 1. `z1 in [0, q * 2^{tau+kappa} + q * 2^kappa]`
    /// 2. `Enc(pk, z1; z2) == A * c_B^e mod N^2`
    ///
    /// # Arguments
    /// - `ek`: Paillier encryption key
    /// - `c_B`: the ciphertext being proven about
    /// - `q`: the curve order
    #[must_use]
    pub fn verify(&self, ek: &EncryptionKey, c_B: &Integer, q: &Integer) -> bool {
        let n = ek.n();
        let n2 = ek.nn();

        // Recompute challenge
        let e = compute_challenge_pib(n, q, c_B, &self.A);

        // Range check: z1 in [0, q * 2^{tau+kappa} + q * 2^kappa]
        let upper_bound = q * Integer::u_pow_u(2, TAU + KAPPA).complete()
            + q * Integer::u_pow_u(2, KAPPA).complete();
        let z1_in_range = self.z1.cmp0().is_ge() && self.z1 <= upper_bound;

        // z2 must be in Z*_N (positive, coprime to N)
        let z2_valid = self.z2.in_mult_group_of(n);

        // Verification equation: Enc(pk, z1; z2) == A * c_B^e mod N^2
        //
        // LHS: z2^N * (1+N)^z1 mod N^2
        // We need z1 to be in the valid encryption range. Since z1 could be
        // larger than N/2, we compute the encryption manually.
        let lhs = paillier_encrypt_raw(n, n2, &self.z1, &self.z2);

        // RHS: A * c_B^e mod N^2
        let c_B_to_e = c_B
            .pow_mod_ref(&e, n2)
            .expect("modular exponentiation should succeed")
            .complete();
        let rhs = (&self.A * &c_B_to_e).complete().modulo(n2);

        z1_in_range && z2_valid && lhs == rhs
    }
}

// ---------------------------------------------------------------------------
// PiA: Affine range-bounded operation proof (R'_AffRan)
// ---------------------------------------------------------------------------

/// PiA proof: proves the affine homomorphic operation was done correctly
/// with the scalar in range.
///
/// Relation: `R'_AffRan = {(N, q, c_A, c_B; a, alpha', r') |
///   c_A = c_B^a * Enc(pk, alpha'; r') AND a in Z_q AND alpha' in Z_K}`
///
/// where `K = q^2 * 2^{tau + 2*kappa}`.
pub struct PiAProof {
    /// Commitment ciphertext `A = c_B^gamma * Enc(pk, delta; mu) mod N^2`.
    pub A: Integer,
    /// Response `z1 = gamma + e * a` (integer, no mod).
    pub z1: Integer,
    /// Response `z2 = delta + e * alpha'` (integer, no mod).
    pub z2: Integer,
    /// Response `z3 = mu * r'^e mod N`.
    pub z3: Integer,
}

impl PiAProof {
    /// Create a PiA proof.
    ///
    /// Proves: `c_A = c_B^a * Enc(pk, alpha'; r')` with `a in Z_q` and
    /// `alpha' in Z_K` where `K = q^2 * 2^{tau + 2*kappa}`.
    ///
    /// # Arguments
    /// - `ek`: Paillier encryption key
    /// - `c_A`: the output ciphertext
    /// - `c_B`: the input ciphertext (encrypted by the other party)
    /// - `a`: the scalar multiplier (the prover's secret)
    /// - `alpha_prime`: the additive mask
    /// - `r_prime`: the encryption nonce for the mask
    /// - `q`: the curve order
    /// - `rng`: cryptographic RNG
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

        // K = q^2 * 2^{tau + 2*kappa}
        let K = (q * q).complete() * Integer::u_pow_u(2, TAU + 2 * KAPPA).complete();

        // Sampling ranges
        let gamma_bound = q * Integer::u_pow_u(2, TAU + KAPPA).complete();
        let delta_bound = &K * Integer::u_pow_u(2, TAU + KAPPA).complete();

        // gamma <- Z_{q * 2^{tau+kappa}}
        let gamma = gamma_bound.sample_below_ref(rng);

        // delta <- Z_{K * 2^{tau+kappa}}
        let delta = delta_bound.sample_below_ref(rng);

        // mu <- Z*_N
        let mu = Integer::sample_in_mult_group_of(rng, n);

        // A = c_B^gamma * Enc(pk, delta; mu) mod N^2
        let c_B_gamma = c_B
            .pow_mod_ref(&gamma, nn)
            .expect("modular exponentiation should succeed")
            .complete();
        let enc_delta = paillier_encrypt_raw(n, nn, &delta, &mu);
        let A = (c_B_gamma * enc_delta).modulo(nn);

        // Challenge: e = H("xal21-pi-a", N, q, c_A, c_B, A) mod 2^kappa
        let e = compute_challenge_pia(n, q, c_A, c_B, &A);

        // z1 = gamma + e * a (integer)
        let z1 = &gamma + (&e * a).complete();

        // z2 = delta + e * alpha' (integer)
        let z2 = &delta + (&e * alpha_prime).complete();

        // z3 = mu * r'^e mod N
        let r_prime_to_e = r_prime
            .pow_mod_ref(&e, n)
            .expect("modular exponentiation should succeed")
            .complete();
        let z3 = (mu * r_prime_to_e).modulo(n);

        PiAProof { A, z1, z2, z3 }
    }

    /// Verify a PiA proof.
    ///
    /// Checks:
    /// 1. `z1 in [0, q * 2^{tau+kappa} + q * 2^kappa]`
    /// 2. `z2 in [0, K * 2^{tau+kappa} + K * 2^kappa]`
    /// 3. `c_B^z1 * Enc(pk, z2; z3) == A * c_A^e mod N^2`
    ///
    /// # Arguments
    /// - `ek`: Paillier encryption key
    /// - `c_A`: the output ciphertext
    /// - `c_B`: the input ciphertext
    /// - `q`: the curve order
    #[must_use]
    pub fn verify(&self, ek: &EncryptionKey, c_A: &Integer, c_B: &Integer, q: &Integer) -> bool {
        let n = ek.n();
        let nn = ek.nn();

        // K = q^2 * 2^{tau + 2*kappa}
        let K = (q * q).complete() * Integer::u_pow_u(2, TAU + 2 * KAPPA).complete();

        // Recompute challenge
        let e = compute_challenge_pia(n, q, c_A, c_B, &self.A);

        // Range check on z1: z1 in [0, q * 2^{tau+kappa} + q * 2^kappa]
        let z1_upper = q * Integer::u_pow_u(2, TAU + KAPPA).complete()
            + q * Integer::u_pow_u(2, KAPPA).complete();
        let z1_in_range = self.z1.cmp0().is_ge() && self.z1 <= z1_upper;

        // Range check on z2: z2 in [0, K * 2^{tau+kappa} + K * 2^kappa]
        let z2_upper = &K * Integer::u_pow_u(2, TAU + KAPPA).complete()
            + &K * Integer::u_pow_u(2, KAPPA).complete();
        let z2_in_range = self.z2.cmp0().is_ge() && self.z2 <= z2_upper;

        // z3 must be in Z*_N
        let z3_valid = self.z3.in_mult_group_of(n);

        // Verification equation: c_B^z1 * Enc(pk, z2; z3) == A * c_A^e mod N^2
        let c_B_z1 = c_B
            .pow_mod_ref(&self.z1, nn)
            .expect("modular exponentiation should succeed")
            .complete();
        let enc_z2 = paillier_encrypt_raw(n, nn, &self.z2, &self.z3);
        let lhs = (c_B_z1 * enc_z2).modulo(nn);

        let c_A_e = c_A
            .pow_mod_ref(&e, nn)
            .expect("modular exponentiation should succeed")
            .complete();
        let rhs = (&self.A * &c_A_e).complete().modulo(nn);

        z1_in_range && z2_in_range && z3_valid && lhs == rhs
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Raw Paillier encryption without the signed-group check.
///
/// Computes `(1 + x*N) * r^N mod N^2`. Unlike the standard `encrypt_with`,
/// this function does not enforce that `x in [-N/2, N/2]`, which is required
/// for ZK responses that can exceed the normal encryption range.
pub(crate) fn paillier_encrypt_raw(n: &Integer, nn: &Integer, x: &Integer, r: &Integer) -> Integer {
    // (1 + N)^x mod N^2 = (1 + x*N) mod N^2  (by binomial theorem)
    let one_plus_xN = (Integer::one() + (x * n).complete()).modulo(nn);
    // r^N mod N^2
    let r_to_N = r
        .pow_mod_ref(n, nn)
        .expect("modular exponentiation should succeed")
        .complete();
    (one_plus_xN * r_to_N).modulo(nn)
}

/// Compute Fiat-Shamir challenge for PiB.
///
/// `e = H("xal21-pi-b" || N || q || c_B || A) mod 2^kappa`
fn compute_challenge_pib(n: &Integer, q: &Integer, c_B: &Integer, A: &Integer) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"xal21-pi-b");
    hasher.update(n.to_bytes_msf());
    hasher.update(q.to_bytes_msf());
    hasher.update(c_B.to_bytes_msf());
    hasher.update(A.to_bytes_msf());
    let hash = hasher.finalize();

    // Interpret hash as integer and reduce mod 2^kappa
    let hash_int = Integer::from_bytes_msf(&hash);
    let modulus = Integer::u_pow_u(2, KAPPA).complete();
    hash_int.modulo(&modulus)
}

/// Compute Fiat-Shamir challenge for PiA.
///
/// `e = H("xal21-pi-a" || N || q || c_A || c_B || A) mod 2^kappa`
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
    let modulus = Integer::u_pow_u(2, KAPPA).complete();
    hash_int.modulo(&modulus)
}
