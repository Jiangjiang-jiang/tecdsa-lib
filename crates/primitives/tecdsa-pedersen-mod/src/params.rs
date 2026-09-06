// SPDX-License-Identifier: MIT OR Apache-2.0
//! Ring-Pedersen parameter generation.
//!
//! Generates `(N, s, t)` where:
//! - `N = p * q` for Blum safe primes `p, q` (p = q = 3 mod 4)
//! - `t = r^2 mod N` for a random `r` in `Z*_N` (ensures `t` is a QR)
//! - `s = t^lambda mod N` for a random `lambda` in `[1, phi(N))`
//!
//! This follows the setup described in CGGMP20 Section 3.3.

use rand_core::CryptoRngCore;
use rug::Integer;
use serde::{Deserialize, Serialize};
use tecdsa_bigint::BigIntExt;

/// Ring-Pedersen parameters over an RSA modulus.
///
/// Public values `(N, s, t)` used as auxiliary data in Paillier ZK proofs
/// (e.g., `Pi_enc`, `Pi_aff_g`, `Pi_fac`). The prover knows the factorisation
/// `N = p * q`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenModParams {
    /// RSA modulus `N = p * q`.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub n: Integer,
    /// Ring-Pedersen base `s = t^lambda mod N`.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub s: Integer,
    /// Ring-Pedersen base `t = r^2 mod N` (quadratic residue).
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub t: Integer,
}

/// Secret material held by the party that generated the parameters.
///
/// Needed for proving correctness (`Pi_prm`, `Pi_mod`) but not shared publicly.
#[derive(Debug, Clone)]
pub struct PedersenModSecret {
    /// Safe prime factor of `N`.
    pub p: Integer,
    /// Safe prime factor of `N`.
    pub q: Integer,
    /// Discrete log `lambda` such that `s = t^lambda mod N`.
    pub lambda: Integer,
}

impl PedersenModParams {
    /// Generate fresh ring-Pedersen parameters with safe primes of `bits` bits each.
    ///
    /// The resulting modulus `N` is approximately `2 * bits` bits long.
    /// Use `bits = 256` for fast tests and `bits >= 1536` for production security.
    #[allow(clippy::similar_names, clippy::many_single_char_names)]
    pub fn generate(bits: u64, rng: &mut impl CryptoRngCore) -> (Self, PedersenModSecret) {
        // p and q are safe primes (p = 2p' + 1), which are automatically Blum primes
        // (p = 3 mod 4) because p' is an odd prime.
        let bits = u32::try_from(bits).expect("modulus size fits in u32");
        let p = Integer::generate_blum_prime(&mut *rng, bits);
        let q = Integer::generate_blum_prime(&mut *rng, bits);

        let n = Integer::from(&p * &q);

        // phi(N) = (p-1)(q-1)
        let p_minus_1 = Integer::from(&p - 1);
        let q_minus_1 = Integer::from(&q - 1);
        let phi_n = p_minus_1 * q_minus_1;

        // Sample r in Z*_N, compute t = r^2 mod N (quadratic residue)
        let r = sample_coprime(rng, &n);
        let t = r.pow_mod(&Integer::from(2), &n).unwrap();

        // Sample lambda in [1, phi(N))
        let lambda = phi_n.sample_positive_below(rng);

        // s = t^lambda mod N
        let s = t.clone().pow_mod(&lambda, &n).unwrap();

        let params = Self { n, s, t };
        let secret = PedersenModSecret { p, q, lambda };
        (params, secret)
    }

    /// Returns the bit-length of the modulus `N`.
    #[must_use]
    pub fn modulus_bits(&self) -> u64 {
        self.n.significant_bits() as u64
    }

    /// Basic structural validation: `N > 1`, `s, t` are in `[1, N)` and
    /// coprime to `N`.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        // N must be > 1 and odd
        if self.n.significant_bits() < 2 || self.n.is_even() {
            return false;
        }

        // s, t must be in [1, N) and coprime to N
        self.s.in_mult_group_of(&self.n)
            && self.t.in_mult_group_of(&self.n)
            && self.s != 1
            && self.t != 1
    }
}

/// Sample a random element in `Z*_N`.
fn sample_coprime(rng: &mut impl CryptoRngCore, n: &Integer) -> Integer {
    loop {
        let x = Integer::sample_in_mult_group_of(rng, n);
        // 1 is excluded: it is a degenerate Ring-Pedersen generator.
        if x > 1 {
            return x;
        }
    }
}
