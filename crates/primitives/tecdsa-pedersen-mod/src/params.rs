// SPDX-License-Identifier: MIT OR Apache-2.0
//! Ring-Pedersen parameter generation.
//!
//! Generates `(N, s, t)` where:
//! - `N = p * q` for Blum safe primes `p, q` (p = q = 3 mod 4)
//! - `t = r^2 mod N` for a random `r` in `Z*_N` (ensures `t` is a QR)
//! - `s = t^lambda mod N` for a random `lambda` in `[1, phi(N))`
//!
//! This follows the setup described in CGGMP20 Section 3.3.

use num_bigint::RandBigInt;
use num_integer::Integer as IntTrait;
use num_traits::One;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tecdsa_bigint::{generate_blum_prime, DynInt};

/// Ring-Pedersen parameters over an RSA modulus.
///
/// Public values `(N, s, t)` used as auxiliary data in Paillier ZK proofs
/// (e.g., `Pi_enc`, `Pi_aff_g`, `Pi_fac`). The prover knows the factorisation
/// `N = p * q`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenModParams {
    /// RSA modulus `N = p * q`.
    pub n: DynInt,
    /// Ring-Pedersen base `s = t^lambda mod N`.
    pub s: DynInt,
    /// Ring-Pedersen base `t = r^2 mod N` (quadratic residue).
    pub t: DynInt,
}

/// Secret material held by the party that generated the parameters.
///
/// Needed for proving correctness (`Pi_prm`, `Pi_mod`) but not shared publicly.
#[derive(Debug, Clone)]
pub struct PedersenModSecret {
    /// Safe prime factor of `N`.
    pub p: DynInt,
    /// Safe prime factor of `N`.
    pub q: DynInt,
    /// Discrete log `lambda` such that `s = t^lambda mod N`.
    pub lambda: DynInt,
}

impl PedersenModParams {
    /// Generate fresh ring-Pedersen parameters with safe primes of `bits` bits each.
    ///
    /// The resulting modulus `N` is approximately `2 * bits` bits long.
    /// Use `bits = 256` for fast tests and `bits >= 1536` for production security.
    #[allow(clippy::similar_names, clippy::many_single_char_names)]
    pub fn generate(bits: u64, rng: &mut impl CryptoRngCore) -> (Self, PedersenModSecret) {
        let p = generate_blum_prime(bits, rng);
        let q = generate_blum_prime(bits, rng);

        let n_big = p.inner() * q.inner();
        let n = DynInt::from(n_big);

        // phi(N) = (p-1)(q-1)
        let p_minus_1 = p.inner() - num_bigint::BigUint::one();
        let q_minus_1 = q.inner() - num_bigint::BigUint::one();
        let phi_n = &p_minus_1 * &q_minus_1;

        // Sample r in Z*_N, compute t = r^2 mod N (quadratic residue)
        let r = sample_coprime(rng, &n);
        let t_big = r
            .inner()
            .modpow(&num_bigint::BigUint::from(2u32), n.inner());
        let t = DynInt::from(t_big);

        // Sample lambda in [1, phi(N))
        let lambda_big = sample_in_range(rng, &phi_n);
        let lambda = DynInt::from(lambda_big.clone());

        // s = t^lambda mod N
        let s_big = t.inner().modpow(&lambda_big, n.inner());
        let s = DynInt::from(s_big);

        let params = Self { n, s, t };
        let secret = PedersenModSecret { p, q, lambda };
        (params, secret)
    }

    /// Returns the bit-length of the modulus `N`.
    #[must_use]
    pub fn modulus_bits(&self) -> u64 {
        self.n.bits()
    }

    /// Basic structural validation: `N > 1`, `s, t` are in `[1, N)` and
    /// coprime to `N`.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let one = DynInt::from(1u64);

        // N must be > 1 and odd
        if self.n.bits() < 2 || !self.n.is_odd() {
            return false;
        }

        // s, t must be in [1, N) and coprime to N
        is_in_mult_group(&self.s, &self.n)
            && is_in_mult_group(&self.t, &self.n)
            && self.s != one
            && self.t != one
    }
}

/// Check that `x` is in `Z*_N`: `0 < x < N` and `gcd(x, N) = 1`.
fn is_in_mult_group(x: &DynInt, n: &DynInt) -> bool {
    let zero = DynInt::zero();
    if *x <= zero || *x >= *n {
        return false;
    }
    tecdsa_bigint::gcd(x, n) == DynInt::from(1u64)
}

/// Sample a random element in `Z*_N`.
fn sample_coprime(rng: &mut impl CryptoRngCore, n: &DynInt) -> DynInt {
    let n_big = n.inner();
    let mut adapter = RandAdapter(rng);
    loop {
        let x = adapter.gen_biguint_below(n_big);
        if x > num_bigint::BigUint::one() && x.gcd(n_big).is_one() {
            return DynInt::from(x);
        }
    }
}

/// Sample a random value in `[1, upper)`.
fn sample_in_range(
    rng: &mut impl CryptoRngCore,
    upper: &num_bigint::BigUint,
) -> num_bigint::BigUint {
    let mut adapter = RandAdapter(rng);
    loop {
        let x = adapter.gen_biguint_below(upper);
        if x > num_bigint::BigUint::zero() {
            return x;
        }
    }
}

use num_traits::Zero;

/// Adapter from `CryptoRngCore` to the `rand 0.8` `RngCore` trait required
/// by `RandBigInt`.
pub(crate) struct RandAdapter<'a, R: CryptoRngCore>(pub(crate) &'a mut R);

impl<R: CryptoRngCore> rand_core::RngCore for RandAdapter<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}
