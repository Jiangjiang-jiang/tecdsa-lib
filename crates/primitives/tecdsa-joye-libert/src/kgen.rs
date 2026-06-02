// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key generation for the Joye-Libert encryption scheme.
//!
//! Generates an RSA-like modulus `N = p * q` where:
//! - `p = 2^k * p' + 1` with `p'` an odd prime
//! - `q = 2 * q' + 1` with `q'` prime (safe prime)
//!
//! The public key contains a generator derived from a quadratic non-residue
//! modulo both `p` and `q`, ensuring the scheme's security properties.

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tecdsa_bigint::jacobi;
use zeroize::Zeroize;

/// Public key for the Joye-Libert encryption scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlPublicKey {
    /// Modulus N = p * q.
    pub n: BigUint,
    /// Generator y = x^alpha mod N, used for encoding messages.
    pub y: BigUint,
    /// Element h = x^{2^k} mod N, used for randomisation.
    pub h: BigUint,
    /// Parameter k: plaintexts live in Z_{2^k}.
    pub k: u32,
}

/// Secret key for the Joye-Libert encryption scheme.
#[derive(Clone, Serialize, Deserialize)]
pub struct JlSecretKey {
    /// Prime factor p of N, where p = 2^k * p' + 1.
    pub p: BigUint,
    /// Discrete log alpha such that y = x^alpha mod N.
    pub alpha: BigUint,
}

impl Zeroize for JlSecretKey {
    fn zeroize(&mut self) {
        // Overwrite secret fields with zero before dropping.
        self.p = BigUint::zero();
        self.alpha = BigUint::zero();
    }
}

impl Drop for JlSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for JlSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JlSecretKey")
            .field("p", &"[REDACTED]")
            .field("alpha", &"[REDACTED]")
            .finish()
    }
}

/// Security level for the JL scheme, determining modulus size and message space.
#[derive(Clone, Copy, Debug)]
pub enum SecurityLevel {
    /// 128-bit security: ~3360-bit modulus, k = 256.
    Sec128,
    /// 192-bit security: ~7680-bit modulus, k = 384.
    Sec192,
    /// 256-bit security: ~15360-bit modulus, k = 512.
    Sec256,
}

impl SecurityLevel {
    /// Returns `(p_bits, k)` for the security level.
    #[must_use]
    pub const fn params(self) -> (u64, u32) {
        match self {
            Self::Sec128 => (1680, 256),
            Self::Sec192 => (3840, 384),
            Self::Sec256 => (7680, 512),
        }
    }
}

/// Generates a JL key pair at the given security level.
///
/// # Note
///
/// Full-size key generation (3360+ bit modulus) is very slow. For testing
/// purposes, use [`generate_keypair_with_params`] with small parameters.
pub fn generate_keypair(
    level: SecurityLevel,
    rng: &mut impl CryptoRngCore,
) -> (JlPublicKey, JlSecretKey) {
    let (p_bits, k) = level.params();
    generate_keypair_with_params(p_bits, k, rng)
}

/// Generates a JL key pair with explicit bit-size and message-space parameters.
///
/// `p_bits` controls the bit length of the prime `p`.
/// `msg_space_bits` controls the message space: plaintexts are in `Z_{2^k}`.
///
/// The modulus `N = p * q` will be approximately `2 * p_bits` bits.
#[allow(clippy::many_single_char_names)]
pub fn generate_keypair_with_params(
    p_bits: u64,
    msg_space_bits: u32,
    rng: &mut impl CryptoRngCore,
) -> (JlPublicKey, JlSecretKey) {
    // Step 1: Generate p = 2^k * p' + 1 where p' is an odd prime
    let (prime_p, _p_prime) = generate_jl_prime(p_bits, msg_space_bits, rng);

    // Step 2: Generate q = 2*q' + 1 (a safe prime) with approximately p_bits bits
    let prime_q = generate_safe_prime_inner(p_bits, rng);

    let modulus = &prime_p * &prime_q;

    // Step 3: Find x that is a quadratic non-residue mod both p and q
    let qnr = choose_non_quadratic_residue(&prime_p, &prime_q, &modulus, rng);

    // Step 4: Choose random odd alpha
    let mut alpha = rng.gen_biguint_below(&modulus);
    if alpha.is_even() {
        alpha += BigUint::one();
    }

    // Step 5: Compute y = x^alpha mod N
    let gen_y = qnr.modpow(&alpha, &modulus);

    // Step 6: Compute h = x^{2^k} mod N
    let two_pow_k = BigUint::one() << msg_space_bits;
    let elem_h = qnr.modpow(&two_pow_k, &modulus);

    let pk = JlPublicKey {
        n: modulus,
        y: gen_y,
        h: elem_h,
        k: msg_space_bits,
    };
    let sk = JlSecretKey { p: prime_p, alpha };

    (pk, sk)
}

/// Generates a JL key pair and also returns the QNR element `x`.
///
/// This variant exposes `x` so that setup ZK proofs (Pi_QR2k, Pi_QR2kDL)
/// can be constructed.  In production, `x` is ephemeral and discarded
/// after the proofs are created.
#[allow(clippy::many_single_char_names)]
pub fn generate_keypair_with_qnr(
    p_bits: u64,
    msg_space_bits: u32,
    rng: &mut impl CryptoRngCore,
) -> (JlPublicKey, JlSecretKey, BigUint) {
    let (prime_p, _p_prime) = generate_jl_prime(p_bits, msg_space_bits, rng);
    let prime_q = generate_safe_prime_inner(p_bits, rng);
    let modulus = &prime_p * &prime_q;
    let qnr = choose_non_quadratic_residue(&prime_p, &prime_q, &modulus, rng);

    let mut alpha = rng.gen_biguint_below(&modulus);
    if alpha.is_even() {
        alpha += BigUint::one();
    }

    let gen_y = qnr.modpow(&alpha, &modulus);
    let two_pow_k = BigUint::one() << msg_space_bits;
    let elem_h = qnr.modpow(&two_pow_k, &modulus);

    let pk = JlPublicKey {
        n: modulus,
        y: gen_y,
        h: elem_h,
        k: msg_space_bits,
    };
    let sk = JlSecretKey { p: prime_p, alpha };

    (pk, sk, qnr)
}

/// Generates a prime `p = 2^k * p' + 1` where `p'` is an odd prime.
///
/// Returns `(p, p')`.
fn generate_jl_prime(bits: u64, k: u32, rng: &mut impl CryptoRngCore) -> (BigUint, BigUint) {
    // p' needs to be roughly (bits - k) bits long so that p is bits-bit
    let p_prime_bits = bits.saturating_sub(u64::from(k));
    assert!(
        p_prime_bits > 1,
        "k is too large relative to the prime bit size"
    );

    let two_pow_k = BigUint::one() << k;

    loop {
        // Generate a random odd candidate for p'
        let mut p_prime = rng.gen_biguint(p_prime_bits);
        // Ensure p' is odd
        p_prime |= BigUint::one();

        // p = 2^k * p' + 1
        let p = &two_pow_k * &p_prime + BigUint::one();

        // Check p' is prime, then check p is prime
        if is_probably_prime(&p_prime, 40) && is_probably_prime(&p, 40) {
            return (p, p_prime);
        }
    }
}

/// Generates a safe prime `q = 2*q' + 1` where `q'` is prime.
fn generate_safe_prime_inner(bits: u64, rng: &mut impl CryptoRngCore) -> BigUint {
    loop {
        let q_prime = rng.gen_biguint(bits - 1) | BigUint::one();
        if !is_probably_prime(&q_prime, 40) {
            continue;
        }
        let q = (&q_prime << 1u32) | BigUint::one();
        if is_probably_prime(&q, 40) {
            return q;
        }
    }
}

/// Finds an element `x` that is a quadratic non-residue modulo both `p` and `q`.
fn choose_non_quadratic_residue(
    p: &BigUint,
    q: &BigUint,
    n: &BigUint,
    rng: &mut impl CryptoRngCore,
) -> BigUint {
    let p_dyn = tecdsa_bigint::DynInt::from(p.clone());
    let q_dyn = tecdsa_bigint::DynInt::from(q.clone());

    loop {
        let x = rng.gen_biguint_below(n);
        if x.is_zero() {
            continue;
        }
        let x_dyn = tecdsa_bigint::DynInt::from(x.clone());
        if jacobi(&x_dyn, &p_dyn) == -1 && jacobi(&x_dyn, &q_dyn) == -1 {
            return x;
        }
    }
}

/// Miller-Rabin primality test.
#[allow(clippy::many_single_char_names)]
fn is_probably_prime(n: &BigUint, rounds: u32) -> bool {
    let one = BigUint::one();
    let two = BigUint::from(2u32);

    if *n < two {
        return false;
    }
    if *n == two || *n == BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while d.is_even() {
        d >>= 1u32;
        r += 1;
    }

    let mut rng = rand::thread_rng();
    'witness: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&two, &(n - &one));
        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 {
            continue 'witness;
        }
        for _ in 1..r {
            x = (&x * &x) % n;
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_keygen_produces_valid_structure() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair_with_params(256, 32, &mut rng);

        // N should be non-zero
        assert!(!pk.n.is_zero());
        // p should divide N
        assert!((&pk.n % &sk.p).is_zero());
        // k should match
        assert_eq!(pk.k, 32);
        // y and h should be non-zero
        assert!(!pk.y.is_zero());
        assert!(!pk.h.is_zero());
    }
}
