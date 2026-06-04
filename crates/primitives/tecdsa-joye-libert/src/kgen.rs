// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key generation for the Joye-Libert encryption scheme.
//!
//! Generates an RSA-like modulus `N = p * q` where:
//! - `p = 2^k * p' + 1` with `p'` an odd prime
//! - `q = 2 * q' + 1` with `q'` prime (safe prime)
//!
//! The public key contains a generator derived from a quadratic non-residue
//! modulo both `p` and `q`, ensuring the scheme's security properties.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand_core::CryptoRngCore;
use rug::{
    integer::{IsPrime, Order},
    rand::{MutRandState, ThreadRandGen, ThreadRandState},
    Integer,
};
use serde::{Deserialize, Serialize};
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

/// Odd primes below `limit` (sieve of Eratosthenes), used for the double sieve.
fn small_odd_primes(limit: usize) -> Vec<u64> {
    let mut composite = vec![false; limit];
    let mut out = Vec::new();
    for i in 2..limit {
        if !composite[i] {
            if i > 2 {
                out.push(i as u64);
            }
            let mut m = i * i;
            while m < limit {
                composite[m] = true;
                m += i;
            }
        }
    }
    out
}

/// x^(l-2) mod l = x^-1 mod l (Fermat; l an odd prime, 0 < x < l).
fn inv_mod(x: u64, l: u64) -> u64 {
    let (mut result, mut base, mut e) = (1u64, x % l, l - 2);
    while e > 0 {
        if e & 1 == 1 {
            result = result * base % l;
        }
        base = base * base % l;
        e >>= 1;
    }
    result
}

/// Uniform random odd integer with exactly `bits` bits (top bit set), from the OS CSPRNG.
fn random_odd(bits: u32, rng: &mut impl MutRandState) -> Integer {
    let mut x = Integer::from(Integer::random_bits(bits, rng));
    x.keep_bits_mut(bits);
    x.set_bit(bits - 1, true);
    x.set_bit(0, true);
    x
}

/// Return (r, a*r + 1) with both prime; r has ~`seed_bits` bits.
///
/// Generic builder for a "chain" prime: r prime AND a*r+1 prime.
///   - q : call with a=2   -> returns (q', q)
///   - p : call with a=2^k -> returns (p', p)
fn gen_pair(
    seed_bits: u32,
    a: &Integer,
    mr_rounds: u32,
    window_bits: u32,
    small_primes: &[u64],
    rng: &mut impl MutRandState,
) -> (Integer, Integer) {
    let w: usize = 1 << window_bits;
    loop {
        // Random odd base; candidates in this window are r = base + 2*j, j in [0, w).
        let base = random_odd(seed_bits, rng);
        let mut sieve = vec![false; w]; // true = ruled out

        for &l in small_primes {
            let base_l = base.mod_u(l as u32) as u64;
            let a_l = a.mod_u(l as u32) as u64;
            let inv2 = (l + 1) / 2; // 2^-1 mod l for odd l

            // Kill positions where r = base + 2j == 0 (mod l).
            let j0 = ((l - base_l) % l * inv2 % l) as usize;
            let mut idx = j0;
            while idx < w {
                sieve[idx] = true;
                idx += l as usize;
            }
            // Kill positions where f = a*r + 1 == 0 (mod l): 2*a*j == -(a*base + 1).
            if a_l != 0 {
                let c = (a_l * base_l + 1) % l;
                let jf = ((l - c) % l * inv_mod(2 * a_l % l, l) % l) as usize;
                let mut idx = jf;
                while idx < w {
                    sieve[idx] = true;
                    idx += l as usize;
                }
            }
        }

        for j in 0..w {
            if sieve[j] {
                continue;
            }
            let r = Integer::from(&base + 2 * j as u64);
            if r.is_probably_prime(mr_rounds) != IsPrime::No {
                // cheap seed first
                let mut f = Integer::from(a * &r);
                f += Integer::ONE;
                if f.is_probably_prime(mr_rounds) != IsPrime::No {
                    return (r, f);
                }
            }
        }
        // window exhausted -> draw a fresh random base
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

struct SyncRng<R: CryptoRngCore>(R);
impl<R: CryptoRngCore> ThreadRandGen for SyncRng<R> {
    fn r#gen(&mut self) -> u32 {
        self.0.next_u32()
    }
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
    let (pk, sk, _) = generate_keypair_with_qnr(p_bits, msg_space_bits, rng);
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
    rng: impl CryptoRngCore,
) -> (JlPublicKey, JlSecretKey, BigUint) {
    let mut rng = SyncRng(rng);
    let rng = &mut ThreadRandState::new_custom(&mut rng);
    let primes = small_odd_primes(50_000);

    let b = p_bits as u32;
    let k = msg_space_bits;
    // Step 1: p = 2^k*p'+1
    let (_, p) = gen_pair(b - k, &(Integer::ONE << k).into(), 25, 15, &primes, rng);
    // Step 2: q = 2*q'+1
    let (_, q) = gen_pair(b - 1, &Integer::from(2), 25, 15, &primes, rng);

    let n = (&p * &q).into();

    // Step 3: Find x that is a quadratic non-residue mod both p and q
    let qnr = choose_non_quadratic_residue(&p, &q, &n, rng);

    let p = BigUint::from_bytes_be(&p.to_digits(Order::Msf));
    let qnr = BigUint::from_bytes_be(&qnr.to_digits(Order::Msf));

    // Step 4: Choose random odd alpha
    let mut alpha = n.clone().random_below(rng);
    alpha.set_bit(0, true);

    let alpha = BigUint::from_bytes_be(&alpha.to_digits(Order::Msf));
    let n = BigUint::from_bytes_be(&n.to_digits(Order::Msf));

    // Step 5: Compute y = x^alpha mod N
    let gen_y = qnr.modpow(&alpha, &n);

    // Step 6: Compute h = x^{2^k} mod N
    let two_pow_k = BigUint::one() << msg_space_bits;
    let elem_h = qnr.modpow(&two_pow_k, &n);

    let pk = JlPublicKey {
        n,
        y: gen_y,
        h: elem_h,
        k: msg_space_bits,
    };
    let sk = JlSecretKey { p, alpha };

    (pk, sk, qnr)
}

/// Finds an element `x` that is a quadratic non-residue modulo both `p` and `q`.
fn choose_non_quadratic_residue(
    p: &Integer,
    q: &Integer,
    n: &Integer,
    rng: &mut impl MutRandState,
) -> Integer {
    loop {
        let x = n.clone().random_below(rng);
        if x.jacobi(&p) == -1 && x.jacobi(&q) == -1 {
            return x;
        }
    }
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
