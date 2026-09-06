// SPDX-License-Identifier: MIT OR Apache-2.0
use rand_core::RngCore;
use rug::{
    integer::IsPrime,
    rand::{MutRandState, ThreadRandGen},
    Integer,
};

/// Miller-Rabin confidence rounds for an accepted prime (25, as `mpz_nextprime` uses).
pub(crate) const MR_ROUNDS: u32 = 25;

/// Width (in bits) of the candidate window scanned per random base.
pub(crate) const WINDOW_BITS: u32 = 15;

/// Small-prime sieve bound used by safe-prime generation, chosen by prime size.
///
/// Larger candidates benefit from removing many more composites up front, while
/// small ones would only pay the extra sieve cost. Tiers were picked by benchmark.
#[must_use]
pub fn default_sieve_limit(bits: u64) -> usize {
    if bits <= 512 {
        50_000
    } else if bits <= 1024 {
        200_000
    } else {
        500_000
    }
}

/// Odd primes below `limit` (sieve of Eratosthenes), used for the double sieve.
pub fn small_odd_primes(limit: usize) -> Vec<u64> {
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
pub fn gen_pair(
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
            let inv2 = l.div_ceil(2); // 2^-1 mod l for odd l

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

        // Safe-prime case (a = 2): f = 2r+1 with r = (f-1)/2 a known prime > sqrt(f),
        // so by Pocklington a single base-2 Fermat test proves f prime given r prime.
        let pocklington = *a == 2;
        for j in 0..w {
            if sieve[j] {
                continue;
            }
            let r = Integer::from(&base + 2 * j as u64);
            // Cheap filter: one Miller-Rabin round rejects almost all composite r.
            if r.is_probably_prime(1) == IsPrime::No {
                continue;
            }
            let mut f = Integer::from(a * &r);
            f += Integer::ONE;
            let f_is_prime = if pocklington {
                // gcd(2^2-1, f) = gcd(3, f) = 1 (3 is sieved); then f prime <=> 2^(f-1) == 1 (mod f).
                f.mod_u(3) != 0
                    && Integer::from(2)
                        .pow_mod(&Integer::from(&f - 1), &f)
                        .unwrap()
                        == 1
            } else {
                f.is_probably_prime(mr_rounds) != IsPrime::No
            };
            if !f_is_prime {
                continue;
            }
            // Confirm r with the full round count (also discharges Pocklington's premise).
            if r.is_probably_prime(mr_rounds) != IsPrime::No {
                return (r, f);
            }
        }
        // window exhausted -> draw a fresh random base
    }
}

/// Adapts a [`rand_core::RngCore`] to rug's [`ThreadRandGen`].
///
/// Wraps `R` by value, but `&mut R` is itself `RngCore`, so `SyncRng(rng)` works
/// for a borrowed RNG too. rug's `ThreadRandState` borrows the adapter, so it
/// cannot be returned from a helper without a transparent transmute (upstream
/// used `bytemuck`); callers hold it as a local instead, which avoids both the
/// dependency and the `unsafe` this workspace forbids.
pub struct SyncRng<R: RngCore>(pub R);
impl<R: RngCore> ThreadRandGen for SyncRng<R> {
    fn r#gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}
