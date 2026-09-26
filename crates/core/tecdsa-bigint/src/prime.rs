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
    // Safe-prime case (a = 2): f = 2r+1 with r = (f-1)/2 a known prime > sqrt(f),
    // so by Pocklington a single base-2 Fermat test proves f prime given r prime.
    let pocklington = *a == 2;
    loop {
        // Random odd base; candidates in this window are r = base + 2*j, j in [0, w).
        let base = random_odd(seed_bits, rng);
        let sieve = sieve_window(&base, a, w, small_primes);

        for j in 0..w {
            if sieve[j] {
                continue;
            }
            if let Some(pair) = test_candidate(&base, a, j, mr_rounds, pocklington) {
                return pair;
            }
        }
        // window exhausted -> draw a fresh random base
    }
}

/// Sieve a window of `w` candidates `r = base + 2j` against `small_primes`,
/// ruling out positions where either `r` or `a*r + 1` is divisible by a small
/// prime. `sieve[j] == true` means "ruled out".
fn sieve_window(base: &Integer, a: &Integer, w: usize, small_primes: &[u64]) -> Vec<bool> {
    let mut sieve = vec![false; w];
    mark_sieve(&mut sieve, base, a, w, small_primes);
    sieve
}

fn mark_sieve(sieve: &mut [bool], base: &Integer, a: &Integer, w: usize, small_primes: &[u64]) {
    for &l in small_primes {
        let base_l = u64::from(base.mod_u(l as u32));
        let a_l = u64::from(a.mod_u(l as u32));
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
}

/// Test one surviving window position: is `(r, a*r + 1)` a prime pair?
fn test_candidate(
    base: &Integer,
    a: &Integer,
    j: usize,
    mr_rounds: u32,
    pocklington: bool,
) -> Option<(Integer, Integer)> {
    let r = Integer::from(base + 2 * j as u64);
    // Cheap filter: one Miller-Rabin round rejects almost all composite r.
    if r.is_probably_prime(1) == IsPrime::No {
        return None;
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
        return None;
    }
    // Confirm r with the full round count (also discharges Pocklington's premise).
    if r.is_probably_prime(mr_rounds) != IsPrime::No {
        Some((r, f))
    } else {
        None
    }
}

/// Multithreaded [`gen_pair`].
///
/// Same output contract as [`gen_pair`]: for a given random base it returns the
/// *lowest-index* surviving candidate in the window, so the returned
/// distribution is identical to the sequential version. Two levels of rayon
/// parallelism are used:
///
/// 1. the small-prime sieve is split across threads (each thread marks a
///    disjoint slice of `small_primes` into its own bitmap, then the bitmaps
///    are OR-ed together);
/// 2. the surviving candidates are primality-tested with `find_map_first`,
///    which keeps the "first match wins" semantics while cancelling the work
///    on later indices as soon as an earlier one succeeds.
#[cfg(feature = "parallel")]
pub fn gen_pair_par(
    seed_bits: u32,
    a: &Integer,
    mr_rounds: u32,
    window_bits: u32,
    small_primes: &[u64],
    rng: &mut impl MutRandState,
) -> (Integer, Integer) {
    use rayon::prelude::*;

    let w: usize = 1 << window_bits;
    let pocklington = *a == 2;
    let chunk = small_primes
        .len()
        .div_ceil(rayon::current_num_threads().max(1));

    loop {
        let base = random_odd(seed_bits, rng);

        // (1) Parallel sieve: one bitmap per chunk of small primes, then OR.
        let sieve = small_primes
            .par_chunks(chunk)
            .map(|primes| sieve_window(&base, a, w, primes))
            .reduce(
                || vec![false; w],
                |mut acc, part| {
                    for (a, b) in acc.iter_mut().zip(part) {
                        *a |= b;
                    }
                    acc
                },
            );

        // (2) Parallel primality testing, first surviving index wins.
        let survivors: Vec<usize> = (0..w).filter(|&j| !sieve[j]).collect();
        let found = survivors
            .par_iter()
            .find_map_first(|&j| test_candidate(&base, a, j, mr_rounds, pocklington));
        if let Some(pair) = found {
            return pair;
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
