// SPDX-License-Identifier: MIT OR Apache-2.0
use rand_core::CryptoRngCore;
use rug::{
    integer::IsPrime,
    rand::{MutRandState, ThreadRandGen},
    Integer,
};

/// Returns `true` if `p` is a safe prime, i.e. both `p` and `(p-1)/2` are
/// (probably) prime.
#[must_use]
#[allow(clippy::module_name_repetitions)]
pub fn is_safe_prime(p: &Integer) -> bool {
    if p.is_probably_prime(25) == IsPrime::No {
        return false;
    }
    let sophie = Integer::from(p - 1) >> 1u32;
    sophie.is_probably_prime(25) != IsPrime::No
}

/// Small-prime sieve bound used by [`generate_safe_prime`], chosen by prime size.
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

/// Generates a random safe prime of approximately `bits` bits using `rng`.
///
/// Generates a Sophie Germain prime `q` of `bits - 1` bits, then returns
/// `p = 2q + 1`.
#[allow(clippy::module_name_repetitions)]
pub fn generate_safe_prime(bits: u64, rng: &mut impl CryptoRngCore) -> Integer {
    let mut sync_rng = SyncRng(&mut *rng);
    let rug_rng = &mut rug::rand::ThreadRandState::new_custom(&mut sync_rng);
    let primes = small_odd_primes(default_sieve_limit(bits));
    let (_, p) = gen_pair(bits as u32 - 1, &Integer::from(2), 25, 15, &primes, rug_rng);
    p
}

/// Generate a random Blum prime: a safe prime p with p = 3 mod 4.
///
/// For safe primes p = 2p'+1 where p' > 2, p = 3 mod 4 always holds.
/// This function makes that guarantee explicit.
///
/// # Panics
///
/// Panics if the generated safe prime is not = 3 mod 4 (invariant violation).
#[allow(clippy::module_name_repetitions)]
pub fn generate_blum_prime(bits: u64, rng: &mut impl CryptoRngCore) -> Integer {
    let p = generate_safe_prime(bits, rng);
    assert_eq!(p.mod_u(4), 3, "safe prime must be = 3 mod 4 for bits >= 3");
    p
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

pub struct SyncRng<R: CryptoRngCore>(pub R);
impl<R: CryptoRngCore> ThreadRandGen for SyncRng<R> {
    fn r#gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}
