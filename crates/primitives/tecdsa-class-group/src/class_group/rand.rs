//! Seedable pseudo-random number generator.
//!
//! Backed by GMP's Mersenne-Twister `randstate` via `rug`. Byte-for-byte
//! stream compatibility with any other implementation is *not* a goal — the CL
//! scheme's security only requires the samples be (statistically) uniform over
//! the stated ranges.

use rug::{rand::RandState, Integer};

/// A seedable RNG used for key generation, encryption randomness and prime
/// generation.
#[derive(Clone)]
pub struct RandGen {
    state: RandState<'static>,
}

impl RandGen {
    /// New generator with the default (unseeded) state.
    pub fn new() -> Self {
        RandGen {
            state: RandState::new(),
        }
    }

    /// New generator seeded with `seed`.
    pub fn with_seed(seed: &Integer) -> Self {
        let mut g = RandGen::new();
        g.set_seed(seed);
        g
    }

    /// (Re)seed the generator.
    pub fn set_seed(&mut self, seed: &Integer) {
        self.state.seed(seed);
    }

    /// Uniform integer in `[0, bound)`. Requires `bound > 0`.
    pub fn random_mpz(&mut self, bound: &Integer) -> Integer {
        debug_assert!(bound.cmp0().is_gt(), "random_mpz: bound must be positive");
        bound.clone().random_below(&mut self.state)
    }

    /// Uniform non-negative integer with exactly `nbits` bits available
    /// (i.e. in `[0, 2^nbits)`).
    pub fn random_bits(&mut self, nbits: usize) -> Integer {
        Integer::from(Integer::random_bits(nbits as u32, &mut self.state))
    }

    /// A random prime with exactly `nbits` bits (top bit set).
    pub fn random_prime(&mut self, nbits: usize) -> Integer {
        assert!(nbits >= 2, "random_prime needs at least 2 bits");
        loop {
            let mut cand = Integer::from(Integer::random_bits(nbits as u32, &mut self.state));
            cand.set_bit(nbits as u32 - 1, true); // force exact bit length
            cand.set_bit(0, true); // force odd
            let p = cand.next_prime();
            if p.significant_bits() == nbits as u32 {
                return p;
            }
        }
    }
}

impl Default for RandGen {
    fn default() -> Self {
        RandGen::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_with_seed() {
        let mut a = RandGen::with_seed(&Integer::from(42u64));
        let mut b = RandGen::with_seed(&Integer::from(42u64));
        let bound = Integer::from(1_000_000u64);
        for _ in 0..20 {
            assert_eq!(a.random_mpz(&bound), b.random_mpz(&bound));
        }
    }

    #[test]
    fn random_mpz_in_range() {
        let mut g = RandGen::with_seed(&Integer::from(7u64));
        let bound = Integer::from(1000u64);
        for _ in 0..100 {
            let r = g.random_mpz(&bound);
            assert!(r.cmp0().is_ge() && r < bound);
        }
    }

    #[test]
    fn random_prime_bits_and_primality() {
        let mut g = RandGen::with_seed(&Integer::from(123u64));
        for &bits in &[16usize, 64, 128] {
            let p = g.random_prime(bits);
            assert_eq!(p.significant_bits() as usize, bits);
            assert!(p.is_probably_prime(25) != rug::integer::IsPrime::No);
        }
    }
}
