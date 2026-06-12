use rug::{rand::RandState, Integer};

use super::mpz::Mpz;

#[derive(Clone)]
pub struct RandGen {
    state: RandState<'static>,
}

impl RandGen {
    pub fn new() -> Self {
        RandGen {
            state: RandState::new(),
        }
    }

    pub fn with_seed(seed: &Mpz) -> Self {
        let mut g = RandGen::new();
        g.set_seed(seed);
        g
    }

    pub fn set_seed(&mut self, seed: &Mpz) {
        self.state.seed(seed.inner());
    }

    pub fn random_mpz(&mut self, bound: &Mpz) -> Mpz {
        debug_assert!(bound.sgn() > 0, "random_mpz: bound must be positive");
        Mpz::from_inner(bound.inner().clone().random_below(&mut self.state))
    }

    pub fn random_bits(&mut self, nbits: usize) -> Mpz {
        Mpz::from_inner(Integer::from(Integer::random_bits(
            nbits as u32,
            &mut self.state,
        )))
    }

    pub fn random_prime(&mut self, nbits: usize) -> Mpz {
        assert!(nbits >= 2, "random_prime needs at least 2 bits");
        loop {
            let mut cand = Integer::from(Integer::random_bits(nbits as u32, &mut self.state));
            cand.set_bit(nbits as u32 - 1, true);
            cand.set_bit(0, true);
            let p = cand.next_prime();
            if p.significant_bits() == nbits as u32 {
                return Mpz::from_inner(p);
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
        let mut a = RandGen::with_seed(&Mpz::from(42u64));
        let mut b = RandGen::with_seed(&Mpz::from(42u64));
        let bound = Mpz::from(1_000_000u64);
        for _ in 0..20 {
            assert_eq!(a.random_mpz(&bound), b.random_mpz(&bound));
        }
    }

    #[test]
    fn random_mpz_in_range() {
        let mut g = RandGen::with_seed(&Mpz::from(7u64));
        let bound = Mpz::from(1000u64);
        for _ in 0..100 {
            let r = g.random_mpz(&bound);
            assert!(r.sgn() >= 0 && r < bound);
        }
    }

    #[test]
    fn random_prime_bits_and_primality() {
        let mut g = RandGen::with_seed(&Mpz::from(123u64));
        for &bits in &[16usize, 64, 128] {
            let p = g.random_prime(bits);
            assert_eq!(p.nbits(), bits);
            assert!(p.is_probab_prime(25));
        }
    }
}
