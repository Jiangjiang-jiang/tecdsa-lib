use rand_core::CryptoRngCore;
use rug::Integer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenModParams {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub n: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub s: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub t: Integer,
}

#[derive(Debug, Clone)]
pub struct PedersenModSecret {
    pub p: Integer,
    pub q: Integer,
    pub lambda: Integer,
}

impl PedersenModParams {
    #[allow(clippy::similar_names, clippy::many_single_char_names)]
    pub fn generate(bits: u64, rng: &mut impl CryptoRngCore) -> (Self, PedersenModSecret) {
        use rug::rand::ThreadRandState;
        use tecdsa_bigint::{default_sieve_limit, gen_pair, small_odd_primes, SyncRng};

        let p;
        let q;
        {
            let mut sync_rng = SyncRng(&mut *rng);
            let rug_rng = &mut ThreadRandState::new_custom(&mut sync_rng);
            let primes = small_odd_primes(default_sieve_limit(bits));

            let (_, p_rug) = gen_pair(bits as u32 - 1, &Integer::from(2), 25, 15, &primes, rug_rng);
            let (_, q_rug) = gen_pair(bits as u32 - 1, &Integer::from(2), 25, 15, &primes, rug_rng);

            p = p_rug;
            q = q_rug;
        }

        let n = Integer::from(&p * &q);

        let p_minus_1 = Integer::from(&p - 1);
        let q_minus_1 = Integer::from(&q - 1);
        let phi_n = Integer::from(&p_minus_1 * &q_minus_1);

        let r = sample_coprime(rng, &n);
        let t = r.pow_mod(&Integer::from(2), &n).unwrap();

        let lambda = sample_in_range(rng, &phi_n);

        let s = t.clone().pow_mod(&lambda, &n).unwrap();

        let params = Self { n, s, t };
        let secret = PedersenModSecret { p, q, lambda };
        (params, secret)
    }

    #[must_use]
    pub fn modulus_bits(&self) -> u64 {
        self.n.significant_bits() as u64
    }

    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        if self.n.significant_bits() < 2 || self.n.is_even() {
            return false;
        }

        is_in_mult_group(&self.s, &self.n)
            && is_in_mult_group(&self.t, &self.n)
            && self.s != 1
            && self.t != 1
    }
}

fn is_in_mult_group(x: &Integer, n: &Integer) -> bool {
    let zero = Integer::from(0);
    if *x <= zero || *x >= *n {
        return false;
    }
    tecdsa_bigint::gcd(x, n) == 1
}

fn sample_coprime(rng: &mut impl CryptoRngCore, n: &Integer) -> Integer {
    use tecdsa_bigint::SyncRng;
    let mut sync_rng = SyncRng(rng);
    let rug_rng = &mut rug::rand::ThreadRandState::new_custom(&mut sync_rng);
    loop {
        let x = n.clone().random_below(rug_rng);
        if x > 1 && x.clone().gcd(n) == 1 {
            return x;
        }
    }
}

fn sample_in_range(rng: &mut impl CryptoRngCore, upper: &Integer) -> Integer {
    use tecdsa_bigint::SyncRng;
    let mut sync_rng = SyncRng(rng);
    let rug_rng = &mut rug::rand::ThreadRandState::new_custom(&mut sync_rng);
    loop {
        let x = upper.clone().random_below(rug_rng);
        if x > 0 {
            return x;
        }
    }
}
