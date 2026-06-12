use rand_core::CryptoRngCore;
use rug::{
    integer::IsPrime,
    rand::{MutRandState, ThreadRandGen},
    Complete, Integer,
};

#[must_use]
pub fn random_below(bound: &Integer, rng: &mut impl CryptoRngCore) -> Integer {
    let mut sync = SyncRng(rng);
    let mut state = rug::rand::ThreadRandState::new_custom(&mut sync);
    bound.random_below_ref(&mut state).complete()
}

#[must_use]
#[allow(clippy::module_name_repetitions)]
pub fn is_safe_prime(p: &Integer) -> bool {
    if p.is_probably_prime(25) == IsPrime::No {
        return false;
    }
    let sophie = Integer::from(p - 1) >> 1u32;
    sophie.is_probably_prime(25) != IsPrime::No
}

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

#[allow(clippy::module_name_repetitions)]
pub fn generate_safe_prime(bits: u64, rng: &mut impl CryptoRngCore) -> Integer {
    let mut sync_rng = SyncRng(&mut *rng);
    let rug_rng = &mut rug::rand::ThreadRandState::new_custom(&mut sync_rng);
    let primes = small_odd_primes(default_sieve_limit(bits));
    let (_, p) = gen_pair(bits as u32 - 1, &Integer::from(2), 25, 15, &primes, rug_rng);
    p
}

#[allow(clippy::module_name_repetitions)]
pub fn generate_blum_prime(bits: u64, rng: &mut impl CryptoRngCore) -> Integer {
    let p = generate_safe_prime(bits, rng);
    assert_eq!(p.mod_u(4), 3, "safe prime must be = 3 mod 4 for bits >= 3");
    p
}

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

fn random_odd(bits: u32, rng: &mut impl MutRandState) -> Integer {
    let mut x = Integer::from(Integer::random_bits(bits, rng));
    x.keep_bits_mut(bits);
    x.set_bit(bits - 1, true);
    x.set_bit(0, true);
    x
}

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
        let base = random_odd(seed_bits, rng);
        let mut sieve = vec![false; w];

        for &l in small_primes {
            let base_l = base.mod_u(l as u32) as u64;
            let a_l = a.mod_u(l as u32) as u64;
            let inv2 = l.div_ceil(2);

            let j0 = ((l - base_l) % l * inv2 % l) as usize;
            let mut idx = j0;
            while idx < w {
                sieve[idx] = true;
                idx += l as usize;
            }
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

        let pocklington = *a == 2;
        for j in 0..w {
            if sieve[j] {
                continue;
            }
            let r = Integer::from(&base + 2 * j as u64);
            if r.is_probably_prime(1) == IsPrime::No {
                continue;
            }
            let mut f = Integer::from(a * &r);
            f += Integer::ONE;
            let f_is_prime = if pocklington {
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
            if r.is_probably_prime(mr_rounds) != IsPrime::No {
                return (r, f);
            }
        }
    }
}

pub struct SyncRng<R: CryptoRngCore>(pub R);
impl<R: CryptoRngCore> ThreadRandGen for SyncRng<R> {
    fn r#gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}
