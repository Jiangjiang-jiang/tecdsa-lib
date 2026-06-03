// SPDX-License-Identifier: MIT OR Apache-2.0
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::One;
use rand_core::CryptoRngCore;

use crate::DynInt;

/// Miller-Rabin primality test with `rounds` witness iterations.
///
/// Uses `rand::thread_rng()` internally for witness selection.
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

/// Returns `true` if `p` is a safe prime, i.e. both `p` and `(p-1)/2` are
/// (probably) prime.
#[must_use]
#[allow(clippy::module_name_repetitions)]
pub fn is_safe_prime(p: &DynInt) -> bool {
    let p_inner = p.inner();
    if !is_probably_prime(p_inner, 40) {
        return false;
    }
    let sophie = (p_inner - BigUint::one()) >> 1u32;
    is_probably_prime(&sophie, 40)
}

/// Generates a random safe prime of approximately `bits` bits using `rng`.
///
/// Generates a Sophie Germain prime `q` of `bits - 1` bits, then returns
/// `p = 2q + 1`.
#[allow(clippy::module_name_repetitions)]
pub fn generate_safe_prime(bits: u64, rng: &mut impl CryptoRngCore) -> DynInt {
    // Wrap the CryptoRngCore in a rand-compatible adapter so we can call
    // gen_biguint from RandBigInt.
    struct RandAdapter<'a, R: CryptoRngCore>(&'a mut R);

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

    let mut adapter = RandAdapter(rng);
    loop {
        // Generate a (bits-1)-bit odd candidate for q.
        let q = adapter.gen_biguint(bits - 1);
        let q = q | BigUint::one();
        if !is_probably_prime(&q, 40) {
            continue;
        }
        let p = (&q << 1u32) | BigUint::one();
        if is_probably_prime(&p, 40) {
            return DynInt::from(p);
        }
    }
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
pub fn generate_blum_prime(bits: u64, rng: &mut impl CryptoRngCore) -> DynInt {
    let p = generate_safe_prime(bits, rng);
    assert_eq!(
        p.inner() % BigUint::from(4u32),
        BigUint::from(3u32),
        "safe prime must be = 3 mod 4 for bits >= 3"
    );
    p
}
