//! Abstract big integer backend. This module makes no guarantees of
//! applicability, all methods are considered internal, except for conversion
//! functions:
//!
//! - [`Integer::to_bytes_lsf`]
//! - [`Integer::to_bytes_msf`]
//! - [`Integer::from_bytes_msf`]
//! - [`Integer::to_str_radix`]
//! - [`Integer::from_str_radix`]
//! - [`num_bigint::Integer::to_num_bigint`]
//! - [`num_bigint::Integer::from_num_bigint`]
//! - [`rug::Integer::to_rug`]
//! - [`rug::Integer::from_rug`]
//!
//! Likewise, the serde serialization format is also well-defined and stable,
//! even compatible with older versions of this library.
//!
//! To select a backend, use a feature flag:
//!
//! - `backend-num-bigint` (default) - use [`num-bigit`](https://docs.rs/num-bigint)
//! - `backend-rug` - use [`rug`](https://docs.rs/rug)
//!
//! When both features are enabled at once, num-bigint is used

pub(crate) mod macro_defs;

pub mod rug;

pub use rug::*;

/// Whether a number is prime. See [`Integer::is_probably_prime`] method
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IsPrime {
    No,
    Probably,
    Yes,
}

/// Sign of a number, to distinguish positives and zero from negatives
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Sign {
    /// Positive or zero
    NonNegative,
    Negative,
}

impl Integer {
    /// Checks that `self` is in Z<super>*</super><sub>n</sub>
    #[inline(always)]
    pub fn in_mult_group_of(&self, n: &Self) -> bool {
        self.cmp0().is_gt() && self < n && self.gcd_ref(n).is_one()
    }

    /// Checks that `abs(self)` is in Z<super>*</super><sub>n</sub>
    #[inline(always)]
    pub fn abs_in_mult_group_of(self: &Integer, n: &Integer) -> bool {
        self.cmp_abs(n).is_lt() && self.gcd_ref(n).is_one()
    }

    /// Samples `x` in Z*_n
    pub fn sample_in_mult_group_of(rng: &mut impl rand_core::RngCore, n: &Self) -> Self {
        let mut x = Integer::zero();
        loop {
            x.assign_random_below(n, rng);
            if x.in_mult_group_of(n) {
                return x;
            }
        }
    }

    /// Samples `x` such that abs(x) is in `Z*_n`
    pub fn sample_pm_in_mult_group_of(rng: &mut impl rand_core::RngCore, n: &Self) -> Self {
        let mut x = Integer::zero();
        let mut sign_buf = [0u8; 1];
        loop {
            x.assign_random_below(n, rng);
            rng.fill_bytes(&mut sign_buf);
            if sign_buf[0] & 1 == 1 {
                x = -x;
            }
            if x.abs_in_mult_group_of(n) {
                return x;
            }
        }
    }

    /// Generates a random safe prime
    pub fn generate_safe_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Self {
        // Sieve bound grows with size: small primes barely need sieving, while large ones
        // benefit from removing far more composite candidates up front (tuned by benchmark).
        let sieve_limit = if bits <= 512 {
            50_000
        } else if bits <= 1024 {
            200_000
        } else {
            500_000
        };
        sieve_generate_safe_primes(rng, bits, sieve_limit)
    }
}

/// Generate a random safe prime using a windowed double sieve.
///
/// Generates a Sophie Germain prime `q` of `bits - 1` bits and returns the safe
/// prime `p = 2q + 1` of `bits` bits.
///
/// Rather than testing random candidates one at a time, this draws a single
/// random odd base and sieves a whole window of candidates `q = base + 2j`
/// against every odd prime below `sieve_limit`, ruling out in one pass any
/// position where either `q` or `2q + 1` is divisible by a small prime. Survivors
/// are first cheaply filtered with a single Miller-Rabin round; `p = 2q + 1` is
/// then checked with one base-2 Fermat test which, by Pocklington's criterion
/// (`q` prime and `q > sqrt(p)`), *proves* `p` prime, so the full confidence
/// rounds are spent only on `q`. This minimises the big-integer primality checks
/// per safe prime found.
///
/// A larger `sieve_limit` removes more composite candidates up front at the cost
/// of a bigger sieve; `50_000` (used by [`generate_safe_prime`]) works well for
/// the bit lengths used in practice.
pub fn sieve_generate_safe_primes(
    rng: &mut impl rand_core::RngCore,
    bits: u32,
    sieve_limit: usize,
) -> Integer {
    use crate::backend::IsPrime;

    /// Width (in bits) of the candidate window scanned per random base.
    const WINDOW_BITS: u32 = 15;
    /// Cheap pre-filter: one Miller-Rabin round rejects almost all composites.
    const FILTER_ROUNDS: u32 = 1;
    /// Final confidence for the accepted Sophie Germain prime `q` (25 as in `mpz_nextprime`).
    const CONFIRM_ROUNDS: u32 = 25;

    let window: usize = 1 << WINDOW_BITS;
    let seed_bits = bits - 1;
    let small_primes = small_odd_primes(sieve_limit);

    loop {
        // Random odd base; the window holds candidates q = base + 2*j, j in [0, window).
        let mut base = Integer::zero();
        base.assign_random_bits(seed_bits, rng);
        base.set_bit(seed_bits - 1, true);
        base |= 1u32;

        // `true` marks a candidate position ruled out by the small-prime sieve.
        let mut ruled_out = alloc::vec![false; window];

        for &l in &small_primes {
            let base_l = u64::from(base.mod_u(l as u32));
            let inv2 = (l + 1) / 2; // 2^-1 mod l, for odd l

            // Kill positions where q = base + 2j == 0 (mod l).
            let j0 = ((l - base_l) % l * inv2 % l) as usize;
            let mut idx = j0;
            while idx < window {
                ruled_out[idx] = true;
                idx += l as usize;
            }

            // Kill positions where 2q + 1 == 0 (mod l): 4j == -(2*base + 1) (mod l).
            let c = (2 * base_l + 1) % l;
            let jf = ((l - c) % l * inv_mod(4 % l, l) % l) as usize;
            let mut idx = jf;
            while idx < window {
                ruled_out[idx] = true;
                idx += l as usize;
            }
        }

        for j in 0..window {
            if ruled_out[j] {
                continue;
            }
            let q = &base + 2 * (j as u64);
            // Cheap filter: one Miller-Rabin round rejects almost all composite `q`
            // before we pay for the full confirmation or touch `p`.
            if q.is_probably_prime(FILTER_ROUNDS, rng) == IsPrime::No {
                continue;
            }
            let mut p = q.clone();
            p <<= 1;
            p += 1; // p = 2q + 1
                    // Pocklington: `q = (p-1)/2` is a (probable) prime with `q > sqrt(p)`, and
                    // `gcd(2^2 - 1, p) = gcd(3, p) = 1` (3 is in the sieve), so a single base-2
                    // Fermat test is a primality *proof* for `p` given `q` is prime.
            if p.mod_u(3) == 0 {
                continue; // 3 | p => p composite (defensive; the sieve already drops these)
            }
            let p_minus_1 = &p - 1i32;
            if Integer::from(2u32).pow_mod(&p_minus_1, &p) != Some(Integer::one()) {
                continue;
            }
            // `p` is prime provided `q` is; spend the confidence rounds on `q` only.
            if q.is_probably_prime(CONFIRM_ROUNDS, rng) == IsPrime::No {
                continue;
            }
            return p;
        }
        // Window exhausted without success: draw a fresh random base.
    }
}

/// Odd primes below `limit` (sieve of Eratosthenes), used for the double sieve.
fn small_odd_primes(limit: usize) -> alloc::vec::Vec<u64> {
    let mut composite = alloc::vec![false; limit];
    let mut out = alloc::vec::Vec::new();
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

/// `x^(l-2) mod l == x^-1 mod l` (Fermat; `l` an odd prime, `0 < x < l`).
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

#[cfg(feature = "quickcheck")]
impl quickcheck::Arbitrary for Sign {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        if bool::arbitrary(g) {
            Sign::NonNegative
        } else {
            Sign::Negative
        }
    }
}

#[cfg(feature = "serde")]
mod serialize {
    use alloc::vec::Vec;
    use crate::backend::Sign;

    macro_rules! make_serde {
        ($integer:ty) => {
            impl serde::Serialize for $integer {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    let (bytes, sign) = self.to_bytes_msf_signed();
                    (bytes, (sign == Sign::Negative)).serialize(serializer)
                }
            }

            impl<'de> serde::Deserialize<'de> for $integer {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    let (bytes, sign) = <(Vec::<u8>, bool)>::deserialize(deserializer)?;
                    Ok(<$integer>::from_bytes_msf_signed(&bytes, if sign { Sign::Negative } else { Sign::NonNegative }))
                }
            }
        };
    }

    #[cfg(feature = "backend-num-bigint")]
    make_serde!(super::num_bigint::Integer);
    #[cfg(feature = "backend-rug")]
    make_serde!(super::rug::Integer);

    #[cfg(test)]
    mod test {
        #[cfg(feature = "backend-rug")]
        use alloc::{string::ToString, vec::Vec};

        use crate::backend::Integer;

        #[cfg(feature = "backend-rug")]
        #[test]
        fn rug_compatible_deser_json() {
            let mut rng = rand_dev::DevRng::new();
            let num = crate::backend::rug::Integer::random_bits(128, &mut rng).to_rug();
            let num_s = serde_json::to_vec(&num).unwrap();
            let num_: Integer = serde_json::from_slice(&num_s).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[cfg(feature = "backend-rug")]
        #[test]
        fn rug_compatible_ser_json() {
            let mut rng = rand_dev::DevRng::new();
            let num = Integer::random_bits(128, &mut rng);
            let num_s = serde_json::to_vec(&num).unwrap();
            let num_: rug::Integer = serde_json::from_slice(&num_s).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[cfg(feature = "backend-rug")]
        #[test]
        fn rug_compatible_deser_cbor() {
            let mut rng = rand_dev::DevRng::new();
            let num = crate::backend::rug::Integer::random_bits(128, &mut rng).to_rug();
            let mut buf = Vec::new();
            ciborium::into_writer(&num, &mut buf).unwrap();
            let num_: Integer = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[cfg(feature = "backend-rug")]
        #[test]
        fn rug_compatible_ser_cbor() {
            let mut rng = rand_dev::DevRng::new();
            let num = Integer::random_bits(128, &mut rng);
            let mut buf = Vec::new();
            ciborium::into_writer(&num, &mut buf).unwrap();
            let num_: rug::Integer = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[test]
        fn decode_odd_length() {
            let json = r#"{"radix": 16, "value": "12345"}"#;
            let num: Integer = serde_json::from_str(json).unwrap();
            assert_eq!(num, Integer::from(0x12345));
        }

        #[test]
        fn decode_negative() {
            let json = r#"{"radix": 16, "value": "-ffffff"}"#;
            let num: Integer = serde_json::from_str(json).unwrap();
            assert_eq!(num, Integer::from(-0xffffff));
        }
    }
}

#[cfg(test)]
mod test {
    use super::Integer;

    #[test]
    fn safe_prime_size() {
        let mut rng = rand_dev::DevRng::new();
        for size in [500, 512, 513, 514] {
            let mut prime = Integer::generate_safe_prime(&mut rng, size);
            // rug doesn't have bit length operations, so
            prime >>= size - 1;
            assert_eq!(prime, Integer::one());
        }
    }

    #[test]
    fn mult_group_check() {
        let n = Integer::from(10);

        let mult_group = [1, 3, 7, 9].map(Integer::from);
        let not_mult_group = [0, 2, 4, 5, 6, 8, 10].map(Integer::from);

        for x in mult_group {
            assert!(x.in_mult_group_of(&n));
            assert!(x.abs_in_mult_group_of(&n));
            assert!((-x).abs_in_mult_group_of(&n));
        }
        for x in not_mult_group {
            assert!(!x.in_mult_group_of(&n));
            assert!(!x.abs_in_mult_group_of(&n));
            assert!(!(-x).abs_in_mult_group_of(&n));
        }
        for delta in 0..15_u32 {
            let x = &n + delta;
            assert!(!x.in_mult_group_of(&n));
            assert!(!x.abs_in_mult_group_of(&n));
            assert!(!(-x).abs_in_mult_group_of(&n));
        }
    }
}
