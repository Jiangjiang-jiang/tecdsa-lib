//! Big integer backend.
//!
//! [`Integer`] is a plain re-export of [`rug::Integer`], so this crate shares a
//! single big-integer type with the rest of the workspace. The helper methods
//! that used to be inherent on a newtype now live on the [`BigIntExt`] extension
//! trait; import it to use them:
//!
//! ```rust
//! use fast_paillier::backend::BigIntExt;
//! ```
//!
//! Conversion helpers on that trait:
//!
//! - [`BigIntExt::to_bytes_lsf`]
//! - [`BigIntExt::to_bytes_msf`]
//! - [`BigIntExt::from_bytes_msf`]
//! - [`BigIntExt::to_str_radix`]
//!
//! Methods that would collide with an inherent `rug::Integer` method are
//! deliberately absent from the trait, since inherent methods take precedence
//! and a colliding trait method could never be called. Use rug's API for
//! `is_probably_prime`, `from_str_radix`, and the `random_*` family (the
//! [`rand_core`]-adapting variants are named `sample_*` here to avoid the clash).
//!
//! Note that the serde representation of [`Integer`] is now rug's own
//! (a `{radix, value}` radix-string struct), *not* the compact byte encoding
//! this crate used to define. Wire structs that care should use an explicit
//! `#[serde(with = ...)]` adapter.

pub mod rug;

/// Whether a number is prime. See [`rug::Integer::is_probably_prime`].
///
/// Re-exported from `rug` rather than defined locally, so that results of
/// `rug::Integer::is_probably_prime` can be compared directly. Note that rug
/// reports negative primes as prime (it tests `|n|`), unlike the guarded
/// wrapper this crate used to provide.
pub use ::rug::integer::IsPrime;
pub use rug::*;

/// Sign of a number, to distinguish positives and zero from negatives
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Sign {
    /// Positive or zero
    NonNegative,
    Negative,
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

#[cfg(test)]
mod test {
    use ::rug::Complete;

    use super::{BigIntExt, Integer};

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
            let x = (&n + delta).complete();
            assert!(!x.in_mult_group_of(&n));
            assert!(!x.abs_in_mult_group_of(&n));
            assert!(!(-x).abs_in_mult_group_of(&n));
        }
    }
}
