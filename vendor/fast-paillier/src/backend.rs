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
//! [`Integer`] can no longer implement `serde::Serialize`/`Deserialize`
//! directly (doing so would violate the orphan rule now that it is a plain
//! re-export rather than a newtype), so it no longer picks up any serde impl
//! by default. Wire structs with an `Integer` field must opt into the
//! [`int_wire`] adapter explicitly, which reproduces this crate's original
//! compact `(magnitude_msf, is_negative)` encoding:
//!
//! ```rust
//! # use fast_paillier::backend::Integer;
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct Wire {
//!     #[serde(with = "fast_paillier::backend::int_wire")]
//!     n: Integer,
//! }
//! ```

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

/// `#[serde(with = "fast_paillier::backend::int_wire")]`-compatible compact
/// wire encoding for [`Integer`].
///
/// [`Integer`] is a plain re-export of `rug::Integer`: both it and
/// `serde::Serialize`/`Deserialize` are foreign to this crate, so the orphan
/// rule forbids implementing them directly (this is exactly why the old
/// newtype's `make_serde!` impl was removed). Fields must therefore opt in
/// via this module instead of deriving. It reproduces `make_serde!`'s
/// original wire format byte-for-byte: the tuple
/// `(magnitude_msf: Vec<u8>, is_negative: bool)`, i.e. big-endian
/// (most-significant-first) base-256 magnitude plus a sign flag.
#[cfg(feature = "serde")]
pub mod int_wire {
    use alloc::vec::Vec;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{BigIntExt, Integer, Sign};

    /// Serializes as `(magnitude_msf, is_negative)`.
    pub fn serialize<S: Serializer>(val: &Integer, serializer: S) -> Result<S::Ok, S::Error> {
        let (bytes, sign) = val.to_bytes_msf_signed();
        (bytes, sign == Sign::Negative).serialize(serializer)
    }

    /// Deserializes from `(magnitude_msf, is_negative)`.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Integer, D::Error> {
        let (bytes, negative) = <(Vec<u8>, bool)>::deserialize(deserializer)?;
        Ok(Integer::from_bytes_msf_signed(
            &bytes,
            if negative {
                Sign::Negative
            } else {
                Sign::NonNegative
            },
        ))
    }

    /// Adapter for `Vec<Integer>` fields:
    /// `#[serde(with = "fast_paillier::backend::int_wire::vec")]`.
    pub mod vec {
        use alloc::vec::Vec;

        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        use super::{BigIntExt, Integer, Sign};

        /// Serializes each element as `(magnitude_msf, is_negative)`.
        pub fn serialize<S: Serializer>(
            vals: &[Integer],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let wire: Vec<(Vec<u8>, bool)> = vals
                .iter()
                .map(|val| {
                    let (bytes, sign) = val.to_bytes_msf_signed();
                    (bytes, sign == Sign::Negative)
                })
                .collect();
            wire.serialize(serializer)
        }

        /// Deserializes each element from `(magnitude_msf, is_negative)`.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<Integer>, D::Error> {
            let wire = <Vec<(Vec<u8>, bool)>>::deserialize(deserializer)?;
            Ok(wire
                .into_iter()
                .map(|(bytes, negative)| {
                    Integer::from_bytes_msf_signed(
                        &bytes,
                        if negative {
                            Sign::Negative
                        } else {
                            Sign::NonNegative
                        },
                    )
                })
                .collect())
        }
    }

    #[cfg(test)]
    mod test {
        use serde::{Deserialize, Serialize};

        use super::Integer;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Wire {
            #[serde(with = "super")]
            x: Integer,
            #[serde(with = "super::vec")]
            v: alloc::vec::Vec<Integer>,
        }

        #[test]
        fn roundtrip() {
            let w = Wire {
                x: -Integer::from(0x1122_3344_5566u64),
                v: alloc::vec![
                    Integer::from(0),
                    Integer::from(1),
                    Integer::from(-1),
                    Integer::from(u128::MAX) * Integer::from(u128::MAX),
                ],
            };
            let bytes = serde_json::to_vec(&w).unwrap();
            let w2: Wire = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(w, w2);
        }
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
