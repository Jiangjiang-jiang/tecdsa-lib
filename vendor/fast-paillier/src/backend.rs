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
//! [`int_wire`] adapter explicitly. That adapter is a re-export of
//! [`tecdsa_bigint::int_wire`], the workspace's single compact
//! `(sign, magnitude)` encoding:
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


/// `#[serde(with = "fast_paillier::backend::int_wire")]`-compatible compact
/// wire encoding for [`Integer`].
///
/// [`Integer`] is a plain re-export of `rug::Integer`: both it and
/// `serde::Serialize`/`Deserialize` are foreign to this crate, so the orphan
/// rule forbids implementing them directly (this is exactly why the old
/// newtype's `make_serde!` impl was removed). Fields must therefore opt in
/// via this module instead of deriving.
///
/// Re-exported from `tecdsa_bigint` so the workspace has exactly one compact
/// integer encoding rather than two byte-compatible copies of it.
#[cfg(feature = "serde")]
pub use tecdsa_bigint::int_wire;

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
