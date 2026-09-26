// SPDX-License-Identifier: MIT OR Apache-2.0
//! Big-integer facade for the `tecdsa` library.
//!
//! Provides a set of number-theoretic utilities used across Paillier, CL, and JL primitives.

mod ext;
pub mod int_wire;
pub mod par;
mod prime;

pub use ext::{BigIntExt, Sign};
#[cfg(feature = "parallel")]
pub use prime::gen_pair_par;
pub use prime::{default_sieve_limit, gen_pair, small_odd_primes, SyncRng};
