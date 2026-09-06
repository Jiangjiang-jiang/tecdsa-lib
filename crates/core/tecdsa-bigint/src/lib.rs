// SPDX-License-Identifier: MIT OR Apache-2.0
//! Big-integer facade for the `tecdsa` library.
//!
//! Provides a set of number-theoretic utilities used across Paillier, CL, and JL primitives.

mod ext;
pub mod int_wire;
mod prime;

pub use ext::{BigIntExt, Sign};
pub use prime::{
    default_sieve_limit, gen_pair, generate_blum_prime, generate_safe_prime, is_safe_prime,
    random_below, small_odd_primes, SyncRng,
};
