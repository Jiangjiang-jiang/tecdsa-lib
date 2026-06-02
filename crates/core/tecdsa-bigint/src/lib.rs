// SPDX-License-Identifier: MIT OR Apache-2.0
//! Big-integer facade for the `tecdsa` library.
//!
//! Provides a [`DynInt`] newtype over `num_bigint::BigUint` and a set of
//! number-theoretic utilities used across Paillier, CL, and JL primitives.

mod arith;
mod dyn_int;
mod prime;

pub use arith::{gcd, jacobi, tonelli_shanks};
pub use dyn_int::DynInt;
pub use prime::{generate_blum_prime, generate_safe_prime, is_safe_prime};
