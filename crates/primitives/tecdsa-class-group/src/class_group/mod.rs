//! Clean-room Rust implementation of the **CL-HSM_qk** linearly-homomorphic
//! encryption scheme over class groups of imaginary quadratic fields.
//!
//! This crate is a drop-in replacement at the CL-encryption API level for an
//! existing implementation, while the big-integer and class-group layers are an
//! independent design. Everything here was derived from public academic papers
//! (see `README.md`); no GPL source was consulted.
//!
//! # Layers
//! * [`Mpz`] — arbitrary-precision integers (GMP via the LGPL `rug` crate).
//! * [`RandGen`] — seedable RNG.
//! * [`QFI`] / [`ClassGroup`] — binary quadratic forms and class-group arithmetic.
//! * [`CL_HSMqk`] — the encryption scheme itself.

#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

pub mod error;
pub mod hgcd;
// FFI to GMP's internal half-GCD. Opt-in via the `gmp-hgcd` feature
// (undocumented, version-fragile internal symbols), where its `mpn_hgcd2`-driven
// partial reduction ([`hgcd_gmp::partial_reduce_hgcd2`]) is faster than the
// word-batched Lehmer at the CL operand size and so backs NUCOMP/NUDUPL;
// without the feature the Lehmer reduction is used.
#[cfg(feature = "gmp-hgcd")]
pub mod hgcd_gmp;
pub mod mpz;
pub mod nt;
pub mod rand;

pub mod qfi;

pub use error::{ClassGroupError, Result};
pub use mpz::Mpz;
pub use qfi::{ClassGroup, QFI};
pub use rand::RandGen;
