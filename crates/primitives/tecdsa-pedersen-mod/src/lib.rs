// SPDX-License-Identifier: MIT OR Apache-2.0
//! RSA-modulus Pedersen parameters and ZK proofs for the `tecdsa` library.
//!
//! Provides:
//! - [`PedersenModParams`] -- ring-Pedersen parameters `(N, s, t)` where `N = p*q`
//!   for safe primes `p, q`, and `s, t` are generators in `Z*_N`.
//! - [`PiPrm`] -- proof of ring-Pedersen parameter validity (CGGMP20 Figure 13).
//! - [`PiMod`] -- proof that `N` is a Paillier-Blum modulus (CGGMP20 Figure 12).

pub(crate) mod number_theory;
mod params;
pub mod zk;

pub use params::{PedersenModParams, PedersenModSecret};
pub use zk::{PiMod, PiPrm};
