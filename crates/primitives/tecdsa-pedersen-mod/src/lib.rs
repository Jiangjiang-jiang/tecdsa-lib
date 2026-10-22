// SPDX-License-Identifier: MIT OR Apache-2.0
//! RSA-modulus Pedersen parameters and ZK proofs for the `tecdsa` library.
//!
//! Provides:
//! - [`PedersenModParams`] -- ring-Pedersen parameters `(N, s, t)` where `N = p*q`
//!   for safe primes `p, q`, and `s, t` are generators in `Z*_N`.
//! - [`PiPrm`] -- proof of ring-Pedersen parameter validity (CGGMP20 Figure 13).
//!
//! For the Paillier-Blum modulus proof (Pi_mod, CGGMP20 Figure 12) use
//! `tecdsa_paillier::zk::paillier_zk::paillier_blum_modulus`.

mod params;
pub mod zk;

pub use params::{PedersenModParams, PedersenModSecret};
pub use zk::PiPrm;
