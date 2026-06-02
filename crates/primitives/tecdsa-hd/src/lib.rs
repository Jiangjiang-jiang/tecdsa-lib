// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! HD-wallet key derivation (SLIP-10) for threshold ECDSA.
//!
//! Implements deterministic child key derivation compatible with
//! BIP-32/SLIP-10, allowing wallet vendors to derive per-account or
//! per-address key shares without running a new DKG.

mod slip10;

pub use slip10::{
    derive_child_public, derive_child_share, derive_master, ChainCode, DerivationIndex,
};
