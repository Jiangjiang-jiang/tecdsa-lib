// SPDX-License-Identifier: GPL-3.0-or-later
//! Class-group encryption and proofs for the `tecdsa` threshold ECDSA library.
//!
//! This crate wraps [`bicycl_glue`] to provide:
//!
//! - **CL-HSM encryption** ([`cl_enc`]): key generation, encryption, decryption,
//!   and homomorphic operations over class-group ciphertexts.
//! - **NIM** ([`nim`]): Non-Interactive Multiplication protocol allowing two
//!   parties to compute additive shares of a product `x * y mod q`.
//! - **`DDLog`** ([`ddlog`]): Discrete-log labeling in the class group.
//!
//! # License
//!
//! This crate is **GPL-3.0-or-later** due to the `bicycl-rs` dependency.
//! Do not depend on this crate from MIT/Apache-2.0 code.

pub mod batch;
pub mod cl;
pub mod class_group;
pub mod ddlog;
pub mod drg;
pub mod matrix;
pub mod mta;
pub mod mta_broadcast;
pub mod nim;
pub mod pvss;
pub mod pvss_share;
pub mod scaled_decrypt;
pub mod t_cl;
pub mod zk;

pub use cl::ClSetup;
pub use ddlog::DdLogLabel;
pub use mta_broadcast::{NimMtA, NimRole, ScaledDecryptMtA};
pub use nim::Nim;
pub use t_cl::{final_decrypt, partial_decrypt, PartialDecryption};
