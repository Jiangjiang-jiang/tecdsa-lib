// SPDX-License-Identifier: MIT OR Apache-2.0
//! Oblivious transfer and vector OLE primitives for threshold ECDSA.
//!
//! Provides:
//! - [`base_ot`] -- endemic 1-out-of-2 OT based on Diffie-Hellman key exchange
//! - [`soft_spoken`] -- OT extension (KOS/SoftSpokenOT with Fiat-Shamir check)
//! - [`rvole`] -- random vector OLE / multiplication from OT extension
//! - [`fzero`] -- zero-check sub-protocol (stub)
//!
//! The base OT is a standalone implementation of the classic DH-based
//! construction (endemic OT, secure against passive adversaries).
//!
//! The OT extension (`soft_spoken`) implements Fig. 10 of KOS
//! (<https://eprint.iacr.org/2015/546.pdf>) with the Fiat-Shamir consistency
//! check from `DKLs23`.  The multiplication module (`rvole`) wraps OTE to
//! realize Functionality 3.5 of `DKLs23` via Protocol 1 of `DKLs19`.

pub mod base_ot;
pub mod fzero;
pub mod mta;
pub mod rvole;
pub mod seed_state;
pub mod soft_spoken;
