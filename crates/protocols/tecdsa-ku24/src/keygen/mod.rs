// SPDX-License-Identifier: MIT OR Apache-2.0
//! One-round honest-majority distributed key generation on top of PRSS.
//!
//! The paper explicitly leaves DKG out of scope (Section 1.2) and assumes the
//! parties already hold `(t + 1)`-out-of-`n` Shamir shares of one or more keys.
//! Since KU24 already sets up PRSS keys, the natural way to produce such shares
//! costs a single round and no extra machinery:
//!
//! 1. Each party derives `x_j <- F_rss.Rand` locally (Section 5).  By
//!    construction the `{x_j}` are a degree-`t` Shamir sharing of a value `x`
//!    that is pseudorandom given the adversary's view.
//! 2. Each party broadcasts `X_j = g^{x_j}`.
//! 3. Each party interpolates the `{X_j}` in the exponent, *checking* that all
//!    `n` points lie on a degree-`t` polynomial, and outputs `y = g^x`.
//!
//! With `n >= 2t + 1` the `t + 1` honest points already determine the sharing
//! polynomial, so step 3 catches any corrupted party that broadcasts a wrong
//! `X_j`; honest parties then abort.  This matches KU24's security-with-abort
//! model.
//!
//! Because presignatures are key-independent, this phase can be re-run for as
//! many keys as needed -- each with a distinct `key_id` -- without touching the
//! PRSS setup or any existing presignature.

pub mod machine;
pub mod msg;

pub use machine::Ku24KeygenMachine;
pub use msg::Ku24KeygenMsg;

/// PRSS stream identifier reserved for key generation.
///
/// Distinct from every stream used by presigning ([`crate::presign::streams`]),
/// and further separated by the per-key `key_id` passed as the PRSS session.
pub const STREAM_KEYGEN: u32 = 0;
