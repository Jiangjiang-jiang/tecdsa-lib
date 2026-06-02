// SPDX-License-Identifier: MIT OR Apache-2.0
//! XAL23 key generation.
//!
//! In the XAL23 protocol, key generation produces:
//! 1. Feldman VSS shares of the ECDSA signing key x -> {x_i}
//! 2. A JL key pair per party for MtA operations
//!
//! This module provides two modes:
//! - `trusted_dealer_keygen` (in `key_share.rs`): single-shot trusted dealer (for testing).
//! - `Xal23KeygenMachine`: interactive 2-round DKG with Feldman VSS + JL keypair exchange.

pub mod machine;
pub mod msg;
pub mod rounds;

pub use machine::Xal23KeygenMachine;
pub use msg::Xal23KeygenMsg;
