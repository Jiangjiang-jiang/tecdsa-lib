// SPDX-License-Identifier: MIT OR Apache-2.0
//! $\mathcal{F}_\text{mult}$ extended multiplication functionality building blocks.
//!
//! This module implements sub-operations of the $\mathcal{F}_\text{mult}$ ideal
//! functionality from the LN18 protocol:
//!
//! - **init** (Protocol 4.3): generates a distributed ElGamal keypair in 2 rounds
//! - **input** (Protocol 4.4): parties input additive shares via commit-then-prove
//!   ($\mathcal{F}_{com\text{-}zk}$ hybrid model), producing an EGexp encryption
//!   of the sum in 2 rounds
//! - **element-out** (Protocol 4.5): reveal $A = a \cdot G$ from encrypted $a$
//!   without revealing $a$ — 1 round (verification is local)
//! - **affine** (Protocol 4.6): compute $b = a \cdot x + y$ locally, no communication
//! - **mult** (Protocol 4.7): multiply two encrypted values and output additive
//!   shares of the product — 6 rounds (includes inlined $\mathcal{F}_\text{checkDH}$)
//! - **checkDH** (Section 7): securely check whether a tuple is DH — 3 rounds
//!   (used standalone or inlined into mult)
//!
//! These are internal building blocks called by KeyGen and Sign, not standalone
//! `StateMachine` implementations.

pub mod affine;
pub mod check_dh;
pub mod element_out;
pub mod init;
pub mod input;
pub mod mult;
