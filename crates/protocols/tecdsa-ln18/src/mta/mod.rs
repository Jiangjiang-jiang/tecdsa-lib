// SPDX-License-Identifier: MIT OR Apache-2.0
//! Private multiplication ($\pi_\text{mult}^\text{priv}$) backends for LN18.
//!
//! The private multiplication takes $n$ parties' additive shares $(a_i, b_i)$
//! and outputs shares $c_i$ such that $\sum c_i = (\sum a_i)(\sum b_i) \bmod q$.
//!
//! Privacy is guaranteed but **not** correctness — correctness is enforced by
//! the $\mathcal{F}_\text{mult}$.mult protocol via checkDH.
//!
//! Two backends are planned:
//! - **Paillier** (section 6.2 of LN18): uses 2-party Paillier MtA for every pair.
//! - **OT** (section 6.3 of LN18): uses oblivious transfer. (Not yet implemented.)

#[cfg(feature = "mta-paillier")]
pub mod paillier;

#[cfg(feature = "mta-ot")]
pub mod ot;
