// SPDX-License-Identifier: MIT OR Apache-2.0
//! "Non-interactive" online signing (`Pi_ECDSA` signing, Figure 2).
//!
//! Given an unused presignature `(r_i, o_{i,j}, k'_{i,j})` and a share `x_j` of
//! *any* key hosted by the network, party `P_j` computes
//!
//! ```text
//! s_j = k'_{i,j} * (h + r_i * x_j) + o_{i,j}
//! ```
//!
//! and sends `(r_i, s_j)` to the coordinator, which reconstructs
//! `s = interpolate_2t(0, [n], {s_j})`, normalizes it to low-`s` form and
//! verifies the signature against the public key.  This is a single message per
//! party with no dependency on other parties' messages, which is why the paper
//! calls signing non-interactive; the ~80 microseconds it costs is pure local
//! arithmetic.
//!
//! # Degree bookkeeping
//!
//! `k'_{i,j}` and `x_j` are degree-`t` shares, so their product has degree `2t`;
//! `o_{i,j}` is a degree-`2t` sharing of zero and randomizes the opened shares.
//! Reconstruction therefore needs `2t + 1 = n` shares -- **every** party must
//! contribute, unlike the presigning phase where the redundancy is used for
//! consistency checking.
//!
//! # Key independence
//!
//! Nothing in the presignature depends on `x_j`; the same presignature works
//! with any of the keys the network holds.  Each presignature must still be
//! used exactly once, which the (semi-honest) coordinator enforces.
//!
//! # Model note
//!
//! The paper's functionality routes the `s_j` to a semi-honest coordinator.  The
//! workspace's [`tecdsa_protocol::StateMachine`] abstraction has no coordinator,
//! so [`Ku25SignMachine`] broadcasts `(r, s_j)` and every party performs the
//! coordinator's reconstruction and verification locally.  This is equivalent:
//! the reconstruction only uses public data, and correctness is checked against
//! the public key.

pub mod machine;
pub mod msg;

use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
pub use machine::Ku25SignMachine;
pub use msg::Ku25SignMsg;
use tecdsa_curve::TecdsaCurve;

use crate::presign::Ku25Presignature;

/// Compute this party's partial signature `s_j = k'_j (h + r x_j) + o_j`.
#[must_use]
pub fn partial_signature<C>(
    presignature: &Ku25Presignature<C>,
    key_share: &C::Scalar,
    digest: &C::Scalar,
) -> C::Scalar
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
{
    presignature.k_inv_share * (*digest + presignature.r * *key_share) + presignature.zero_share
}
