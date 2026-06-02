// SPDX-License-Identifier: GPL-3.0-or-later
//! `DDLog` — discrete-log labeling in the class group.
//!
//! The `DDLog` (or "coset labeling") maps an element of `Cl(Delta)` to a
//! scalar in `Z/q` by projecting onto the `F`-subgroup and computing
//! the discrete logarithm there.
//!
//! This module provides type definitions and basic operations.  The
//! full `DDLog` proof (`Pi_DDLog`) will be implemented in the ZK proofs
//! task (Task 17).

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::Qfi;
use num_bigint::BigUint;

/// A `DDLog` label: a scalar in `Z/q` obtained by computing the discrete
/// logarithm of the `F`-component of a class-group element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdLogLabel {
    /// The label value as big-endian bytes (in `[0, q)`).
    value: Vec<u8>,
}

impl DdLogLabel {
    /// Creates a new `DDLog` label from big-endian bytes.
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    /// Returns the label value as big-endian bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Converts the label to a `BigUint`.
    #[must_use]
    pub fn to_biguint(&self) -> BigUint {
        BigUint::from_bytes_be(&self.value)
    }

    /// Creates a label from a `BigUint`.
    #[must_use]
    pub fn from_biguint(v: &BigUint) -> Self {
        Self {
            value: v.to_bytes_be(),
        }
    }

    /// Returns the zero label.
    #[must_use]
    pub fn zero() -> Self {
        Self { value: vec![0u8] }
    }
}

/// Computes the `DDLog` label of a QFI element.
///
/// Given an element `g` in `Cl(Delta)`, this:
/// 1. Maps to the maximal order via `to_maximal_order`.
/// 2. Lifts to isolate the `F`-component.
/// 3. Divides out the `F`-component to get an element purely in `F`.
/// 4. Computes `dlog_in_F` to get the scalar label.
///
/// # Errors
///
/// Returns an error if the BICYCL operations fail.
pub fn ddlog_label(setup: &ClSetup, element: &Qfi) -> ClResult<DdLogLabel> {
    let q_bytes = setup.q_bytes()?;
    #[allow(non_snake_case)]
    let dk_bytes = setup.DeltaK_bytes()?;
    let ctx = setup.ctx();

    // Clone the element by round-tripping through to_bytes/from_bytes.
    let elt_bytes = element.to_bytes(ctx)?;
    let mut label_elt = Qfi::from_bytes(ctx, &elt_bytes)?;

    // Map to maximal order and lift.
    label_elt.to_maximal_order_bytes(ctx, &q_bytes, &dk_bytes, true)?;
    label_elt.lift_bytes(ctx, &q_bytes)?;

    // Compute alpha = element * label_elt^{-1}
    let label_inv = label_elt.neg(ctx)?;
    let alpha = setup.compose(element, &label_inv)?;

    // Discrete log in F.
    #[allow(non_snake_case)]
    let dlog = setup.dlog_in_F_bytes(&alpha)?;
    Ok(DdLogLabel::new(dlog))
}

/// Computes the `DDLog` label of `f^m` and verifies it equals `m`.
///
/// This is a self-test: for any `m` in `[0, q)`, `ddlog_label(f^m) = m`.
///
/// # Errors
///
/// Returns an error if the operations fail.
pub fn ddlog_verify_power_of_f(setup: &ClSetup, m_bytes: &[u8]) -> ClResult<bool> {
    let fm = setup.power_of_f_bytes(m_bytes)?;
    let label = ddlog_label(setup, &fm)?;
    let label_val = BigUint::from_bytes_be(label.as_bytes());
    let m_val = BigUint::from_bytes_be(m_bytes);
    Ok(label_val == m_val)
}
