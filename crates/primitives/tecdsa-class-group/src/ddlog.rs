// SPDX-License-Identifier: MIT OR Apache-2.0
//! `DDLog` — discrete-log labeling in the class group.
//!
//! The `DDLog` (or "coset labeling") maps an element of `Cl(Delta)` to a
//! scalar in `Z/q` by projecting onto the `F`-subgroup and computing
//! the discrete logarithm there.
//!
//! This module provides type definitions and basic operations.  The
//! full `DDLog` proof (`Pi_DDLog`) will be implemented in the ZK proofs
//! task (Task 17).

use rug::Integer;

use crate::cl::{ClResult, ClSetup, Qfi};

/// A `DDLog` label: a scalar in `Z/q` obtained by computing the discrete
/// logarithm of the `F`-component of a class-group element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdLogLabel {
    /// The label value (in `[0, q)`).
    value: Integer,
}

impl DdLogLabel {
    /// Creates a new `DDLog` label from an integer value.
    #[must_use]
    pub fn new(value: Integer) -> Self {
        Self { value }
    }

    /// Returns the label value.
    #[must_use]
    pub fn as_integer(&self) -> &Integer {
        &self.value
    }

    /// Converts the label to an owned `Integer`.
    #[must_use]
    pub fn to_integer(&self) -> Integer {
        self.value.clone()
    }

    /// Creates a label from an `Integer`.
    #[must_use]
    pub fn from_integer(v: &Integer) -> Self {
        Self { value: v.clone() }
    }

    /// Returns the zero label.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            value: Integer::new(),
        }
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
    let mut label_elt = setup.cl().to_cl_delta_k(element); // reduced π(z)
    setup.cl().from_cl_delta_k_to_cl_delta(&mut label_elt); // reduced lift back

    // Compute alpha = element * label_elt^{-1}
    label_elt.neg();
    let alpha = setup.compose(element, &label_elt)?;

    // Discrete log in F.
    let dlog = setup.dlog_in_F(&alpha)?;
    Ok(DdLogLabel::new(dlog))
}

/// Computes the `DDLog` label of `f^m` and verifies it equals `m`.
///
/// This is a self-test: for any `m` in `[0, q)`, `ddlog_label(f^m) = m`.
///
/// # Errors
///
/// Returns an error if the operations fail.
pub fn ddlog_verify_power_of_f(setup: &ClSetup, m: &Integer) -> ClResult<bool> {
    let fm = setup.power_of_f(m)?;
    let label = ddlog_label(setup, &fm)?;
    Ok(label.as_integer() == m)
}
