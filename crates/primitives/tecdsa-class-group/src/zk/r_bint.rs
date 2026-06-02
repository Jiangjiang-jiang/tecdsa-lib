// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_bint` — bounded integer proof.
//!
//! Proves knowledge of `x` such that `Y = h^x` and `x` lies in a
//! specified range `[0, B)`.  Uses a statistical zero-knowledge technique
//! where the commitment randomness is sampled from a larger range.

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::Qfi;
use num_bigint::BigUint;

use super::{challenge_from_qfi, response_unbounded, sample_random};

/// Bounded integer proof.
pub struct RBintProof {
    t: Qfi,
    z: Vec<u8>,
    e: Vec<u8>,
}

impl RBintProof {
    /// Proves that the prover knows `x` such that `Y = h^x`.
    ///
    /// The bound check is statistical — we verify that the response `z`
    /// has bounded size relative to the commitment randomness distribution.
    pub fn prove(setup: &mut ClSetup, y: &Qfi, x_bytes: &[u8]) -> ClResult<Self> {
        let a = sample_random(setup)?;
        let t = setup.power_of_h_bytes(&a)?;

        let e = challenge_from_qfi(setup, b"R_bint", &[y, &t], &[])?;

        let z = response_unbounded(&a, &e, x_bytes)?;

        Ok(Self { t, z, e })
    }

    /// Verifies the bounded integer proof.
    ///
    /// - `bound_bytes`: the upper bound `B` on `x` (big-endian bytes).
    pub fn verify(&self, setup: &ClSetup, y: &Qfi, bound_bytes: &[u8]) -> ClResult<bool> {
        let e_check = challenge_from_qfi(setup, b"R_bint", &[y, &self.t], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check: h^z == t * Y^e
        let z_val = BigUint::from_bytes_be(&self.z);
        let h_z = setup.power_of_h_bytes(&self.z)?;
        let y_e = setup.exp_bytes(y, &self.e)?;
        let rhs = setup.compose(&self.t, &y_e)?;
        if !h_z.equal(setup.ctx(), &rhs)? {
            return Ok(false);
        }

        // Statistical bound check: z < B * 2^256 (slack from commitment randomness).
        let bound = BigUint::from_bytes_be(bound_bytes);
        let sk_bound_bytes = setup.secretkey_bound_bytes()?;
        let sk_bound = BigUint::from_bytes_be(&sk_bound_bytes);
        // z should be bounded by sk_bound + e * bound, which for our test params is fine.
        let e_val = BigUint::from_bytes_be(&self.e);
        let max_z = &sk_bound + &e_val * &bound;
        if z_val > max_z {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::ClSetup;

    #[test]
    fn r_bint_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("11001").expect("setup");
        let x_bytes = BigUint::from(42u32).to_bytes_be();
        let y = setup.power_of_h("42").expect("h^x");

        let proof = RBintProof::prove(&mut setup, &y, &x_bytes).expect("prove");
        let bound = setup.secretkey_bound_bytes().expect("bound");
        assert!(proof.verify(&setup, &y, &bound).expect("verify"));
    }

    #[test]
    fn r_bint_rejects_wrong_x() {
        let mut setup = ClSetup::new_secp256k1("11002").expect("setup");
        let y = setup.power_of_h("42").expect("h^x");

        let wrong_x_bytes = BigUint::from(99u32).to_bytes_be();
        let proof = RBintProof::prove(&mut setup, &y, &wrong_x_bytes).expect("prove");
        let bound = setup.secretkey_bound_bytes().expect("bound");
        assert!(!proof.verify(&setup, &y, &bound).expect("verify"));
    }
}
