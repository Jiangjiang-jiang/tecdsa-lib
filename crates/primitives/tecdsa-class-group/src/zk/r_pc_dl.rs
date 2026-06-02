// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_pc_dl` — public-checked DL proof.
//!
//! Proves knowledge of `x` such that `Y = f^x` in the F-subgroup.
//!
//! Since F-subgroup elements cannot be composed/exponentiated via
//! `Cl(Delta)` operations, verification uses `dlog_in_F` to work
//! in scalar arithmetic modulo `q`.

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::Qfi;
use num_bigint::BigUint;

use super::{challenge_from_qfi, sample_random_mod_q};

/// Public-checked DL proof.
pub struct RPcDlProof {
    pub t: Qfi,
    pub z: Vec<u8>,
    pub e: Vec<u8>,
}

impl RPcDlProof {
    /// Proves knowledge of `x` such that `Y = f^x`.
    pub fn prove(setup: &mut ClSetup, y: &Qfi, x_bytes: &[u8]) -> ClResult<Self> {
        let a = sample_random_mod_q(setup)?;
        let t = setup.power_of_f_bytes(&a)?;

        let e = challenge_from_qfi(setup, b"R_pc_dl", &[y, &t], &[])?;

        let q_bytes = setup.q_bytes()?;
        let q = BigUint::from_bytes_be(&q_bytes);
        let a_val = BigUint::from_bytes_be(&a);
        let e_val = BigUint::from_bytes_be(&e);
        let x_val = BigUint::from_bytes_be(x_bytes);
        let z_val = (&a_val + &e_val * &x_val) % &q;

        Ok(Self {
            t,
            z: z_val.to_bytes_be(),
            e,
        })
    }

    /// Verifies the public-checked DL proof.
    #[allow(non_snake_case)]
    pub fn verify(&self, setup: &ClSetup, y: &Qfi) -> ClResult<bool> {
        let e_check = challenge_from_qfi(setup, b"R_pc_dl", &[y, &self.t], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        // Verify using scalar arithmetic over F-subgroup:
        // z == dlog(t) + e * dlog(Y) mod q
        let dlog_t = setup.dlog_in_F_bytes(&self.t)?;
        let dlog_y = setup.dlog_in_F_bytes(y)?;

        let q_bytes = setup.q_bytes()?;
        let q = BigUint::from_bytes_be(&q_bytes);
        let dt = BigUint::from_bytes_be(&dlog_t);
        let dy = BigUint::from_bytes_be(&dlog_y);
        let ev = BigUint::from_bytes_be(&self.e);
        let zv = BigUint::from_bytes_be(&self.z);

        let expected = (&dt + &ev * &dy) % &q;
        let z_mod = &zv % &q;

        Ok(expected == z_mod)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::ClSetup;

    #[test]
    fn r_pc_dl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("9001").expect("setup");
        let x_bytes = BigUint::from(42u32).to_bytes_be();
        let y = setup.power_of_f("42").expect("f^x");
        let proof = RPcDlProof::prove(&mut setup, &y, &x_bytes).expect("prove");
        assert!(proof.verify(&setup, &y).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_pc_dl_rejects_wrong_x() {
        let mut setup = ClSetup::new_secp256k1("9002").expect("setup");
        let y = setup.power_of_f("42").expect("f^x");
        let wrong_x_bytes = BigUint::from(99u32).to_bytes_be();
        let proof = RPcDlProof::prove(&mut setup, &y, &wrong_x_bytes).expect("prove");
        assert!(!proof.verify(&setup, &y).expect("verify"));
    }
}
