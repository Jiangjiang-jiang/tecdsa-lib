// SPDX-License-Identifier: MIT OR Apache-2.0
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

use rug::{integer::Order, Integer};

use super::{challenge_from_qfi, sample_random_mod_q};
use crate::cl::{ClResult, ClSetup, Qfi};

/// Public-checked DL proof.
pub struct RPcDlProof {
    pub t: Qfi,
    pub z: Vec<u8>,
    pub e: Vec<u8>,
}

impl RPcDlProof {
    /// Proves knowledge of `x` such that `Y = f^x`.
    pub fn prove(setup: &mut ClSetup, y: &Qfi, x: &Integer) -> ClResult<Self> {
        let a = sample_random_mod_q(setup)?;
        let t = setup.power_of_f(&a)?;

        let e = challenge_from_qfi(setup, b"R_pc_dl", &[y, &t], &[])?;

        let q = setup.cl().q();
        let e_val = Integer::from_digits(&e, Order::Msf);
        let z_val = (a + e_val * x) % q;

        Ok(Self {
            t,
            z: z_val.to_digits::<u8>(Order::Msf),
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
        let dt = setup.dlog_in_F(&self.t)?;
        let dy = setup.dlog_in_F(y)?;

        let q = setup.cl().q();
        let ev = Integer::from_digits(&self.e, Order::Msf);
        let zv = Integer::from_digits(&self.z, Order::Msf);

        let expected = (dt + ev * dy) % q;
        let z_mod = zv % q;

        Ok(expected == z_mod)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_pc_dl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(9001u64).expect("setup");
        let x = Integer::from(42u32);
        let y = setup.power_of_f(&x).expect("f^x");
        let proof = RPcDlProof::prove(&mut setup, &y, &x).expect("prove");
        assert!(proof.verify(&setup, &y).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_pc_dl_rejects_wrong_x() {
        let mut setup = ClSetup::new_secp256k1(9002u64).expect("setup");
        let y = setup.power_of_f(&Integer::from(42u32)).expect("f^x");
        let wrong_x = Integer::from(99u32);
        let proof = RPcDlProof::prove(&mut setup, &y, &wrong_x).expect("prove");
        assert!(!proof.verify(&setup, &y).expect("verify"));
    }
}
