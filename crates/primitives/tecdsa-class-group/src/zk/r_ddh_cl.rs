// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_ddh_cl` — DDH over class groups.
//!
//! Proves that a DDH tuple `(g, A, B, C)` is valid: prover knows `x`
//! such that `A = g^x` and `C = B^x`.

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::Qfi;

use super::{challenge_from_qfi, response_unbounded, sample_random};

/// DDH proof over class groups.
pub struct RDdhClProof {
    t1: Qfi,
    t2: Qfi,
    z: Vec<u8>,
    e: Vec<u8>,
}

impl RDdhClProof {
    /// Proves a DDH relation: `A = g^x` and `C = B^x`.
    pub fn prove(
        setup: &mut ClSetup,
        g: &Qfi,
        a: &Qfi,
        b: &Qfi,
        c: &Qfi,
        x_bytes: &[u8],
    ) -> ClResult<Self> {
        let alpha = sample_random(setup)?;

        let t1 = setup.exp_bytes(g, &alpha)?;
        let t2 = setup.exp_bytes(b, &alpha)?;

        let e = challenge_from_qfi(setup, b"R_ddh_cl", &[g, a, b, c, &t1, &t2], &[])?;

        let z = response_unbounded(&alpha, &e, x_bytes)?;

        Ok(Self { t1, t2, z, e })
    }

    /// Verifies the DDH proof.
    pub fn verify(&self, setup: &ClSetup, g: &Qfi, a: &Qfi, b: &Qfi, c: &Qfi) -> ClResult<bool> {
        let e_check =
            challenge_from_qfi(setup, b"R_ddh_cl", &[g, a, b, c, &self.t1, &self.t2], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check 1: g^z == t1 * A^e
        let g_z = setup.exp_bytes(g, &self.z)?;
        let a_e = setup.exp_bytes(a, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &a_e)?;
        if !g_z.equal(setup.ctx(), &rhs1)? {
            return Ok(false);
        }

        // Check 2: B^z == t2 * C^e
        let b_z = setup.exp_bytes(b, &self.z)?;
        let c_e = setup.exp_bytes(c, &self.e)?;
        let rhs2 = setup.compose(&self.t2, &c_e)?;
        if !b_z.equal(setup.ctx(), &rhs2)? {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::ClSetup;
    use num_bigint::BigUint;

    #[test]
    fn r_ddh_cl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("13001").expect("setup");

        let x = "42";
        let x_bytes = BigUint::from(42u32).to_bytes_be();
        let g = setup.h().expect("h");
        let a = setup.exp(&g, x).expect("g^x");

        // Pick another base B = h^r.
        let r = {
            let (sk, _) = setup.keygen().expect("kg");
            setup.sk_to_decimal(&sk).expect("dec")
        };
        let b = setup.exp(&g, &r).expect("h^r");
        let c = setup.exp(&b, x).expect("B^x");

        let proof = RDdhClProof::prove(&mut setup, &g, &a, &b, &c, &x_bytes).expect("prove");
        assert!(proof.verify(&setup, &g, &a, &b, &c).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_ddh_cl_rejects_wrong_x() {
        let mut setup = ClSetup::new_secp256k1("13002").expect("setup");

        let x = "42";
        let g = setup.h().expect("h");
        let a = setup.exp(&g, x).expect("g^x");

        let r = {
            let (sk, _) = setup.keygen().expect("kg");
            setup.sk_to_decimal(&sk).expect("dec")
        };
        let b = setup.exp(&g, &r).expect("h^r");
        let c = setup.exp(&b, x).expect("B^x");

        let wrong_x_bytes = BigUint::from(99u32).to_bytes_be();
        let proof = RDdhClProof::prove(&mut setup, &g, &a, &b, &c, &wrong_x_bytes).expect("prove");
        assert!(!proof.verify(&setup, &g, &a, &b, &c).expect("verify"));
    }
}
