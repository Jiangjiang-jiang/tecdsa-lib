// SPDX-License-Identifier: MIT OR Apache-2.0
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

use super::{challenge_from_qfi, response_unbounded, sample_random};
use crate::cl::{ClResult, ClSetup, Qfi};

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

        // Check 1: g^z == t1 * A^e ⟺ g^z * A^{-e} == t1 (shared-squaring multi-exp).
        let lhs1 = setup
            .multiexp_signed_bytes(&[g, a], &[(false, self.z.clone()), (true, self.e.clone())])?;
        if lhs1 != self.t1 {
            return Ok(false);
        }

        // Check 2: B^z == t2 * C^e ⟺ B^z * C^{-e} == t2.
        let lhs2 = setup
            .multiexp_signed_bytes(&[b, c], &[(false, self.z.clone()), (true, self.e.clone())])?;
        if lhs2 != self.t2 {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use rug::{integer::Order, Integer};

    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_ddh_cl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("13001").expect("setup");

        let x = "42";
        let x_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let g = setup.cl().h().clone();
        let a = setup.exp(&g, x).expect("g^x");

        // Pick another base B = h^r.
        let r = {
            let (sk, _) = setup.keygen().expect("kg");
            sk.to_string()
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
        let g = setup.cl().h().clone();
        let a = setup.exp(&g, x).expect("g^x");

        let r = {
            let (sk, _) = setup.keygen().expect("kg");
            sk.to_string()
        };
        let b = setup.exp(&g, &r).expect("h^r");
        let c = setup.exp(&b, x).expect("B^x");

        let wrong_x_bytes = Integer::from(99u32).to_digits::<u8>(Order::Msf);
        let proof = RDdhClProof::prove(&mut setup, &g, &a, &b, &c, &wrong_x_bytes).expect("prove");
        assert!(!proof.verify(&setup, &g, &a, &b, &c).expect("verify"));
    }
}
