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

use rug::{integer::Order, Integer};

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
        x: &Integer,
    ) -> ClResult<Self> {
        let alpha = sample_random(setup)?;

        let t1 = setup.exp(g, &alpha)?;
        let t2 = setup.exp(b, &alpha)?;

        let e = challenge_from_qfi(setup, b"R_ddh_cl", &[g, a, b, c, &t1, &t2], &[])?;

        let z = response_unbounded(&alpha, &e, x);

        Ok(Self { t1, t2, z, e })
    }

    /// Verifies the DDH proof.
    pub fn verify(&self, setup: &ClSetup, g: &Qfi, a: &Qfi, b: &Qfi, c: &Qfi) -> ClResult<bool> {
        let e_check =
            challenge_from_qfi(setup, b"R_ddh_cl", &[g, a, b, c, &self.t1, &self.t2], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        let z = Integer::from_digits(&self.z, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        // Check 1: g^z == t1 * A^e ⟺ g^z * A^{-e} == t1 (shared-squaring multi-exp).
        let lhs1 = setup.multiexp(&[g, a], &[z.clone(), -e.clone()])?;
        if lhs1 != self.t1 {
            return Ok(false);
        }

        // Check 2: B^z == t2 * C^e ⟺ B^z * C^{-e} == t2.
        let lhs2 = setup.multiexp(&[b, c], &[z, -e])?;
        if lhs2 != self.t2 {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_ddh_cl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(13001u64).expect("setup");

        let x = Integer::from(42u32);
        let g = setup.cl().h().clone();
        let a = setup.exp(&g, &x).expect("g^x");

        // Pick another base B = h^r.
        let r = {
            let (sk, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk)
        };
        let b = setup.exp(&g, &r).expect("h^r");
        let c = setup.exp(&b, &x).expect("B^x");

        let proof = RDdhClProof::prove(&mut setup, &g, &a, &b, &c, &x).expect("prove");
        assert!(proof.verify(&setup, &g, &a, &b, &c).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_ddh_cl_rejects_wrong_x() {
        let mut setup = ClSetup::new_secp256k1(13002u64).expect("setup");

        let x = Integer::from(42u32);
        let g = setup.cl().h().clone();
        let a = setup.exp(&g, &x).expect("g^x");

        let r = {
            let (sk, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk)
        };
        let b = setup.exp(&g, &r).expect("h^r");
        let c = setup.exp(&b, &x).expect("B^x");

        let wrong_x = Integer::from(99u32);
        let proof = RDdhClProof::prove(&mut setup, &g, &a, &b, &c, &wrong_x).expect("prove");
        assert!(!proof.verify(&setup, &g, &a, &b, &c).expect("verify"));
    }
}
