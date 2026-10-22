// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_com_kwlg` — commitment knowledge proof.
//!
//! Proves knowledge of `(m, r)` such that `C = h^r * g^m` (a Pedersen-style
//! commitment in the CL group), where `g` is either the message-subgroup
//! generator `f` or an arbitrary element like the CL public key `pk`.

use rug::{integer::Order, Integer};

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};
use crate::cl::{ClResult, ClSetup, Qfi};

/// Commitment-knowledge proof.
pub struct RComKwlgProof {
    /// Commitment: t = h^{a1} * g^{a2} (where g is f or pk).
    pub t: Qfi,
    /// Response for randomness: z1 = a1 + e * r (big-endian bytes).
    pub z1: Vec<u8>,
    /// Response for message: z2 = (a2 + e * m) mod q (big-endian bytes).
    pub z2: Vec<u8>,
    /// Fiat-Shamir challenge (big-endian bytes).
    pub e: Vec<u8>,
}

impl RComKwlgProof {
    /// Proves knowledge of `(m, r)` in commitment `C = h^r * f^m`.
    pub fn prove(
        setup: &mut ClSetup,
        commitment: &Qfi,
        m: &Integer,
        r: &Integer,
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        let h_a1 = setup.power_of_h(&a1)?;
        let f_a2 = setup.power_of_f(&a2)?;
        let t = setup.compose(&h_a1, &f_a2)?;

        let e = challenge_from_qfi(setup, b"R_com_kwlg", &[commitment, &t], &[])?;

        let z1 = response_unbounded(&a1, &e, r);
        let q = setup.cl().q();
        let z2 = response_mod_q(&a2, &e, m, q);

        Ok(Self { t, z1, z2, e })
    }

    /// Proves knowledge of `(m, r)` in commitment `C = h^r * g^m` where `g`
    /// is an arbitrary group element (e.g., the CL public key `pk`).
    ///
    /// Used by protocols where the Pedersen commitment uses a non-standard
    /// second base (e.g., Trout uses `Com(r, m) = h^r * pk^m`).
    ///
    /// Both responses are unbounded (over Z) because `g` may have unknown
    /// order in the class group.
    pub fn prove_with_base(
        setup: &mut ClSetup,
        commitment: &Qfi,
        g: &Qfi,
        m: &Integer,
        r: &Integer,
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random(setup)?;

        let h_a1 = setup.power_of_h(&a1)?;
        let g_a2 = setup.exp(g, &a2)?;
        let t = setup.compose(&h_a1, &g_a2)?;

        let e = challenge_from_qfi(setup, b"R_com_kwlg", &[commitment, &t], &[])?;

        let z1 = response_unbounded(&a1, &e, r);
        let z2 = response_unbounded(&a2, &e, m);

        Ok(Self { t, z1, z2, e })
    }

    /// Verifies the commitment-knowledge proof for `C = h^r * f^m`.
    pub fn verify(&self, setup: &ClSetup, commitment: &Qfi) -> ClResult<bool> {
        let e_check = challenge_from_qfi(setup, b"R_com_kwlg", &[commitment, &self.t], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check: h^z1 * f^z2 == t * C^e
        let z1 = Integer::from_digits(&self.z1, Order::Msf);
        let z2 = Integer::from_digits(&self.z2, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);
        let h_z1 = setup.power_of_h(&z1)?;
        let f_z2 = setup.power_of_f(&z2)?;
        let lhs = setup.compose(&h_z1, &f_z2)?;

        let c_e = setup.exp(commitment, &e)?;
        let rhs = setup.compose(&self.t, &c_e)?;

        if lhs != rhs {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verifies the commitment-knowledge proof for `C = h^r * g^m` where `g`
    /// is an arbitrary group element.
    ///
    /// Note: responses z1, z2 are unbounded (not reduced mod q) when using
    /// an arbitrary base `g` with unknown order.
    pub fn verify_with_base(&self, setup: &ClSetup, commitment: &Qfi, g: &Qfi) -> ClResult<bool> {
        let e_check = challenge_from_qfi(setup, b"R_com_kwlg", &[commitment, &self.t], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check: h^z1 * g^z2 == t * C^e
        let z1 = Integer::from_digits(&self.z1, Order::Msf);
        let z2 = Integer::from_digits(&self.z2, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);
        let h_z1 = setup.power_of_h(&z1)?;
        let g_z2 = setup.exp(g, &z2)?;
        let lhs = setup.compose(&h_z1, &g_z2)?;

        let c_e = setup.exp(commitment, &e)?;
        let rhs = setup.compose(&self.t, &c_e)?;

        if lhs != rhs {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    fn make_commitment(setup: &ClSetup, m: &Integer, r: &Integer) -> ClResult<Qfi> {
        let h_r = setup.power_of_h(r)?;
        let f_m = setup.power_of_f(m)?;
        setup.compose(&h_r, &f_m)
    }

    #[test]
    fn r_com_kwlg_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(5001u64).expect("setup");
        let r = {
            let (sk, _) = setup.keygen().expect("keygen");
            setup.sk_to_integer(&sk)
        };
        let m = Integer::from(42u32);
        let c = make_commitment(&setup, &m, &r).expect("commit");

        let proof = RComKwlgProof::prove(&mut setup, &c, &m, &r).expect("prove");
        assert!(proof.verify(&setup, &c).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_com_kwlg_rejects_wrong_message() {
        let mut setup = ClSetup::new_secp256k1(5002u64).expect("setup");
        let r = {
            let (sk, _) = setup.keygen().expect("keygen");
            setup.sk_to_integer(&sk)
        };
        let c = make_commitment(&setup, &Integer::from(42u32), &r).expect("commit");

        let wrong_m = Integer::from(99u32);
        let proof = RComKwlgProof::prove(&mut setup, &c, &wrong_m, &r).expect("prove");
        assert!(!proof.verify(&setup, &c).expect("verify"));
    }

    #[test]
    fn r_com_kwlg_with_pk_base_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(5003u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");
        let pk_elt = &pk.elt();

        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_integer(&sk2)
        };
        let m = Integer::from(42u32);

        // Com(r, m) = h^r * pk^m
        let h_r = setup.power_of_h(&r).expect("h_r");
        let pk_m = setup.exp(pk_elt, &m).expect("pk_m");
        let c = setup.compose(&h_r, &pk_m).expect("compose");

        let proof = RComKwlgProof::prove_with_base(&mut setup, &c, pk_elt, &m, &r)
            .expect("prove_with_base");
        assert!(proof.verify_with_base(&setup, &c, pk_elt).expect("verify"));
    }

    #[ignore = "redundant ZK negative test"]
    #[test]
    fn r_com_kwlg_with_pk_base_rejects_wrong_message() {
        let mut setup = ClSetup::new_secp256k1(5004u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");
        let pk_elt = &pk.elt();

        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_integer(&sk2)
        };

        let h_r = setup.power_of_h(&r).expect("h_r");
        let pk_m = setup.exp(pk_elt, &Integer::from(42u32)).expect("pk_m");
        let c = setup.compose(&h_r, &pk_m).expect("compose");

        // Prove with wrong message
        let wrong_m = Integer::from(99u32);
        let proof = RComKwlgProof::prove_with_base(&mut setup, &c, pk_elt, &wrong_m, &r)
            .expect("prove_with_base");
        assert!(!proof.verify_with_base(&setup, &c, pk_elt).expect("verify"));
    }
}
