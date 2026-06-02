// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_cl_dl` — CL-DL relation proof.
//!
//! Proves that a ciphertext encrypts the discrete log of a public QFI
//! point: given `(pk, ct, Y)`, prover knows `(x, r)` such that
//!   `ct = Enc(pk, x; r)`  and  `Y = f^x`.

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::{ClHsmqkCiphertext, ClHsmqkPublicKey, Qfi};

use super::{
    challenge_from_qfi, challenge_from_qfi_with_prefix, response_mod_q, response_unbounded,
    sample_random, sample_random_mod_q,
};

/// CL-DL relation proof.
pub struct RClDlProof {
    t1: Qfi,
    t2: Qfi,
    /// Commitment in F-subgroup: s = f^{a2}.
    s: Qfi,
    /// Response for randomness: u1 = a1 + e * r (big-endian bytes).
    u1: Vec<u8>,
    /// Response for plaintext: u2 = (a2 + e * x) mod q (big-endian bytes).
    u2: Vec<u8>,
    e: Vec<u8>,
}

impl RClDlProof {
    /// Generates a CL-DL proof.
    ///
    /// - `Y = f^x` (the public F-element).
    /// - `ct = Enc(pk, x; r)`.
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        y: &Qfi,
        x_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        // t1 = h^a1 (commitment to randomness)
        let t1 = setup.power_of_h_bytes(&a1)?;
        // t2 = pk^a1 * f^a2 (commitment to message)
        let pk_elt = setup.pk_element(pk)?;
        let pk_a1 = setup.exp_bytes(&pk_elt, &a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let t2 = setup.compose(&pk_a1, &f_a2)?;
        // s = f^a2 (commitment in F-subgroup)
        let s = setup.power_of_f_bytes(&a2)?;

        let (c1, c2) = setup.ct_components(ct)?;
        let e = challenge_from_qfi(
            setup,
            b"R_cl_dl",
            &[&pk_elt, &c1, &c2, y, &t1, &t2, &s],
            &[],
        )?;

        let u1 = response_unbounded(&a1, &e, r_bytes)?;
        let q_bytes = setup.q_bytes()?;
        let u2 = response_mod_q(&a2, &e, x_bytes, &q_bytes)?;

        Ok(Self {
            t1,
            t2,
            s,
            u1,
            u2,
            e,
        })
    }

    /// Verifies the CL-DL proof.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        y: &Qfi,
    ) -> ClResult<bool> {
        let pk_elt = setup.pk_element(pk)?;
        let (c1, c2) = setup.ct_components(ct)?;

        let e_check = challenge_from_qfi(
            setup,
            b"R_cl_dl",
            &[&pk_elt, &c1, &c2, y, &self.t1, &self.t2, &self.s],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check 1: h^u1 == t1 * c1^e
        let lhs1 = setup.power_of_h_bytes(&self.u1)?;
        let c1_e = setup.exp_bytes(&c1, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &c1_e)?;
        if !lhs1.equal(setup.ctx(), &rhs1)? {
            return Ok(false);
        }

        // Check 2: pk^u1 * f^u2 == t2 * c2^e
        let pk_u1 = setup.exp_bytes(&pk_elt, &self.u1)?;
        let f_u2 = setup.power_of_f_bytes(&self.u2)?;
        let lhs2 = setup.compose(&pk_u1, &f_u2)?;
        let c2_e = setup.exp_bytes(&c2, &self.e)?;
        let rhs2 = setup.compose(&self.t2, &c2_e)?;
        if !lhs2.equal(setup.ctx(), &rhs2)? {
            return Ok(false);
        }

        // Check 3: f^u2 == s * Y^e  (scalar check via dlog_in_F)
        if !super::verify_f_check(setup, &self.u2, &self.s, &self.e, y)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Like [`prove`](Self::prove), but binds the Fiat-Shamir challenge to an
    /// opaque context prefix (e.g. session/party/round bytes).
    pub fn prove_with_prefix(
        prefix: &[u8],
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        y: &Qfi,
        x_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        let t1 = setup.power_of_h_bytes(&a1)?;
        let pk_elt = setup.pk_element(pk)?;
        let pk_a1 = setup.exp_bytes(&pk_elt, &a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let t2 = setup.compose(&pk_a1, &f_a2)?;
        let s = setup.power_of_f_bytes(&a2)?;

        let (c1, c2) = setup.ct_components(ct)?;
        let e = challenge_from_qfi_with_prefix(
            setup,
            prefix,
            b"R_cl_dl",
            &[&pk_elt, &c1, &c2, y, &t1, &t2, &s],
            &[],
        )?;

        let u1 = response_unbounded(&a1, &e, r_bytes)?;
        let q_bytes = setup.q_bytes()?;
        let u2 = response_mod_q(&a2, &e, x_bytes, &q_bytes)?;

        Ok(Self {
            t1,
            t2,
            s,
            u1,
            u2,
            e,
        })
    }

    /// Like [`verify`](Self::verify), but uses the same context prefix that was
    /// used during proving.
    pub fn verify_with_prefix(
        &self,
        prefix: &[u8],
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        y: &Qfi,
    ) -> ClResult<bool> {
        let pk_elt = setup.pk_element(pk)?;
        let (c1, c2) = setup.ct_components(ct)?;

        let e_check = challenge_from_qfi_with_prefix(
            setup,
            prefix,
            b"R_cl_dl",
            &[&pk_elt, &c1, &c2, y, &self.t1, &self.t2, &self.s],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let lhs1 = setup.power_of_h_bytes(&self.u1)?;
        let c1_e = setup.exp_bytes(&c1, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &c1_e)?;
        if !lhs1.equal(setup.ctx(), &rhs1)? {
            return Ok(false);
        }

        let pk_u1 = setup.exp_bytes(&pk_elt, &self.u1)?;
        let f_u2 = setup.power_of_f_bytes(&self.u2)?;
        let lhs2 = setup.compose(&pk_u1, &f_u2)?;
        let c2_e = setup.exp_bytes(&c2, &self.e)?;
        let rhs2 = setup.compose(&self.t2, &c2_e)?;
        if !lhs2.equal(setup.ctx(), &rhs2)? {
            return Ok(false);
        }

        if !super::verify_f_check(setup, &self.u2, &self.s, &self.e, y)? {
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
    fn r_cl_dl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("3001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = "77";
        let x_bytes = BigUint::from(77u32).to_bytes_be();
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let r_dec = BigUint::from_bytes_be(&r).to_str_radix(10);
        let ct = setup.encrypt_with_r(&pk, x, &r_dec).expect("encrypt");
        let y = setup.power_of_f(x).expect("f^x");

        let proof = RClDlProof::prove(&mut setup, &pk, &ct, &y, &x_bytes, &r).expect("prove");
        assert!(proof.verify(&setup, &pk, &ct, &y).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_cl_dl_rejects_wrong_x() {
        let mut setup = ClSetup::new_secp256k1("3002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = "77";
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let r_dec = BigUint::from_bytes_be(&r).to_str_radix(10);
        let ct = setup.encrypt_with_r(&pk, x, &r_dec).expect("encrypt");
        let y = setup.power_of_f(x).expect("f^x");

        // Prove with wrong x.
        let wrong_x_bytes = BigUint::from(99u32).to_bytes_be();
        let proof = RClDlProof::prove(&mut setup, &pk, &ct, &y, &wrong_x_bytes, &r).expect("prove");
        assert!(!proof.verify(&setup, &pk, &ct, &y).expect("verify"));
    }

    #[test]
    fn r_cl_dl_with_prefix_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("3003").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = "77";
        let x_bytes = BigUint::from(77u32).to_bytes_be();
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let r_dec = BigUint::from_bytes_be(&r).to_str_radix(10);
        let ct = setup.encrypt_with_r(&pk, x, &r_dec).expect("encrypt");
        let y = setup.power_of_f(x).expect("f^x");

        let prefix = b"session-1::party-2::round-3";
        let proof = RClDlProof::prove_with_prefix(prefix, &mut setup, &pk, &ct, &y, &x_bytes, &r)
            .expect("prove");
        assert!(proof
            .verify_with_prefix(prefix, &setup, &pk, &ct, &y)
            .expect("verify"));
    }

    #[ignore = "redundant ZK negative test"]
    #[test]
    fn r_cl_dl_with_prefix_rejects_wrong_prefix() {
        let mut setup = ClSetup::new_secp256k1("3004").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = "77";
        let x_bytes = BigUint::from(77u32).to_bytes_be();
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let r_dec = BigUint::from_bytes_be(&r).to_str_radix(10);
        let ct = setup.encrypt_with_r(&pk, x, &r_dec).expect("encrypt");
        let y = setup.power_of_f(x).expect("f^x");

        let proof =
            RClDlProof::prove_with_prefix(b"prefix-A", &mut setup, &pk, &ct, &y, &x_bytes, &r)
                .expect("prove");
        assert!(!proof
            .verify_with_prefix(b"prefix-B", &setup, &pk, &ct, &y)
            .expect("verify"));
    }
}
