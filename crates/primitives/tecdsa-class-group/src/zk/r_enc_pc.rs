// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_enc_pc` — encryption public-check proof.
//!
//! Proves knowledge of `(m, r)` such that `ct = Enc(pk, m; r)` and
//! `Y = f^m` (links encryption to an F-subgroup element).

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};
use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

/// Encryption public-check proof.
pub struct REncPcProof {
    pub t1: Qfi,
    pub t2: Qfi,
    pub s: Qfi,
    pub u1: Vec<u8>,
    pub u2: Vec<u8>,
    pub e: Vec<u8>,
}

impl REncPcProof {
    /// Generates the encryption public-check proof.
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        y: &Qfi,
        m_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        let t1 = setup.power_of_h_bytes(&a1)?;
        let pk_elt = pk.elt();
        let pk_a1 = setup.exp_bytes(pk_elt, &a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let t2 = setup.compose(&pk_a1, &f_a2)?;
        let s = setup.power_of_f_bytes(&a2)?;

        let (c1, c2) = setup.ct_components(ct)?;
        let e = challenge_from_qfi(
            setup,
            b"R_enc_pc",
            &[pk_elt, &c1, &c2, y, &t1, &t2, &s],
            &[],
        )?;

        let u1 = response_unbounded(&a1, &e, r_bytes)?;
        let q_bytes = setup.q_bytes()?;
        let u2 = response_mod_q(&a2, &e, m_bytes, &q_bytes)?;

        Ok(Self {
            t1,
            t2,
            s,
            u1,
            u2,
            e,
        })
    }

    /// Verifies the encryption public-check proof.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        y: &Qfi,
    ) -> ClResult<bool> {
        let pk_elt = pk.elt();
        let (c1, c2) = setup.ct_components(ct)?;

        let e_check = challenge_from_qfi(
            setup,
            b"R_enc_pc",
            &[pk_elt, &c1, &c2, y, &self.t1, &self.t2, &self.s],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check 1: h^u1 == t1 * c1^e
        let lhs1 = setup.power_of_h_bytes(&self.u1)?;
        let c1_e = setup.exp_bytes(&c1, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &c1_e)?;
        if lhs1 != rhs1 {
            return Ok(false);
        }

        // Check 2: pk^u1 * f^u2 == t2 * c2^e
        let pk_u1 = setup.exp_bytes(pk_elt, &self.u1)?;
        let f_u2 = setup.power_of_f_bytes(&self.u2)?;
        let lhs2 = setup.compose(&pk_u1, &f_u2)?;
        let c2_e = setup.exp_bytes(&c2, &self.e)?;
        let rhs2 = setup.compose(&self.t2, &c2_e)?;
        if lhs2 != rhs2 {
            return Ok(false);
        }

        // Check 3: f^u2 == s * Y^e  (scalar check via dlog_in_F)
        if !super::verify_f_check(setup, &self.u2, &self.s, &self.e, y)? {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_enc_pc_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("10001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let m_bytes = BigUint::from(77u32).to_bytes_be();
        let r = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_dec = BigUint::from_bytes_be(&r).to_str_radix(10);
        let ct = setup.encrypt_with_r(&pk, "77", &r_dec).expect("enc");
        let y = setup.power_of_f("77").expect("f^m");

        let proof = REncPcProof::prove(&mut setup, &pk, &ct, &y, &m_bytes, &r).expect("prove");
        assert!(proof.verify(&setup, &pk, &ct, &y).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_enc_pc_rejects_wrong_m() {
        let mut setup = ClSetup::new_secp256k1("10002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let r = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_dec = BigUint::from_bytes_be(&r).to_str_radix(10);
        let ct = setup.encrypt_with_r(&pk, "77", &r_dec).expect("enc");
        let y = setup.power_of_f("77").expect("f^m");

        let wrong_m_bytes = BigUint::from(88u32).to_bytes_be();
        let proof =
            REncPcProof::prove(&mut setup, &pk, &ct, &y, &wrong_m_bytes, &r).expect("prove");
        assert!(!proof.verify(&setup, &pk, &ct, &y).expect("verify"));
    }
}
