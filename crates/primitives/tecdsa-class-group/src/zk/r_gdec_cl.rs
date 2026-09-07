// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_gdec_cl` — generalized decryption proof.
//!
//! Proves that `D = c2 * (c1^{sk})^{-1}` is the correct generalized
//! decryption of ciphertext `(c1, c2)` under secret key `sk`, where
//! `pk = h^{sk}`.

use rug::{integer::Order, Integer};

use super::{challenge_from_qfi, response_unbounded, sample_random};
use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

/// Generalized decryption proof.
pub struct RGdecClProof {
    t1: Qfi,
    t2: Qfi,
    z: Vec<u8>,
    e: Vec<u8>,
}

impl RGdecClProof {
    /// Constructs from raw parts (for deserialization).
    pub fn from_parts(t1: Qfi, t2: Qfi, z: Vec<u8>, e: Vec<u8>) -> Self {
        Self { t1, t2, z, e }
    }

    /// Extracts raw parts (for serialization).
    pub fn to_parts(&self) -> (Qfi, Qfi, Vec<u8>, Vec<u8>) {
        (
            self.t1.clone(),
            self.t2.clone(),
            self.z.clone(),
            self.e.clone(),
        )
    }

    /// Proves correct generalized decryption.
    ///
    /// `dec_result` is the decrypted element `D = c2 * (c1^{sk})^{-1}`.
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        dec_result: &Qfi,
        sk: &Integer,
    ) -> ClResult<Self> {
        let a = sample_random(setup)?;

        let t1 = setup.power_of_h(&a)?;
        let (c1, _) = setup.ct_components(ct)?;
        let t2 = setup.exp(&c1, &a)?;

        let pk_elt = pk.elt();
        let e = challenge_from_qfi(
            setup,
            b"R_gdec_cl",
            &[pk_elt, &c1, dec_result, &t1, &t2],
            &[],
        )?;

        let z = response_unbounded(&a, &e, sk);

        Ok(Self { t1, t2, z, e })
    }

    /// Verifies the generalized decryption proof.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        dec_result: &Qfi,
    ) -> ClResult<bool> {
        let pk_elt = pk.elt();
        let (c1, c2) = setup.ct_components(ct)?;

        let e_check = challenge_from_qfi(
            setup,
            b"R_gdec_cl",
            &[pk_elt, &c1, dec_result, &self.t1, &self.t2],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let z = Integer::from_digits(&self.z, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        // Check 1: h^z == t1 * pk^e
        let h_z = setup.power_of_h(&z)?;
        let pk_e = setup.exp(pk_elt, &e)?;
        let rhs1 = setup.compose(&self.t1, &pk_e)?;
        if h_z != rhs1 {
            return Ok(false);
        }

        // Check 2: c1^z == t2 * (c2 * D^{-1})^e
        // Note: c1^{sk} = c2 * D^{-1}, so we check c1^z == t2 * (c2 * D^{-1})^e.
        let mut d_inv = dec_result.clone();
        d_inv.neg();
        let c2_d_inv = setup.compose(&c2, &d_inv)?;
        // c1^z == t2 * (c2*D^-1)^e ⟺ c1^z * (c2*D^-1)^{-e} == t2 (shared-squaring
        // multi-exp; both bases vary per proof).
        let lhs2 = setup.multiexp(&[&c1, &c2_d_inv], &[z, -e])?;
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
    fn r_gdec_cl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(12001u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let ct = setup
            .encrypt(&pk_raw, &Integer::from(42u32))
            .expect("encrypt");
        let (c1, c2) = setup.ct_components(&ct).expect("comp");
        let mut c1_sk = setup.exp(&c1, &sk).expect("c1^sk");
        c1_sk.neg();
        let dec_result = setup.compose(&c2, &c1_sk).expect("dec");

        let proof = RGdecClProof::prove(&mut setup, &pk_raw, &ct, &dec_result, &sk).expect("prove");
        assert!(proof
            .verify(&setup, &pk_raw, &ct, &dec_result)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_gdec_cl_rejects_wrong_sk() {
        let mut setup = ClSetup::new_secp256k1(12002u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let ct = setup
            .encrypt(&pk_raw, &Integer::from(42u32))
            .expect("encrypt");
        let (c1, c2) = setup.ct_components(&ct).expect("comp");
        let mut c1_sk = setup.exp(&c1, &sk).expect("c1^sk");
        c1_sk.neg();
        let dec_result = setup.compose(&c2, &c1_sk).expect("dec");

        let (sk2, _) = setup.keygen().expect("kg2");
        let wrong_sk = setup.sk_to_integer(&sk2);
        let proof =
            RGdecClProof::prove(&mut setup, &pk_raw, &ct, &dec_result, &wrong_sk).expect("prove");
        assert!(!proof
            .verify(&setup, &pk_raw, &ct, &dec_result)
            .expect("verify"));
    }
}
