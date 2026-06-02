// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_aff_com` — affine commitment relation proof.
//!
//! Proves that a ciphertext `ct_out` is an affine transformation of
//! `ct_in`: given `(pk, ct_in, ct_out, C)`, prover knows `(x, y, r1, r2)` such that
//!   `ct_out = x * ct_in + Enc(pk, y; r1)`  (homomorphic)
//!   `C = h^{r2} * f^x`  (commitment to x).

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::{ClHsmqkCiphertext, ClHsmqkPublicKey, Qfi};

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};

/// Affine-commitment relation proof.
pub struct RAffComProof {
    /// Commitment for Enc randomness.
    pub t1: Qfi,
    /// Commitment for affine message component.
    pub t2: Qfi,
    /// Commitment for commitment randomness.
    pub t3: Qfi,
    /// Response for Enc randomness (big-endian bytes).
    pub z1: Vec<u8>,
    /// Response for y (additive plaintext, big-endian bytes).
    pub z2: Vec<u8>,
    /// Response for x (multiplicative scalar, big-endian bytes).
    pub z3: Vec<u8>,
    /// Response for commitment randomness r2 (big-endian bytes).
    pub z4: Vec<u8>,
    pub e: Vec<u8>,
}

impl RAffComProof {
    /// Generates the affine-commitment proof.
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct_in: &ClHsmqkCiphertext,
        ct_out: &ClHsmqkCiphertext,
        commitment: &Qfi,
        x_bytes: &[u8],
        y_bytes: &[u8],
        r1_bytes: &[u8],
        r2_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;
        let a3 = sample_random_mod_q(setup)?;
        let a4 = sample_random(setup)?;

        let pk_elt = setup.pk_element(pk)?;
        let (ci1, ci2) = setup.ct_components(ct_in)?;

        // t1 = ci1^a3 * h^a1
        let ci1_a3 = setup.exp_bytes(&ci1, &a3)?;
        let h_a1 = setup.power_of_h_bytes(&a1)?;
        let t1 = setup.compose(&ci1_a3, &h_a1)?;
        // t2 = pk^a1 * f^a2 * ci2^a3
        let pk_a1 = setup.exp_bytes(&pk_elt, &a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let tmp = setup.compose(&pk_a1, &f_a2)?;
        let ci2_a3 = setup.exp_bytes(&ci2, &a3)?;
        let t2 = setup.compose(&tmp, &ci2_a3)?;
        // t3 = h^a4 * f^a3 (commitment to x)
        let h_a4 = setup.power_of_h_bytes(&a4)?;
        let f_a3 = setup.power_of_f_bytes(&a3)?;
        let t3 = setup.compose(&h_a4, &f_a3)?;

        let (co1, co2) = setup.ct_components(ct_out)?;
        let e = challenge_from_qfi(
            setup,
            b"R_aff_com",
            &[&pk_elt, &ci1, &ci2, &co1, &co2, commitment, &t1, &t2, &t3],
            &[],
        )?;

        let q_bytes = setup.q_bytes()?;
        let z1 = response_unbounded(&a1, &e, r1_bytes)?;
        let z2 = response_mod_q(&a2, &e, y_bytes, &q_bytes)?;
        // z3 must be unbounded: it is used as exponent on H-subgroup
        // elements (ci1, commitment) whose order is unknown.
        let z3 = response_unbounded(&a3, &e, x_bytes)?;
        let z4 = response_unbounded(&a4, &e, r2_bytes)?;

        Ok(Self {
            t1,
            t2,
            t3,
            z1,
            z2,
            z3,
            z4,
            e,
        })
    }

    /// Verifies the affine-commitment proof.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct_in: &ClHsmqkCiphertext,
        ct_out: &ClHsmqkCiphertext,
        commitment: &Qfi,
    ) -> ClResult<bool> {
        let pk_elt = setup.pk_element(pk)?;
        let (co1, co2) = setup.ct_components(ct_out)?;
        let (ci1, ci2) = setup.ct_components(ct_in)?;

        let e_check = challenge_from_qfi(
            setup,
            b"R_aff_com",
            &[
                &pk_elt, &ci1, &ci2, &co1, &co2, commitment, &self.t1, &self.t2, &self.t3,
            ],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check 1: ci1^z3 * h^z1 == t1 * co1^e
        let ci1_z3 = setup.exp_bytes(&ci1, &self.z3)?;
        let h_z1 = setup.power_of_h_bytes(&self.z1)?;
        let lhs1 = setup.compose(&ci1_z3, &h_z1)?;
        let co1_e = setup.exp_bytes(&co1, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &co1_e)?;
        if !lhs1.equal(setup.ctx(), &rhs1)? {
            return Ok(false);
        }

        // Check 2: pk^z1 * f^z2 * ci2^z3 == t2 * co2^e
        let pk_z1 = setup.exp_bytes(&pk_elt, &self.z1)?;
        let f_z2 = setup.power_of_f_bytes(&self.z2)?;
        let ci2_z3 = setup.exp_bytes(&ci2, &self.z3)?;
        let tmp1 = setup.compose(&pk_z1, &f_z2)?;
        let lhs2 = setup.compose(&tmp1, &ci2_z3)?;
        let co2_e = setup.exp_bytes(&co2, &self.e)?;
        let rhs2 = setup.compose(&self.t2, &co2_e)?;
        if !lhs2.equal(setup.ctx(), &rhs2)? {
            return Ok(false);
        }

        // Check 3: h^z4 * f^z3 == t3 * C^e
        let h_z4 = setup.power_of_h_bytes(&self.z4)?;
        let f_z3 = setup.power_of_f_bytes(&self.z3)?;
        let lhs3 = setup.compose(&h_z4, &f_z3)?;
        let c_e = setup.exp_bytes(commitment, &self.e)?;
        let rhs3 = setup.compose(&self.t3, &c_e)?;
        if !lhs3.equal(setup.ctx(), &rhs3)? {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::{ClSetup, SECP256K1_ORDER};
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn r_aff_com_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("6001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x_bytes = BigUint::from(5u32).to_bytes_be();
        let y_bytes = BigUint::from(10u32).to_bytes_be();

        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_base_dec = BigUint::from_bytes_be(&r_base).to_str_radix(10);
        let ct_in = setup
            .encrypt_with_r(&pk, "100", &r_base_dec)
            .expect("enc_in");

        let r1 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        let q = BigUint::from_str_radix(SECP256K1_ORDER, 10).unwrap();
        let x_val = BigUint::from(5u32);
        let m_in = BigUint::from(100u32);
        let y_val = BigUint::from(10u32);
        let m_out = (&x_val * &m_in + &y_val) % &q;
        let m_out_dec = m_out.to_str_radix(10);

        let r_base_val = BigUint::from_bytes_be(&r_base);
        let r1_val = BigUint::from_bytes_be(&r1);
        let r_out_val = &x_val * &r_base_val + &r1_val;
        let r_out_dec = r_out_val.to_str_radix(10);

        let ct_out2 = setup
            .encrypt_with_r(&pk, &m_out_dec, &r_out_dec)
            .expect("enc_out2");

        // Commitment C = h^r2 * f^x.
        let r2 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r2_dec = BigUint::from_bytes_be(&r2).to_str_radix(10);
        let h_r2 = setup.power_of_h(&r2_dec).expect("h_r2");
        let f_x = setup.power_of_f("5").expect("f_x");
        let commitment = setup.compose(&h_r2, &f_x).expect("com");

        let proof = RAffComProof::prove(
            &mut setup,
            &pk,
            &ct_in,
            &ct_out2,
            &commitment,
            &x_bytes,
            &y_bytes,
            &r1,
            &r2,
        )
        .expect("prove");
        assert!(proof
            .verify(&setup, &pk, &ct_in, &ct_out2, &commitment)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_aff_com_rejects_wrong_x() {
        let mut setup = ClSetup::new_secp256k1("6002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let y_bytes = BigUint::from(10u32).to_bytes_be();
        let r1 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_base_dec = BigUint::from_bytes_be(&r_base).to_str_radix(10);

        let q = BigUint::from_str_radix(SECP256K1_ORDER, 10).unwrap();
        let x_val = BigUint::from(5u32);
        let m_in = BigUint::from(100u32);
        let y_val = BigUint::from(10u32);
        let m_out = (&x_val * &m_in + &y_val) % &q;
        let m_out_dec = m_out.to_str_radix(10);

        let r_base_val = BigUint::from_bytes_be(&r_base);
        let r1_val = BigUint::from_bytes_be(&r1);
        let r_out = (&x_val * &r_base_val + &r1_val).to_str_radix(10);

        let ct_in = setup
            .encrypt_with_r(&pk, "100", &r_base_dec)
            .expect("enc_in");
        let ct_out = setup
            .encrypt_with_r(&pk, &m_out_dec, &r_out)
            .expect("enc_out");

        let r2 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r2_dec = BigUint::from_bytes_be(&r2).to_str_radix(10);
        let h_r2 = setup.power_of_h(&r2_dec).expect("h_r2");
        let f_x = setup.power_of_f("5").expect("f_x");
        let commitment = setup.compose(&h_r2, &f_x).expect("com");

        // Prove with wrong x.
        let wrong_x_bytes = BigUint::from(7u32).to_bytes_be();
        let proof = RAffComProof::prove(
            &mut setup,
            &pk,
            &ct_in,
            &ct_out,
            &commitment,
            &wrong_x_bytes,
            &y_bytes,
            &r1,
            &r2,
        )
        .expect("prove");
        assert!(!proof
            .verify(&setup, &pk, &ct_in, &ct_out, &commitment)
            .expect("verify"));
    }
}
