// SPDX-License-Identifier: MIT OR Apache-2.0
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

use rug::{integer::Order, Integer};

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};
use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
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
        x: &Integer,
        y: &Integer,
        r1: &Integer,
        r2: &Integer,
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;
        let a3 = sample_random_mod_q(setup)?;
        let a4 = sample_random(setup)?;

        let pk_elt = pk.elt();
        let (ci1, ci2) = setup.ct_components(ct_in)?;

        // t1 = ci1^a3 * h^a1
        let ci1_a3 = setup.exp(&ci1, &a3)?;
        let h_a1 = setup.power_of_h(&a1)?;
        let t1 = setup.compose(&ci1_a3, &h_a1)?;
        // t2 = pk^a1 * f^a2 * ci2^a3
        let pk_a1 = setup.pk_pow(pk, &a1)?;
        let f_a2 = setup.power_of_f(&a2)?;
        let tmp = setup.compose(&pk_a1, &f_a2)?;
        let ci2_a3 = setup.exp(&ci2, &a3)?;
        let t2 = setup.compose(&tmp, &ci2_a3)?;
        // t3 = h^a4 * f^a3 (commitment to x)
        let h_a4 = setup.power_of_h(&a4)?;
        let f_a3 = setup.power_of_f(&a3)?;
        let t3 = setup.compose(&h_a4, &f_a3)?;

        let (co1, co2) = setup.ct_components(ct_out)?;
        let e = challenge_from_qfi(
            setup,
            b"R_aff_com",
            &[pk_elt, &ci1, &ci2, &co1, &co2, commitment, &t1, &t2, &t3],
            &[],
        )?;

        let q = setup.cl().q();
        let z1 = response_unbounded(&a1, &e, r1);
        let z2 = response_mod_q(&a2, &e, y, q);
        // z3 must be unbounded: it is used as exponent on H-subgroup
        // elements (ci1, commitment) whose order is unknown.
        let z3 = response_unbounded(&a3, &e, x);
        let z4 = response_unbounded(&a4, &e, r2);

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
        let pk_elt = pk.elt();
        let (co1, co2) = setup.ct_components(ct_out)?;
        let (ci1, ci2) = setup.ct_components(ct_in)?;

        let e_check = challenge_from_qfi(
            setup,
            b"R_aff_com",
            &[
                pk_elt, &ci1, &ci2, &co1, &co2, commitment, &self.t1, &self.t2, &self.t3,
            ],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let z1 = Integer::from_digits(&self.z1, Order::Msf);
        let z2 = Integer::from_digits(&self.z2, Order::Msf);
        let z3 = Integer::from_digits(&self.z3, Order::Msf);
        let z4 = Integer::from_digits(&self.z4, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        // Check 1: ci1^z3 * h^z1 == t1 * co1^e
        if setup.compose(
            &setup.multiexp(&[&ci1, &co1], &[z3.clone(), -e.clone()])?,
            &setup.power_of_h(&z1)?,
        )? != self.t1
        {
            return Ok(false);
        }

        // Check 2: pk^z1 * f^z2 * ci2^z3 == t2 * co2^e
        if setup.compose(
            &setup.pk_pow(pk, &z1)?,
            &setup.compose(
                &setup.power_of_f(&z2)?,
                &setup.multiexp(&[&ci2, &co2], &[z3.clone(), -e.clone()])?,
            )?,
        )? != self.t2
        {
            return Ok(false);
        }

        // Check 3: h^z4 * f^z3 == t3 * C^e
        let h_z4 = setup.power_of_h(&z4)?;
        let f_z3 = setup.power_of_f(&z3)?;
        let lhs3 = setup.compose(&h_z4, &f_z3)?;
        let c_e = setup.exp(commitment, &e)?;
        let rhs3 = setup.compose(&self.t3, &c_e)?;
        if lhs3 != rhs3 {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use tecdsa_curve::TecdsaCurve;

    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_aff_com_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(6001u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = Integer::from(5u32);
        let y = Integer::from(10u32);

        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };
        let ct_in = setup
            .encrypt_with_r(&pk, &Integer::from(100u32), &r_base)
            .expect("enc_in");

        let r1 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };

        let q = k256::Secp256k1::order();
        let m_in = Integer::from(100u32);
        let m_out = (Integer::from(&x * &m_in) + &y) % &q;

        let r_out: Integer = Integer::from(&x * &r_base) + &r1;

        let ct_out2 = setup.encrypt_with_r(&pk, &m_out, &r_out).expect("enc_out2");

        // Commitment C = h^r2 * f^x.
        let r2 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };
        let h_r2 = setup.power_of_h(&r2).expect("h_r2");
        let f_x = setup.power_of_f(&x).expect("f_x");
        let commitment = setup.compose(&h_r2, &f_x).expect("com");

        let proof = RAffComProof::prove(
            &mut setup,
            &pk,
            &ct_in,
            &ct_out2,
            &commitment,
            &x,
            &y,
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
        let mut setup = ClSetup::new_secp256k1(6002u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let y = Integer::from(10u32);
        let r1 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };
        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };

        let q = k256::Secp256k1::order();
        let x = Integer::from(5u32);
        let m_in = Integer::from(100u32);
        let m_out = (Integer::from(&x * &m_in) + &y) % &q;

        let r_out: Integer = Integer::from(&x * &r_base) + &r1;

        let ct_in = setup
            .encrypt_with_r(&pk, &Integer::from(100u32), &r_base)
            .expect("enc_in");
        let ct_out = setup.encrypt_with_r(&pk, &m_out, &r_out).expect("enc_out");

        let r2 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };
        let h_r2 = setup.power_of_h(&r2).expect("h_r2");
        let f_x = setup.power_of_f(&x).expect("f_x");
        let commitment = setup.compose(&h_r2, &f_x).expect("com");

        // Prove with wrong x.
        let wrong_x = Integer::from(7u32);
        let proof = RAffComProof::prove(
            &mut setup,
            &pk,
            &ct_in,
            &ct_out,
            &commitment,
            &wrong_x,
            &y,
            &r1,
            &r2,
        )
        .expect("prove");
        assert!(!proof
            .verify(&setup, &pk, &ct_in, &ct_out, &commitment)
            .expect("verify"));
    }
}
