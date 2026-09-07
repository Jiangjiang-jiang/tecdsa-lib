// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_m_aff_dl` — MtA affine DL relation (with batch support).
//!
//! Proves knowledge of `(x, y, r)` such that
//!   `ct_out = x * ct_in + Enc(pk, y; r)`  (affine on ciphertexts)
//!   `Y = f^y`  (DL relation in F-subgroup).

use rug::{integer::Order, Integer};

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};
use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

/// MtA affine DL proof.
pub struct RMAffDlProof {
    t1: Qfi,
    t2: Qfi,
    s: Qfi,
    z1: Vec<u8>,
    z2: Vec<u8>,
    z3: Vec<u8>,
    e: Vec<u8>,
}

impl RMAffDlProof {
    /// Generates a MtA affine DL proof.
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct_in: &ClHsmqkCiphertext,
        ct_out: &ClHsmqkCiphertext,
        y_point: &Qfi,
        x: &Integer,
        y: &Integer,
        r: &Integer,
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;
        let a3 = sample_random_mod_q(setup)?;

        let pk_elt = pk.elt();
        let (ci1, ci2) = setup.ct_components(ct_in)?;

        // t1 = ci1^a3 * h^a1  (mirrors co1 = ci1^x * h^r_enc)
        let ci1_a3 = setup.exp(&ci1, &a3)?;
        let h_a1 = setup.power_of_h(&a1)?;
        let t1 = setup.compose(&ci1_a3, &h_a1)?;

        // t2 = pk^a1 * f^a2 * ci2^a3
        let pk_a1 = setup.pk_pow(pk, &a1)?;
        let f_a2 = setup.power_of_f(&a2)?;
        let ci2_a3 = setup.exp(&ci2, &a3)?;
        let tmp = setup.compose(&pk_a1, &f_a2)?;
        let t2 = setup.compose(&tmp, &ci2_a3)?;

        let s = setup.power_of_f(&a2)?;
        let (co1, co2) = setup.ct_components(ct_out)?;
        let e = challenge_from_qfi(
            setup,
            b"R_m_aff_dl",
            &[pk_elt, &ci1, &ci2, &co1, &co2, y_point, &t1, &t2, &s],
            &[],
        )?;

        let q = setup.cl().q();
        let z1 = response_unbounded(&a1, &e, r);
        let z2 = response_mod_q(&a2, &e, y, q);
        // z3 must be unbounded: used as exponent on H-subgroup
        // elements (ci1, ci2) whose order is unknown.
        let z3 = response_unbounded(&a3, &e, x);

        Ok(Self {
            t1,
            t2,
            s,
            z1,
            z2,
            z3,
            e,
        })
    }

    /// Verifies the MtA affine DL proof.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct_in: &ClHsmqkCiphertext,
        ct_out: &ClHsmqkCiphertext,
        y_point: &Qfi,
    ) -> ClResult<bool> {
        let pk_elt = pk.elt();
        let (ci1, ci2) = setup.ct_components(ct_in)?;
        let (co1, co2) = setup.ct_components(ct_out)?;

        let e_check = challenge_from_qfi(
            setup,
            b"R_m_aff_dl",
            &[
                pk_elt, &ci1, &ci2, &co1, &co2, y_point, &self.t1, &self.t2, &self.s,
            ],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let z1 = Integer::from_digits(&self.z1, Order::Msf);
        let z2 = Integer::from_digits(&self.z2, Order::Msf);
        let z3 = Integer::from_digits(&self.z3, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        // Check 1: h^z1 * ci1^z3 == t1 * co1^e
        let h_z1 = setup.power_of_h(&z1)?;
        let ci1_z3 = setup.exp(&ci1, &z3)?;
        let lhs1 = setup.compose(&h_z1, &ci1_z3)?;
        let co1_e = setup.exp(&co1, &e)?;
        let rhs1 = setup.compose(&self.t1, &co1_e)?;
        if lhs1 != rhs1 {
            return Ok(false);
        }

        // Check 2: pk^z1 * f^z2 * ci2^z3 == t2 * co2^e
        let pk_z1 = setup.pk_pow(pk, &z1)?;
        let f_z2 = setup.power_of_f(&z2)?;
        let ci2_z3 = setup.exp(&ci2, &z3)?;
        let tmp = setup.compose(&pk_z1, &f_z2)?;
        let lhs2 = setup.compose(&tmp, &ci2_z3)?;
        let co2_e = setup.exp(&co2, &e)?;
        let rhs2 = setup.compose(&self.t2, &co2_e)?;
        if lhs2 != rhs2 {
            return Ok(false);
        }

        // Check 3: f^z2 == s * Y^e  (scalar check via dlog_in_F)
        if !super::verify_f_check(setup, &self.z2, &self.s, &self.e, y_point)? {
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
    fn r_m_aff_dl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(8001u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = Integer::from(3u32);
        let y = Integer::from(7u32);
        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };
        let r_enc = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };

        let ct_in = setup
            .encrypt_with_r(&pk, &Integer::from(100u32), &r_base)
            .expect("enc_in");

        let q = k256::Secp256k1::order();
        let m_out = (&x * Integer::from(100u32) + &y) % &q;

        let r_out: Integer = Integer::from(&x * &r_base) + &r_enc;

        let ct_out = setup.encrypt_with_r(&pk, &m_out, &r_out).expect("enc_out");
        let y_point = setup.power_of_f(&Integer::from(7u32)).expect("f^y");

        let proof = RMAffDlProof::prove(&mut setup, &pk, &ct_in, &ct_out, &y_point, &x, &y, &r_enc)
            .expect("prove");
        assert!(proof
            .verify(&setup, &pk, &ct_in, &ct_out, &y_point)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_m_aff_dl_rejects_wrong_y() {
        let mut setup = ClSetup::new_secp256k1(8002u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = Integer::from(3u32);
        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };
        let r_enc = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };

        let ct_in = setup
            .encrypt_with_r(&pk, &Integer::from(100u32), &r_base)
            .expect("enc_in");

        let q = k256::Secp256k1::order();
        let m_out = (&x * Integer::from(100u32) + Integer::from(7u32)) % &q;

        let r_out: Integer = Integer::from(&x * &r_base) + &r_enc;

        let ct_out = setup.encrypt_with_r(&pk, &m_out, &r_out).expect("enc_out");
        let y_point = setup.power_of_f(&Integer::from(7u32)).expect("f^y");

        // Prove with wrong y.
        let wrong_y = Integer::from(99u32);
        let proof = RMAffDlProof::prove(
            &mut setup, &pk, &ct_in, &ct_out, &y_point, &x, &wrong_y, &r_enc,
        )
        .expect("prove");
        assert!(!proof
            .verify(&setup, &pk, &ct_in, &ct_out, &y_point)
            .expect("verify"));
    }
}
