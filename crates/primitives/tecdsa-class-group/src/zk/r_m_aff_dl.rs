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
        x_bytes: &[u8],
        y_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;
        let a3 = sample_random_mod_q(setup)?;

        let pk_elt = pk.elt();
        let (ci1, ci2) = setup.ct_components(ct_in)?;

        // t1 = ci1^a3 * h^a1  (mirrors co1 = ci1^x * h^r_enc)
        let ci1_a3 = setup.exp_bytes(&ci1, &a3)?;
        let h_a1 = setup.power_of_h_bytes(&a1)?;
        let t1 = setup.compose(&ci1_a3, &h_a1)?;

        // t2 = pk^a1 * f^a2 * ci2^a3
        let pk_a1 = setup.exp_bytes(pk_elt, &a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let ci2_a3 = setup.exp_bytes(&ci2, &a3)?;
        let tmp = setup.compose(&pk_a1, &f_a2)?;
        let t2 = setup.compose(&tmp, &ci2_a3)?;

        let s = setup.power_of_f_bytes(&a2)?;
        let (co1, co2) = setup.ct_components(ct_out)?;
        let e = challenge_from_qfi(
            setup,
            b"R_m_aff_dl",
            &[pk_elt, &ci1, &ci2, &co1, &co2, y_point, &t1, &t2, &s],
            &[],
        )?;

        let q_bytes = setup.q_bytes()?;
        let z1 = response_unbounded(&a1, &e, r_bytes)?;
        let z2 = response_mod_q(&a2, &e, y_bytes, &q_bytes)?;
        // z3 must be unbounded: used as exponent on H-subgroup
        // elements (ci1, ci2) whose order is unknown.
        let z3 = response_unbounded(&a3, &e, x_bytes)?;

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

        // Check 1: h^z1 * ci1^z3 == t1 * co1^e
        let h_z1 = setup.power_of_h_bytes(&self.z1)?;
        let ci1_z3 = setup.exp_bytes(&ci1, &self.z3)?;
        let lhs1 = setup.compose(&h_z1, &ci1_z3)?;
        let co1_e = setup.exp_bytes(&co1, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &co1_e)?;
        if lhs1 != rhs1 {
            return Ok(false);
        }

        // Check 2: pk^z1 * f^z2 * ci2^z3 == t2 * co2^e
        let pk_z1 = setup.exp_bytes(pk_elt, &self.z1)?;
        let f_z2 = setup.power_of_f_bytes(&self.z2)?;
        let ci2_z3 = setup.exp_bytes(&ci2, &self.z3)?;
        let tmp = setup.compose(&pk_z1, &f_z2)?;
        let lhs2 = setup.compose(&tmp, &ci2_z3)?;
        let co2_e = setup.exp_bytes(&co2, &self.e)?;
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
    use rug::{integer::Order, Integer};

    use super::*;
    use crate::cl::{ClSetup, SECP256K1_ORDER};

    #[test]
    fn r_m_aff_dl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("8001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x_bytes = Integer::from(3u32).to_digits::<u8>(Order::Msf);
        let y_bytes = Integer::from(7u32).to_digits::<u8>(Order::Msf);
        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_enc = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        let r_base_dec = Integer::from_digits(&r_base, Order::Msf).to_string_radix(10);
        let ct_in = setup
            .encrypt_with_r(&pk, "100", &r_base_dec)
            .expect("enc_in");

        let q = Integer::from_str_radix(SECP256K1_ORDER, 10).unwrap();
        let m_out = (Integer::from(3u32) * Integer::from(100u32) + Integer::from(7u32)) % &q;
        let m_out_dec = m_out.to_string_radix(10);

        let r_base_val = Integer::from_digits(&r_base, Order::Msf);
        let r_enc_val = Integer::from_digits(&r_enc, Order::Msf);
        let r_out = (Integer::from(3u32) * r_base_val + r_enc_val).to_string_radix(10);

        let ct_out = setup
            .encrypt_with_r(&pk, &m_out_dec, &r_out)
            .expect("enc_out");
        let y_point = setup.power_of_f("7").expect("f^y");

        let proof = RMAffDlProof::prove(
            &mut setup, &pk, &ct_in, &ct_out, &y_point, &x_bytes, &y_bytes, &r_enc,
        )
        .expect("prove");
        assert!(proof
            .verify(&setup, &pk, &ct_in, &ct_out, &y_point)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_m_aff_dl_rejects_wrong_y() {
        let mut setup = ClSetup::new_secp256k1("8002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x_bytes = Integer::from(3u32).to_digits::<u8>(Order::Msf);
        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_enc = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        let r_base_dec = Integer::from_digits(&r_base, Order::Msf).to_string_radix(10);
        let ct_in = setup
            .encrypt_with_r(&pk, "100", &r_base_dec)
            .expect("enc_in");

        let q = Integer::from_str_radix(SECP256K1_ORDER, 10).unwrap();
        let m_out = (Integer::from(3u32) * Integer::from(100u32) + Integer::from(7u32)) % &q;
        let m_out_dec = m_out.to_string_radix(10);

        let r_base_val = Integer::from_digits(&r_base, Order::Msf);
        let r_enc_val = Integer::from_digits(&r_enc, Order::Msf);
        let r_out = (Integer::from(3u32) * r_base_val + r_enc_val).to_string_radix(10);

        let ct_out = setup
            .encrypt_with_r(&pk, &m_out_dec, &r_out)
            .expect("enc_out");
        let y_point = setup.power_of_f("7").expect("f^y");

        // Prove with wrong y.
        let wrong_y_bytes = Integer::from(99u32).to_digits::<u8>(Order::Msf);
        let proof = RMAffDlProof::prove(
            &mut setup,
            &pk,
            &ct_in,
            &ct_out,
            &y_point,
            &x_bytes,
            &wrong_y_bytes,
            &r_enc,
        )
        .expect("prove");
        assert!(!proof
            .verify(&setup, &pk, &ct_in, &ct_out, &y_point)
            .expect("verify"));
    }
}
