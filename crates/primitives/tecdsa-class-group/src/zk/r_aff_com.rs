#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};
use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

pub struct RAffComProof {
    pub t1: Qfi,
    pub t2: Qfi,
    pub t3: Qfi,
    pub z1: Vec<u8>,
    pub z2: Vec<u8>,
    pub z3: Vec<u8>,
    pub z4: Vec<u8>,
    pub e: Vec<u8>,
}

impl RAffComProof {
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

        let pk_elt = pk.elt();
        let (ci1, ci2) = setup.ct_components(ct_in)?;

        let ci1_a3 = setup.exp_bytes(&ci1, &a3)?;
        let h_a1 = setup.power_of_h_bytes(&a1)?;
        let t1 = setup.compose(&ci1_a3, &h_a1)?;
        let pk_a1 = setup.pk_pow_bytes(pk, &a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let tmp = setup.compose(&pk_a1, &f_a2)?;
        let ci2_a3 = setup.exp_bytes(&ci2, &a3)?;
        let t2 = setup.compose(&tmp, &ci2_a3)?;
        let h_a4 = setup.power_of_h_bytes(&a4)?;
        let f_a3 = setup.power_of_f_bytes(&a3)?;
        let t3 = setup.compose(&h_a4, &f_a3)?;

        let (co1, co2) = setup.ct_components(ct_out)?;
        let e = challenge_from_qfi(
            setup,
            b"R_aff_com",
            &[pk_elt, &ci1, &ci2, &co1, &co2, commitment, &t1, &t2, &t3],
            &[],
        )?;

        let q_bytes = setup.q_bytes()?;
        let z1 = response_unbounded(&a1, &e, r1_bytes)?;
        let z2 = response_mod_q(&a2, &e, y_bytes, &q_bytes)?;
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

        if &setup.compose(
            &setup.multiexp_signed_bytes(
                &[&ci1, &co1],
                &[(false, self.z3.clone()), (true, self.e.clone())],
            )?,
            &setup.power_of_h_bytes(&self.z1)?,
        )? != &self.t1
        {
            return Ok(false);
        }

        if &setup.compose(
            &setup.pk_pow_bytes(pk, &self.z1)?,
            &setup.compose(
                &setup.power_of_f_bytes(&self.z2)?,
                &setup.multiexp_signed_bytes(
                    &[&ci2, &co2],
                    &[(false, self.z3.clone()), (true, self.e.clone())],
                )?,
            )?,
        )? != &self.t2
        {
            return Ok(false);
        }

        let h_z4 = setup.power_of_h_bytes(&self.z4)?;
        let f_z3 = setup.power_of_f_bytes(&self.z3)?;
        let lhs3 = setup.compose(&h_z4, &f_z3)?;
        let c_e = setup.exp_bytes(commitment, &self.e)?;
        let rhs3 = setup.compose(&self.t3, &c_e)?;
        if lhs3 != rhs3 {
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
    fn r_aff_com_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("6001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x_bytes = Integer::from(5u32).to_digits::<u8>(Order::Msf);
        let y_bytes = Integer::from(10u32).to_digits::<u8>(Order::Msf);

        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_base_dec = Integer::from_digits(&r_base, Order::Msf).to_string_radix(10);
        let ct_in = setup
            .encrypt_with_r(&pk, "100", &r_base_dec)
            .expect("enc_in");

        let r1 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        let q = Integer::from_str_radix(SECP256K1_ORDER, 10).unwrap();
        let x_val = Integer::from(5u32);
        let m_in = Integer::from(100u32);
        let y_val = Integer::from(10u32);
        let m_out = (Integer::from(&x_val * &m_in) + &y_val) % &q;
        let m_out_dec = m_out.to_string_radix(10);

        let r_base_val = Integer::from_digits(&r_base, Order::Msf);
        let r1_val = Integer::from_digits(&r1, Order::Msf);
        let r_out_val = Integer::from(&x_val * &r_base_val) + &r1_val;
        let r_out_dec = r_out_val.to_string_radix(10);

        let ct_out2 = setup
            .encrypt_with_r(&pk, &m_out_dec, &r_out_dec)
            .expect("enc_out2");

        let r2 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r2_dec = Integer::from_digits(&r2, Order::Msf).to_string_radix(10);
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

        let y_bytes = Integer::from(10u32).to_digits::<u8>(Order::Msf);
        let r1 = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_base = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_base_dec = Integer::from_digits(&r_base, Order::Msf).to_string_radix(10);

        let q = Integer::from_str_radix(SECP256K1_ORDER, 10).unwrap();
        let x_val = Integer::from(5u32);
        let m_in = Integer::from(100u32);
        let y_val = Integer::from(10u32);
        let m_out = (Integer::from(&x_val * &m_in) + &y_val) % &q;
        let m_out_dec = m_out.to_string_radix(10);

        let r_base_val = Integer::from_digits(&r_base, Order::Msf);
        let r1_val = Integer::from_digits(&r1, Order::Msf);
        let r_out = (Integer::from(&x_val * &r_base_val) + &r1_val).to_string_radix(10);

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
        let r2_dec = Integer::from_digits(&r2, Order::Msf).to_string_radix(10);
        let h_r2 = setup.power_of_h(&r2_dec).expect("h_r2");
        let f_x = setup.power_of_f("5").expect("f_x");
        let commitment = setup.compose(&h_r2, &f_x).expect("com");

        let wrong_x_bytes = Integer::from(7u32).to_digits::<u8>(Order::Msf);
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
