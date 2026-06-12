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
use crate::cl::{ClResult, ClSetup, Qfi};

pub struct RComKwlgProof {
    pub t: Qfi,
    pub z1: Vec<u8>,
    pub z2: Vec<u8>,
    pub e: Vec<u8>,
}

impl RComKwlgProof {
    pub fn prove(
        setup: &mut ClSetup,
        commitment: &Qfi,
        m_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        let h_a1 = setup.power_of_h_bytes(&a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let t = setup.compose(&h_a1, &f_a2)?;

        let e = challenge_from_qfi(setup, b"R_com_kwlg", &[commitment, &t], &[])?;

        let z1 = response_unbounded(&a1, &e, r_bytes)?;
        let q_bytes = setup.q_bytes()?;
        let z2 = response_mod_q(&a2, &e, m_bytes, &q_bytes)?;

        Ok(Self { t, z1, z2, e })
    }

    pub fn prove_with_base(
        setup: &mut ClSetup,
        commitment: &Qfi,
        g: &Qfi,
        m_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random(setup)?;

        let h_a1 = setup.power_of_h_bytes(&a1)?;
        let g_a2 = setup.exp_bytes(g, &a2)?;
        let t = setup.compose(&h_a1, &g_a2)?;

        let e = challenge_from_qfi(setup, b"R_com_kwlg", &[commitment, &t], &[])?;

        let z1 = response_unbounded(&a1, &e, r_bytes)?;
        let z2 = response_unbounded(&a2, &e, m_bytes)?;

        Ok(Self { t, z1, z2, e })
    }

    pub fn verify(&self, setup: &ClSetup, commitment: &Qfi) -> ClResult<bool> {
        let e_check = challenge_from_qfi(setup, b"R_com_kwlg", &[commitment, &self.t], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        let h_z1 = setup.power_of_h_bytes(&self.z1)?;
        let f_z2 = setup.power_of_f_bytes(&self.z2)?;
        let lhs = setup.compose(&h_z1, &f_z2)?;

        let c_e = setup.exp_bytes(commitment, &self.e)?;
        let rhs = setup.compose(&self.t, &c_e)?;

        if lhs != rhs {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn verify_with_base(&self, setup: &ClSetup, commitment: &Qfi, g: &Qfi) -> ClResult<bool> {
        let e_check = challenge_from_qfi(setup, b"R_com_kwlg", &[commitment, &self.t], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        let h_z1 = setup.power_of_h_bytes(&self.z1)?;
        let g_z2 = setup.exp_bytes(g, &self.z2)?;
        let lhs = setup.compose(&h_z1, &g_z2)?;

        let c_e = setup.exp_bytes(commitment, &self.e)?;
        let rhs = setup.compose(&self.t, &c_e)?;

        if lhs != rhs {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use rug::{integer::Order, Integer};

    use super::*;
    use crate::cl::ClSetup;

    fn make_commitment(setup: &ClSetup, m: &str, r: &str) -> ClResult<Qfi> {
        let h_r = setup.power_of_h(r)?;
        let f_m = setup.power_of_f(m)?;
        setup.compose(&h_r, &f_m)
    }

    #[test]
    fn r_com_kwlg_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("5001").expect("setup");
        let r = {
            let (sk, _) = setup.keygen().expect("keygen");
            setup.sk_to_bytes(&sk).expect("sk_bytes")
        };
        let r_dec = Integer::from_digits(&r, Order::Msf).to_string_radix(10);
        let m_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let c = make_commitment(&setup, "42", &r_dec).expect("commit");

        let proof = RComKwlgProof::prove(&mut setup, &c, &m_bytes, &r).expect("prove");
        assert!(proof.verify(&setup, &c).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_com_kwlg_rejects_wrong_message() {
        let mut setup = ClSetup::new_secp256k1("5002").expect("setup");
        let r = {
            let (sk, _) = setup.keygen().expect("keygen");
            setup.sk_to_bytes(&sk).expect("sk_bytes")
        };
        let r_dec = Integer::from_digits(&r, Order::Msf).to_string_radix(10);
        let c = make_commitment(&setup, "42", &r_dec).expect("commit");

        let wrong_m_bytes = Integer::from(99u32).to_digits::<u8>(Order::Msf);
        let proof = RComKwlgProof::prove(&mut setup, &c, &wrong_m_bytes, &r).expect("prove");
        assert!(!proof.verify(&setup, &c).expect("verify"));
    }

    #[test]
    fn r_com_kwlg_with_pk_base_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("5003").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");
        let pk_elt = &pk.elt();

        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let r_dec = Integer::from_digits(&r, Order::Msf).to_string_radix(10);
        let m_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);

        let h_r = setup.power_of_h(&r_dec).expect("h_r");
        let pk_m = setup.exp(pk_elt, "42").expect("pk_m");
        let c = setup.compose(&h_r, &pk_m).expect("compose");

        let proof = RComKwlgProof::prove_with_base(&mut setup, &c, pk_elt, &m_bytes, &r)
            .expect("prove_with_base");
        assert!(proof.verify_with_base(&setup, &c, pk_elt).expect("verify"));
    }

    #[ignore = "redundant ZK negative test"]
    #[test]
    fn r_com_kwlg_with_pk_base_rejects_wrong_message() {
        let mut setup = ClSetup::new_secp256k1("5004").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");
        let pk_elt = &pk.elt();

        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let r_dec = Integer::from_digits(&r, Order::Msf).to_string_radix(10);

        let h_r = setup.power_of_h(&r_dec).expect("h_r");
        let pk_m = setup.exp(pk_elt, "42").expect("pk_m");
        let c = setup.compose(&h_r, &pk_m).expect("compose");

        let wrong_m_bytes = Integer::from(99u32).to_digits::<u8>(Order::Msf);
        let proof = RComKwlgProof::prove_with_base(&mut setup, &c, pk_elt, &wrong_m_bytes, &r)
            .expect("prove_with_base");
        assert!(!proof.verify_with_base(&setup, &c, pk_elt).expect("verify"));
    }
}
