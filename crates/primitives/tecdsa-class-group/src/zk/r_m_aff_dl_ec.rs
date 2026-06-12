#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use elliptic_curve::group::GroupEncoding;
use k256::{ProjectivePoint, Scalar, Secp256k1};
use rug::{integer::Order, Integer};
use tecdsa_curve::conv;

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};
use crate::cl::{ClResult, ClSetup, Qfi};

pub struct RMAffDlEcProof {
    pub d_prime_1: Qfi,
    pub d_prime_2: Qfi,
    pub b0_bytes: Vec<u8>,
    pub r0_bytes: Vec<u8>,
    pub k_hat: Vec<u8>,
    pub beta_hat: Vec<u8>,
    pub e: Vec<u8>,
}

fn bytes_to_scalar(bytes: &[u8]) -> ClResult<Scalar> {
    Ok(conv::bytes_to_scalar::<Secp256k1>(bytes))
}

#[cfg(test)]
fn test_scalar(val: u64) -> Scalar {
    Scalar::from(val)
}

fn decode_point(bytes: &[u8]) -> ClResult<ProjectivePoint> {
    if bytes.len() != 33 {
        return Err(crate::cl::ClError::InvalidParam(format!(
            "expected 33-byte compressed point, got {} bytes",
            bytes.len()
        )));
    }
    let mut repr = <ProjectivePoint as GroupEncoding>::Repr::default();
    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(bytes);
    let opt = ProjectivePoint::from_bytes(&repr);
    if bool::from(opt.is_none()) {
        return Err(crate::cl::ClError::InvalidParam(
            "invalid EC point encoding".into(),
        ));
    }
    Ok(opt.unwrap())
}

fn point_to_bytes(p: &ProjectivePoint) -> Vec<u8> {
    p.to_bytes().to_vec()
}

fn negate_mod_q_bytes(val: &[u8], q: &[u8]) -> ClResult<Vec<u8>> {
    let val_big = Integer::from_digits(val, Order::Msf);
    let q_big = Integer::from_digits(q, Order::Msf);
    let val_mod = Integer::from(&val_big % &q_big);
    if val_mod == 0 {
        Ok(vec![0])
    } else {
        Ok(Integer::from(&q_big - &val_mod).to_digits::<u8>(Order::Msf))
    }
}

impl RMAffDlEcProof {
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        setup: &mut ClSetup,
        c1: &Qfi,
        c2: &Qfi,
        d1: &Qfi,
        d2: &Qfi,
        r_point: &ProjectivePoint,
        b_point: &ProjectivePoint,
        k_star_bytes: &[u8],
        beta_bytes: &[u8],
    ) -> ClResult<Self> {
        let q_bytes = setup.q_bytes()?;

        let beta0 = sample_random_mod_q(setup)?;
        let k0_star = sample_random(setup)?;

        let d_prime_1 = setup.exp_bytes(c1, &k0_star)?;

        let c2_k0 = setup.exp_bytes(c2, &k0_star)?;
        let neg_beta0 = negate_mod_q_bytes(&beta0, &q_bytes)?;
        let f_neg_beta0 = setup.power_of_f_bytes(&neg_beta0)?;
        let d_prime_2 = setup.compose(&c2_k0, &f_neg_beta0)?;

        let beta0_scalar = bytes_to_scalar(&beta0)?;
        let b0 = ProjectivePoint::GENERATOR * beta0_scalar;
        let b0_bytes = point_to_bytes(&b0);

        let k0_scalar = bytes_to_scalar(&k0_star)?;
        let r0 = ProjectivePoint::GENERATOR * k0_scalar;
        let r0_bytes = point_to_bytes(&r0);

        let r_pt_bytes = point_to_bytes(r_point);
        let b_pt_bytes = point_to_bytes(b_point);

        let e = challenge_from_qfi(
            setup,
            b"R_m_aff_dl_ec",
            &[c1, c2, d1, d2, &d_prime_1, &d_prime_2],
            &[&r_pt_bytes, &b_pt_bytes, &b0_bytes, &r0_bytes],
        )?;

        let k_hat = response_unbounded(&k0_star, &e, k_star_bytes)?;
        let beta_hat = response_mod_q(&beta0, &e, beta_bytes, &q_bytes)?;

        Ok(Self {
            d_prime_1,
            d_prime_2,
            b0_bytes,
            r0_bytes,
            k_hat,
            beta_hat,
            e,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        setup: &ClSetup,
        c1: &Qfi,
        c2: &Qfi,
        d1: &Qfi,
        d2: &Qfi,
        r_point: &ProjectivePoint,
        b_point: &ProjectivePoint,
    ) -> ClResult<bool> {
        let b0 = decode_point(&self.b0_bytes)?;
        let r0 = decode_point(&self.r0_bytes)?;

        let r_pt_bytes = point_to_bytes(r_point);
        let b_pt_bytes = point_to_bytes(b_point);

        let e_check = challenge_from_qfi(
            setup,
            b"R_m_aff_dl_ec",
            &[c1, c2, d1, d2, &self.d_prime_1, &self.d_prime_2],
            &[&r_pt_bytes, &b_pt_bytes, &self.b0_bytes, &self.r0_bytes],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let lhs1 = setup.multiexp_signed_bytes(
            &[c1, d1],
            &[(false, self.k_hat.clone()), (true, self.e.clone())],
        )?;
        if lhs1 != self.d_prime_1 {
            return Ok(false);
        }

        let lhs2 = setup.multiexp_signed_bytes(
            &[c2, d2],
            &[(false, self.k_hat.clone()), (true, self.e.clone())],
        )?;
        let f_beta_hat = setup.power_of_f_bytes(&self.beta_hat)?;
        let rhs2 = setup.compose(&self.d_prime_2, &f_beta_hat)?;
        if lhs2 != rhs2 {
            return Ok(false);
        }

        let khat_scalar = bytes_to_scalar(&self.k_hat)?;
        let lhs3 = ProjectivePoint::GENERATOR * khat_scalar;
        let e_scalar = bytes_to_scalar(&self.e)?;
        let rhs3 = r0 + *r_point * e_scalar;
        if lhs3 != rhs3 {
            return Ok(false);
        }

        let bhat_scalar = bytes_to_scalar(&self.beta_hat)?;
        let lhs4 = ProjectivePoint::GENERATOR * bhat_scalar;
        let rhs4 = b0 + *b_point * e_scalar;
        if lhs4 != rhs4 {
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
    fn r_m_aff_dl_ec_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("9001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let gamma_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let r_gamma = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let ct_gamma = setup
            .encrypt_with_r_bytes(&pk, &gamma_bytes, &r_gamma)
            .expect("enc");
        let (c1, c2) = setup.ct_components(&ct_gamma).expect("ct");

        let k_star = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let beta_bytes = Integer::from(17u32).to_digits::<u8>(Order::Msf);
        let q_bytes = setup.q_bytes().expect("q");

        let d1 = setup.exp_bytes(&c1, &k_star).expect("exp c1");
        let c2_k = setup.exp_bytes(&c2, &k_star).expect("exp c2");
        let neg_beta = negate_mod_q_bytes(&beta_bytes, &q_bytes).expect("neg");
        let f_neg_beta = setup.power_of_f_bytes(&neg_beta).expect("f^-b");
        let d2 = setup.compose(&c2_k, &f_neg_beta).expect("compose");

        let k_scalar = bytes_to_scalar(&k_star).expect("k scalar");
        let r_point = ProjectivePoint::GENERATOR * k_scalar;
        let beta_scalar = test_scalar(17);
        let b_point = ProjectivePoint::GENERATOR * beta_scalar;

        let proof = RMAffDlEcProof::prove(
            &mut setup,
            &c1,
            &c2,
            &d1,
            &d2,
            &r_point,
            &b_point,
            &k_star,
            &beta_bytes,
        )
        .expect("prove");

        assert!(proof
            .verify(&setup, &c1, &c2, &d1, &d2, &r_point, &b_point)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_m_aff_dl_ec_rejects_wrong_k_star() {
        let mut setup = ClSetup::new_secp256k1("9002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let gamma_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let r_gamma = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let ct_gamma = setup
            .encrypt_with_r_bytes(&pk, &gamma_bytes, &r_gamma)
            .expect("enc");
        let (c1, c2) = setup.ct_components(&ct_gamma).expect("ct");

        let k_star = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let beta_bytes = Integer::from(17u32).to_digits::<u8>(Order::Msf);
        let q_bytes = setup.q_bytes().expect("q");

        let d1 = setup.exp_bytes(&c1, &k_star).expect("exp c1");
        let c2_k = setup.exp_bytes(&c2, &k_star).expect("exp c2");
        let neg_beta = negate_mod_q_bytes(&beta_bytes, &q_bytes).expect("neg");
        let f_neg_beta = setup.power_of_f_bytes(&neg_beta).expect("f^-b");
        let d2 = setup.compose(&c2_k, &f_neg_beta).expect("compose");

        let k_scalar = bytes_to_scalar(&k_star).expect("k scalar");
        let r_point = ProjectivePoint::GENERATOR * k_scalar;
        let beta_scalar = test_scalar(17);
        let b_point = ProjectivePoint::GENERATOR * beta_scalar;

        let wrong_k_star = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        let proof = RMAffDlEcProof::prove(
            &mut setup,
            &c1,
            &c2,
            &d1,
            &d2,
            &r_point,
            &b_point,
            &wrong_k_star,
            &beta_bytes,
        )
        .expect("prove");

        assert!(!proof
            .verify(&setup, &c1, &c2, &d1, &d2, &r_point, &b_point)
            .expect("verify"));
    }

    #[ignore = "redundant ZK negative test"]
    #[test]
    fn r_m_aff_dl_ec_rejects_wrong_beta() {
        let mut setup = ClSetup::new_secp256k1("9003").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let gamma_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let r_gamma = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let ct_gamma = setup
            .encrypt_with_r_bytes(&pk, &gamma_bytes, &r_gamma)
            .expect("enc");
        let (c1, c2) = setup.ct_components(&ct_gamma).expect("ct");

        let k_star = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let beta_bytes = Integer::from(17u32).to_digits::<u8>(Order::Msf);
        let q_bytes = setup.q_bytes().expect("q");

        let d1 = setup.exp_bytes(&c1, &k_star).expect("exp c1");
        let c2_k = setup.exp_bytes(&c2, &k_star).expect("exp c2");
        let neg_beta = negate_mod_q_bytes(&beta_bytes, &q_bytes).expect("neg");
        let f_neg_beta = setup.power_of_f_bytes(&neg_beta).expect("f^-b");
        let d2 = setup.compose(&c2_k, &f_neg_beta).expect("compose");

        let k_scalar = bytes_to_scalar(&k_star).expect("k scalar");
        let r_point = ProjectivePoint::GENERATOR * k_scalar;
        let beta_scalar = test_scalar(17);
        let b_point = ProjectivePoint::GENERATOR * beta_scalar;

        let wrong_beta_bytes = Integer::from(999u32).to_digits::<u8>(Order::Msf);
        let proof = RMAffDlEcProof::prove(
            &mut setup,
            &c1,
            &c2,
            &d1,
            &d2,
            &r_point,
            &b_point,
            &k_star,
            &wrong_beta_bytes,
        )
        .expect("prove");

        assert!(!proof
            .verify(&setup, &c1, &c2, &d1, &d2, &r_point, &b_point)
            .expect("verify"));
    }
}
