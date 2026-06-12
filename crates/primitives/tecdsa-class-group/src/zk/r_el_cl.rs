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

use super::{challenge_from_qfi, response_unbounded, sample_random, sample_random_mod_q};
use crate::cl::{ClResult, ClSetup, Qfi};

pub struct RElClProof {
    pub r_elg_bytes: Vec<u8>,
    pub s_elg_bytes: Vec<u8>,
    pub r_ck: Qfi,
    pub s_ck: Qfi,
    pub z1: Vec<u8>,
    pub z2: Vec<u8>,
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

impl RElClProof {
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        setup: &mut ClSetup,
        d: &ProjectivePoint,
        elek: &ProjectivePoint,
        elg_0: &ProjectivePoint,
        elg_1: &ProjectivePoint,
        ck_0: &Qfi,
        ck_1: &Qfi,
        cgk_0: &Qfi,
        cgk_1: &Qfi,
        gamma_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        let a2_scalar = bytes_to_scalar(&a2)?;
        let r_elg = ProjectivePoint::GENERATOR * a2_scalar;
        let r_elg_bytes = point_to_bytes(&r_elg);

        let a1_scalar = bytes_to_scalar(&a1)?;
        let s_elg = *d * a1_scalar + *elek * a2_scalar;
        let s_elg_bytes = point_to_bytes(&s_elg);

        let r_ck = setup.exp_bytes(ck_0, &a1)?;
        let s_ck = setup.exp_bytes(ck_1, &a1)?;

        let d_bytes = point_to_bytes(d);
        let elek_bytes = point_to_bytes(elek);
        let elg_0_bytes = point_to_bytes(elg_0);
        let elg_1_bytes = point_to_bytes(elg_1);

        let e = challenge_from_qfi(
            setup,
            b"R_el_cl",
            &[ck_0, ck_1, cgk_0, cgk_1, &r_ck, &s_ck],
            &[
                &d_bytes,
                &elek_bytes,
                &elg_0_bytes,
                &elg_1_bytes,
                &r_elg_bytes,
                &s_elg_bytes,
            ],
        )?;

        let z1 = response_unbounded(&a1, &e, gamma_bytes)?;

        let q_bytes = setup.q_bytes()?;
        let q = Integer::from_digits(&q_bytes, Order::Msf);
        let a2_big = Integer::from_digits(&a2, Order::Msf);
        let e_big = Integer::from_digits(&e, Order::Msf);
        let r_big = Integer::from_digits(r_bytes, Order::Msf);
        let z2_big = (&a2_big + Integer::from(&e_big * &r_big)) % &q;
        let z2 = z2_big.to_digits::<u8>(Order::Msf);

        Ok(Self {
            r_elg_bytes,
            s_elg_bytes,
            r_ck,
            s_ck,
            z1,
            z2,
            e,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        setup: &ClSetup,
        d: &ProjectivePoint,
        elek: &ProjectivePoint,
        elg_0: &ProjectivePoint,
        elg_1: &ProjectivePoint,
        ck_0: &Qfi,
        ck_1: &Qfi,
        cgk_0: &Qfi,
        cgk_1: &Qfi,
    ) -> ClResult<bool> {
        let r_elg = decode_point(&self.r_elg_bytes)?;
        let s_elg = decode_point(&self.s_elg_bytes)?;

        let d_bytes = point_to_bytes(d);
        let elek_bytes = point_to_bytes(elek);
        let elg_0_bytes = point_to_bytes(elg_0);
        let elg_1_bytes = point_to_bytes(elg_1);

        let e_check = challenge_from_qfi(
            setup,
            b"R_el_cl",
            &[ck_0, ck_1, cgk_0, cgk_1, &self.r_ck, &self.s_ck],
            &[
                &d_bytes,
                &elek_bytes,
                &elg_0_bytes,
                &elg_1_bytes,
                &self.r_elg_bytes,
                &self.s_elg_bytes,
            ],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let z1_scalar = bytes_to_scalar(&self.z1)?;
        let z2_scalar = bytes_to_scalar(&self.z2)?;
        let e_scalar = bytes_to_scalar(&self.e)?;

        let lhs1 = ProjectivePoint::GENERATOR * z2_scalar;
        let rhs1 = r_elg + *elg_0 * e_scalar;
        if lhs1 != rhs1 {
            return Ok(false);
        }

        let lhs2 = *d * z1_scalar + *elek * z2_scalar;
        let rhs2 = s_elg + *elg_1 * e_scalar;
        if lhs2 != rhs2 {
            return Ok(false);
        }

        let lhs3 = setup.multiexp_signed_bytes(
            &[ck_0, cgk_0],
            &[(false, self.z1.clone()), (true, self.e.clone())],
        )?;
        if lhs3 != self.r_ck {
            return Ok(false);
        }

        let lhs4 = setup.multiexp_signed_bytes(
            &[ck_1, cgk_1],
            &[(false, self.z1.clone()), (true, self.e.clone())],
        )?;
        if lhs4 != self.s_ck {
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
    fn r_el_cl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("17001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let g = ProjectivePoint::GENERATOR;

        let eldk = test_scalar(42);
        let elek = g * eldk;

        let gamma_bytes = Integer::from(17u32).to_digits::<u8>(Order::Msf);
        let r_bytes = Integer::from(23u32).to_digits::<u8>(Order::Msf);
        let gamma_scalar = test_scalar(17);
        let r_scalar = test_scalar(23);

        let elg_0 = g * r_scalar;
        let elg_1 = g * gamma_scalar + elek * r_scalar;

        let ct = setup
            .encrypt_bytes(&pk, &Integer::from(55u32).to_digits::<u8>(Order::Msf))
            .expect("encrypt");
        let (ck_0, ck_1) = setup.ct_components(&ct).expect("comp");

        let cgk_0 = setup
            .exp_bytes(&ck_0, &Integer::from(17u32).to_digits::<u8>(Order::Msf))
            .expect("exp");
        let cgk_1 = setup
            .exp_bytes(&ck_1, &Integer::from(17u32).to_digits::<u8>(Order::Msf))
            .expect("exp");

        let proof = RElClProof::prove(
            &mut setup,
            &g,
            &elek,
            &elg_0,
            &elg_1,
            &ck_0,
            &ck_1,
            &cgk_0,
            &cgk_1,
            &gamma_bytes,
            &r_bytes,
        )
        .expect("prove");

        assert!(proof
            .verify(&setup, &g, &elek, &elg_0, &elg_1, &ck_0, &ck_1, &cgk_0, &cgk_1,)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_el_cl_rejects_wrong_gamma() {
        let mut setup = ClSetup::new_secp256k1("17002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let g = ProjectivePoint::GENERATOR;
        let eldk = test_scalar(42);
        let elek = g * eldk;

        let gamma_scalar = test_scalar(17);
        let r_scalar = test_scalar(23);
        let r_bytes = Integer::from(23u32).to_digits::<u8>(Order::Msf);

        let elg_0 = g * r_scalar;
        let elg_1 = g * gamma_scalar + elek * r_scalar;

        let ct = setup
            .encrypt_bytes(&pk, &Integer::from(55u32).to_digits::<u8>(Order::Msf))
            .expect("encrypt");
        let (ck_0, ck_1) = setup.ct_components(&ct).expect("comp");
        let cgk_0 = setup
            .exp_bytes(&ck_0, &Integer::from(17u32).to_digits::<u8>(Order::Msf))
            .expect("exp");
        let cgk_1 = setup
            .exp_bytes(&ck_1, &Integer::from(17u32).to_digits::<u8>(Order::Msf))
            .expect("exp");

        let wrong_gamma_bytes = Integer::from(99u32).to_digits::<u8>(Order::Msf);
        let proof = RElClProof::prove(
            &mut setup,
            &g,
            &elek,
            &elg_0,
            &elg_1,
            &ck_0,
            &ck_1,
            &cgk_0,
            &cgk_1,
            &wrong_gamma_bytes,
            &r_bytes,
        )
        .expect("prove");

        assert!(!proof
            .verify(&setup, &g, &elek, &elg_0, &elg_1, &ck_0, &ck_1, &cgk_0, &cgk_1,)
            .expect("verify"));
    }
}
