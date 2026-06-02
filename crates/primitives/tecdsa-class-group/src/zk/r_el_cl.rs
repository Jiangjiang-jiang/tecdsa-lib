// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_El-CL` -- ElGamal + CL Scalar Multiply proof.
//!
//! From WMC24 (NDSS 2024). Proves knowledge of (gamma, r) such that:
//!   - `elg_0 = r * G`                 (ElGamal randomness on EC)
//!   - `elg_1 = gamma * D + r * elek`  (ElGamal encryption of gamma * D)
//!   - `cgk_0 = ck_0^gamma`            (CL scalar multiply component 1)
//!   - `cgk_1 = ck_1^gamma`            (CL scalar multiply component 2)
//!
//! where D is the EC generator G (encrypting g^gamma under ElGamal).
//!
//! The proof uses z1 unbounded (for CL checks) and z1 mod q (for EC checks),
//! z2 mod q (for EC checks only).

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::Qfi;

use elliptic_curve::group::GroupEncoding;
use k256::{ProjectivePoint, Scalar, Secp256k1};
use num_bigint::BigUint;
use tecdsa_curve::conv;

use super::{challenge_from_qfi, response_unbounded, sample_random, sample_random_mod_q};

/// ElGamal + CL scalar multiply proof (R_El-CL).
pub struct RElClProof {
    /// EC commitment: R_elg = a2 * G.
    pub r_elg_bytes: Vec<u8>,
    /// EC commitment: S_elg = a1 * D + a2 * elek.
    pub s_elg_bytes: Vec<u8>,
    /// CL commitment: R_ck = ck_0^{a1}.
    pub r_ck: Qfi,
    /// CL commitment: S_ck = ck_1^{a1}.
    pub s_ck: Qfi,
    /// Unbounded response z1 = a1_big + e * gamma_big (big-endian bytes).
    pub z1: Vec<u8>,
    /// EC response z2 = a2 + e * r mod q (big-endian bytes).
    pub z2: Vec<u8>,
    /// Fiat-Shamir challenge (big-endian bytes).
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
        return Err(crate::bicycl_glue::ClError::InvalidParam(format!(
            "expected 33-byte compressed point, got {} bytes",
            bytes.len()
        )));
    }
    let mut repr = <ProjectivePoint as GroupEncoding>::Repr::default();
    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(bytes);
    let opt = ProjectivePoint::from_bytes(&repr);
    if bool::from(opt.is_none()) {
        return Err(crate::bicycl_glue::ClError::InvalidParam(
            "invalid EC point encoding".into(),
        ));
    }
    Ok(opt.unwrap())
}

fn point_to_bytes(p: &ProjectivePoint) -> Vec<u8> {
    p.to_bytes().to_vec()
}

impl RElClProof {
    /// Generates an R_El-CL proof.
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
        // 1. Sample random commitment values.
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        // 2. Compute commitments.
        // EC: R_elg = a2 * G
        let a2_scalar = bytes_to_scalar(&a2)?;
        let r_elg = ProjectivePoint::GENERATOR * a2_scalar;
        let r_elg_bytes = point_to_bytes(&r_elg);

        // EC: S_elg = a1 * D + a2 * elek
        let a1_scalar = bytes_to_scalar(&a1)?;
        let s_elg = *d * a1_scalar + *elek * a2_scalar;
        let s_elg_bytes = point_to_bytes(&s_elg);

        // CL: R_ck = ck_0^{a1}
        let r_ck = setup.exp_bytes(ck_0, &a1)?;
        // CL: S_ck = ck_1^{a1}
        let s_ck = setup.exp_bytes(ck_1, &a1)?;

        // 3. Fiat-Shamir challenge.
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

        // 4. Responses.
        // z1 = a1 + e * gamma (unbounded for CL checks).
        let z1 = response_unbounded(&a1, &e, gamma_bytes)?;

        // z2 = a2 + e * r mod q (for EC checks).
        let q_bytes = setup.q_bytes()?;
        let q = BigUint::from_bytes_be(&q_bytes);
        let a2_big = BigUint::from_bytes_be(&a2);
        let e_big = BigUint::from_bytes_be(&e);
        let r_big = BigUint::from_bytes_be(r_bytes);
        let z2_big = (&a2_big + &e_big * &r_big) % &q;
        let z2 = z2_big.to_bytes_be();

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

    /// Verifies the R_El-CL proof.
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
        // Decode EC commitments from stored bytes.
        let r_elg = decode_point(&self.r_elg_bytes)?;
        let s_elg = decode_point(&self.s_elg_bytes)?;

        // Recompute Fiat-Shamir challenge.
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

        // Check 1: z2 * G == R_elg + e * elg_0
        let lhs1 = ProjectivePoint::GENERATOR * z2_scalar;
        let rhs1 = r_elg + *elg_0 * e_scalar;
        if lhs1 != rhs1 {
            return Ok(false);
        }

        // Check 2: z1 * D + z2 * elek == S_elg + e * elg_1
        let lhs2 = *d * z1_scalar + *elek * z2_scalar;
        let rhs2 = s_elg + *elg_1 * e_scalar;
        if lhs2 != rhs2 {
            return Ok(false);
        }

        // Check 3: ck_0^{z1} == R_ck * cgk_0^e (CL check)
        let ck_0_z1 = setup.exp_bytes(ck_0, &self.z1)?;
        let cgk_0_e = setup.exp_bytes(cgk_0, &self.e)?;
        let rhs3 = setup.compose(&self.r_ck, &cgk_0_e)?;
        if !ck_0_z1.equal(setup.ctx(), &rhs3)? {
            return Ok(false);
        }

        // Check 4: ck_1^{z1} == S_ck * cgk_1^e (CL check)
        let ck_1_z1 = setup.exp_bytes(ck_1, &self.z1)?;
        let cgk_1_e = setup.exp_bytes(cgk_1, &self.e)?;
        let rhs4 = setup.compose(&self.s_ck, &cgk_1_e)?;
        if !ck_1_z1.equal(setup.ctx(), &rhs4)? {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::ClSetup;

    #[test]
    fn r_el_cl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("17001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let g = ProjectivePoint::GENERATOR;

        // ElGamal key
        let eldk = test_scalar(42);
        let elek = g * eldk;

        // Witness: gamma and r
        let gamma_bytes = BigUint::from(17u32).to_bytes_be();
        let r_bytes = BigUint::from(23u32).to_bytes_be();
        let gamma_scalar = test_scalar(17);
        let r_scalar = test_scalar(23);

        // ElGamal encryption of g^gamma: (r*G, gamma*G + r*elek)
        let elg_0 = g * r_scalar;
        let elg_1 = g * gamma_scalar + elek * r_scalar;

        // CL ciphertext to scalar multiply
        let ct = setup
            .encrypt_bytes(&pk, &BigUint::from(55u32).to_bytes_be())
            .expect("encrypt");
        let (ck_0, ck_1) = setup.ct_components(&ct).expect("comp");

        // CL scalar multiply by gamma
        let cgk_0 = setup
            .exp_bytes(&ck_0, &BigUint::from(17u32).to_bytes_be())
            .expect("exp");
        let cgk_1 = setup
            .exp_bytes(&ck_1, &BigUint::from(17u32).to_bytes_be())
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
    fn r_el_cl_rejects_wrong_gamma() {
        let mut setup = ClSetup::new_secp256k1("17002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let g = ProjectivePoint::GENERATOR;
        let eldk = test_scalar(42);
        let elek = g * eldk;

        let gamma_scalar = test_scalar(17);
        let r_scalar = test_scalar(23);
        let r_bytes = BigUint::from(23u32).to_bytes_be();

        let elg_0 = g * r_scalar;
        let elg_1 = g * gamma_scalar + elek * r_scalar;

        let ct = setup
            .encrypt_bytes(&pk, &BigUint::from(55u32).to_bytes_be())
            .expect("encrypt");
        let (ck_0, ck_1) = setup.ct_components(&ct).expect("comp");
        let cgk_0 = setup
            .exp_bytes(&ck_0, &BigUint::from(17u32).to_bytes_be())
            .expect("exp");
        let cgk_1 = setup
            .exp_bytes(&ck_1, &BigUint::from(17u32).to_bytes_be())
            .expect("exp");

        // Prove with WRONG gamma
        let wrong_gamma_bytes = BigUint::from(99u32).to_bytes_be();
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
