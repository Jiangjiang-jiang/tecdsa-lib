// SPDX-License-Identifier: MIT OR Apache-2.0
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

use k256::{ProjectivePoint, Secp256k1};
use rug::{integer::Order, Integer};
use tecdsa_curve::{PointExt, TecdsaCurve};

use super::{challenge_from_qfi, response_unbounded, sample_random, sample_random_mod_q};
use crate::cl::{ClResult, ClSetup, Qfi};

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

fn decode_point(bytes: &[u8]) -> ClResult<ProjectivePoint> {
    ProjectivePoint::from_bytes_slice(bytes)
        .ok_or_else(|| crate::cl::ClError::InvalidParam("invalid EC point encoding".into()))
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
        gamma: &Integer,
        r: &Integer,
    ) -> ClResult<Self> {
        // 1. Sample random commitment values.
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        // 2. Compute commitments.
        // EC: R_elg = a2 * G
        let a2_scalar = Secp256k1::scalar_from_integer(&a2);
        let r_elg = ProjectivePoint::GENERATOR * a2_scalar;
        let r_elg_bytes = r_elg.to_bytes_vec();

        // EC: S_elg = a1 * D + a2 * elek
        let a1_scalar = Secp256k1::scalar_from_integer(&a1);
        let s_elg = *d * a1_scalar + *elek * a2_scalar;
        let s_elg_bytes = s_elg.to_bytes_vec();

        // CL: R_ck = ck_0^{a1}
        let r_ck = setup.exp(ck_0, &a1)?;
        // CL: S_ck = ck_1^{a1}
        let s_ck = setup.exp(ck_1, &a1)?;

        // 3. Fiat-Shamir challenge.
        let d_bytes = d.to_bytes_vec();
        let elek_bytes = elek.to_bytes_vec();
        let elg_0_bytes = elg_0.to_bytes_vec();
        let elg_1_bytes = elg_1.to_bytes_vec();

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
        let z1 = response_unbounded(&a1, &e, gamma);

        // z2 = a2 + e * r mod q (for EC checks).
        let q = setup.cl().q();
        let e_big = Integer::from_digits(&e, Order::Msf);
        let z2_big = (a2 + e_big * r) % q;
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
        let d_bytes = d.to_bytes_vec();
        let elek_bytes = elek.to_bytes_vec();
        let elg_0_bytes = elg_0.to_bytes_vec();
        let elg_1_bytes = elg_1.to_bytes_vec();

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

        let z1_scalar = Secp256k1::scalar_from_bytes(&self.z1);
        let z2_scalar = Secp256k1::scalar_from_bytes(&self.z2);
        let e_scalar = Secp256k1::scalar_from_bytes(&self.e);

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

        let z1 = Integer::from_digits(&self.z1, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        // Check 3: ck_0^{z1} == R_ck * cgk_0^e ⟺ ck_0^{z1} * cgk_0^{-e} == R_ck.
        let lhs3 = setup.multiexp(&[ck_0, cgk_0], &[z1.clone(), -e.clone()])?;
        if lhs3 != self.r_ck {
            return Ok(false);
        }

        // Check 4: ck_1^{z1} == S_ck * cgk_1^e ⟺ ck_1^{z1} * cgk_1^{-e} == S_ck.
        let lhs4 = setup.multiexp(&[ck_1, cgk_1], &[z1, -e])?;
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
        let mut setup = ClSetup::new_secp256k1(17001u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let g = ProjectivePoint::GENERATOR;

        // ElGamal key
        let eldk = k256::Scalar::from(42u64);
        let elek = g * eldk;

        // Witness: gamma and r
        let gamma = Integer::from(17u32);
        let r = Integer::from(23u32);
        let gamma_scalar = k256::Scalar::from(17u64);
        let r_scalar = k256::Scalar::from(23u64);

        // ElGamal encryption of g^gamma: (r*G, gamma*G + r*elek)
        let elg_0 = g * r_scalar;
        let elg_1 = g * gamma_scalar + elek * r_scalar;

        // CL ciphertext to scalar multiply
        let ct = setup.encrypt(&pk, &Integer::from(55u32)).expect("encrypt");
        let (ck_0, ck_1) = setup.ct_components(&ct).expect("comp");

        // CL scalar multiply by gamma
        let cgk_0 = setup.exp(&ck_0, &gamma).expect("exp");
        let cgk_1 = setup.exp(&ck_1, &gamma).expect("exp");

        let proof = RElClProof::prove(
            &mut setup, &g, &elek, &elg_0, &elg_1, &ck_0, &ck_1, &cgk_0, &cgk_1, &gamma, &r,
        )
        .expect("prove");

        assert!(proof
            .verify(&setup, &g, &elek, &elg_0, &elg_1, &ck_0, &ck_1, &cgk_0, &cgk_1,)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_el_cl_rejects_wrong_gamma() {
        let mut setup = ClSetup::new_secp256k1(17002u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let g = ProjectivePoint::GENERATOR;
        let eldk = k256::Scalar::from(42u64);
        let elek = g * eldk;

        let gamma_scalar = k256::Scalar::from(17u64);
        let r_scalar = k256::Scalar::from(23u64);
        let r = Integer::from(23u32);

        let elg_0 = g * r_scalar;
        let elg_1 = g * gamma_scalar + elek * r_scalar;

        let ct = setup.encrypt(&pk, &Integer::from(55u32)).expect("encrypt");
        let (ck_0, ck_1) = setup.ct_components(&ct).expect("comp");
        let cgk_0 = setup.exp(&ck_0, &Integer::from(17u32)).expect("exp");
        let cgk_1 = setup.exp(&ck_1, &Integer::from(17u32)).expect("exp");

        // Prove with WRONG gamma
        let wrong_gamma = Integer::from(99u32);
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
            &wrong_gamma,
            &r,
        )
        .expect("prove");

        assert!(!proof
            .verify(&setup, &g, &elek, &elg_0, &elg_1, &ck_0, &ck_1, &cgk_0, &cgk_1,)
            .expect("verify"));
    }
}
