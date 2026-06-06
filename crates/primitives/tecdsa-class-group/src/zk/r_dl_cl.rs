// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_dl_cl` -- CL Ciphertext Scalar Multiply + EC Discrete Log.
//!
//! From JTX25.  Proves knowledge of `x` such that:
//!   - `X = x * G`  (EC discrete log on secp256k1)
//!   - `c_{11} = c_{01}^x`  (CL group exponentiation, first ciphertext component)
//!   - `c_{12} = c_{02}^x`  (CL group exponentiation, second ciphertext component)
//!
//! In other words, the output ciphertext `c_1 = (c_{11}, c_{12})` is the
//! deterministic scalar multiplication of input ciphertext `c_0 = (c_{01}, c_{02})`
//! by the same secret `x` that is committed on the elliptic curve as `X = x * G`.

use elliptic_curve::group::GroupEncoding;
use k256::{ProjectivePoint, Scalar, Secp256k1};
use tecdsa_curve::conv;

use super::{challenge_from_qfi, response_unbounded, sample_random};
use crate::cl::{Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, Qfi};

/// CL ciphertext scalar multiply + EC discrete log proof (R\_dl-cl).
pub struct RDlClProof {
    /// Commitment t1 = c_{01}^a (CL group).
    pub t1: Qfi,
    /// Commitment t2 = c_{02}^a (CL group).
    pub t2: Qfi,
    /// Commitment T = (a mod q) * G (compressed EC point, 33 bytes).
    pub t_ec_bytes: Vec<u8>,
    /// Response z = a + e * x (unbounded integer, big-endian bytes).
    pub z: Vec<u8>,
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

impl RDlClProof {
    /// Generates an R\_dl-cl proof.
    pub fn prove(
        setup: &mut ClSetup,
        x_point: &ProjectivePoint,
        ct_in: &ClHsmqkCiphertext,
        ct_out: &ClHsmqkCiphertext,
        x_bytes: &[u8],
    ) -> ClResult<Self> {
        let (c01, c02) = setup.ct_components(ct_in)?;
        let (c11, c12) = setup.ct_components(ct_out)?;

        // 1. Sample random commitment value a from [0, sk_bound).
        let a = sample_random(setup)?;

        // 2. Compute commitments.
        let t1 = setup.exp_bytes(&c01, &a)?;
        let t2 = setup.exp_bytes(&c02, &a)?;
        let a_scalar = bytes_to_scalar(&a)?;
        let t_ec = ProjectivePoint::GENERATOR * a_scalar;
        let t_ec_bytes = point_to_bytes(&t_ec);

        // 3. Fiat-Shamir challenge.
        let x_pt_bytes = point_to_bytes(x_point);

        let e = challenge_from_qfi(
            setup,
            b"R_dl_cl",
            &[&c01, &c02, &c11, &c12, &t1, &t2],
            &[&x_pt_bytes, &t_ec_bytes],
        )?;

        // 4. Response: z = a + e * x (unbounded).
        let z = response_unbounded(&a, &e, x_bytes)?;

        Ok(Self {
            t1,
            t2,
            t_ec_bytes,
            z,
            e,
        })
    }

    /// Verifies the R\_dl-cl proof.
    pub fn verify(
        &self,
        setup: &ClSetup,
        x_point: &ProjectivePoint,
        ct_in: &ClHsmqkCiphertext,
        ct_out: &ClHsmqkCiphertext,
    ) -> ClResult<bool> {
        let (c01, c02) = setup.ct_components(ct_in)?;
        let (c11, c12) = setup.ct_components(ct_out)?;

        let t_ec = decode_point(&self.t_ec_bytes)?;

        // Recompute Fiat-Shamir challenge.
        let x_pt_bytes = point_to_bytes(x_point);

        let e_check = challenge_from_qfi(
            setup,
            b"R_dl_cl",
            &[&c01, &c02, &c11, &c12, &self.t1, &self.t2],
            &[&x_pt_bytes, &self.t_ec_bytes],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check 1: c_{01}^z == t1 * c_{11}^e
        let c01_z = setup.exp_bytes(&c01, &self.z)?;
        let c11_e = setup.exp_bytes(&c11, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &c11_e)?;
        if c01_z != rhs1 {
            return Ok(false);
        }

        // Check 2: c_{02}^z == t2 * c_{12}^e
        let c02_z = setup.exp_bytes(&c02, &self.z)?;
        let c12_e = setup.exp_bytes(&c12, &self.e)?;
        let rhs2 = setup.compose(&self.t2, &c12_e)?;
        if c02_z != rhs2 {
            return Ok(false);
        }

        // Check 3: (z mod q) * G == T + e * X
        let z_scalar = bytes_to_scalar(&self.z)?;
        let lhs3 = ProjectivePoint::GENERATOR * z_scalar;
        let e_scalar = bytes_to_scalar(&self.e)?;
        let rhs3 = t_ec + *x_point * e_scalar;
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
    use crate::cl::ClSetup;

    fn scalar_mul_components(
        setup: &ClSetup,
        ct: &ClHsmqkCiphertext,
        x_bytes: &[u8],
    ) -> ClHsmqkCiphertext {
        let (c1, c2) = setup.ct_components(ct).expect("ct_components");
        let c1_x = setup.exp_bytes(&c1, x_bytes).expect("exp c1");
        let c2_x = setup.exp_bytes(&c2, x_bytes).expect("exp c2");
        setup.ct_from_components(&c1_x, &c2_x).expect("ct_from")
    }

    #[test]
    fn r_dl_cl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("14001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let m_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let r_m = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let ct_in = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_m)
            .expect("enc");

        let x_bytes = Integer::from(17u32).to_digits::<u8>(Order::Msf);

        let ct_out = scalar_mul_components(&setup, &ct_in, &x_bytes);

        let x_scalar = test_scalar(17);
        let x_point = ProjectivePoint::GENERATOR * x_scalar;

        let proof =
            RDlClProof::prove(&mut setup, &x_point, &ct_in, &ct_out, &x_bytes).expect("prove");

        assert!(proof
            .verify(&setup, &x_point, &ct_in, &ct_out)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_dl_cl_rejects_wrong_x() {
        let mut setup = ClSetup::new_secp256k1("14002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let m_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let r_m = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let ct_in = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_m)
            .expect("enc");

        let x_bytes = Integer::from(17u32).to_digits::<u8>(Order::Msf);
        let ct_out = scalar_mul_components(&setup, &ct_in, &x_bytes);

        let x_scalar = test_scalar(17);
        let x_point = ProjectivePoint::GENERATOR * x_scalar;

        let wrong_x_bytes = Integer::from(99u32).to_digits::<u8>(Order::Msf);
        let proof = RDlClProof::prove(&mut setup, &x_point, &ct_in, &ct_out, &wrong_x_bytes)
            .expect("prove");

        assert!(!proof
            .verify(&setup, &x_point, &ct_in, &ct_out)
            .expect("verify"));
    }

    #[ignore = "redundant ZK negative test"]
    #[test]
    fn r_dl_cl_rejects_wrong_ciphertext() {
        let mut setup = ClSetup::new_secp256k1("14003").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let m_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let r_m = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let ct_in = setup
            .encrypt_with_r_bytes(&pk, &m_bytes, &r_m)
            .expect("enc");

        let x_bytes = Integer::from(17u32).to_digits::<u8>(Order::Msf);
        let ct_out = scalar_mul_components(&setup, &ct_in, &x_bytes);

        let x_scalar = test_scalar(17);
        let x_point = ProjectivePoint::GENERATOR * x_scalar;

        let proof =
            RDlClProof::prove(&mut setup, &x_point, &ct_in, &ct_out, &x_bytes).expect("prove");

        let wrong_ct_out = scalar_mul_components(
            &setup,
            &ct_in,
            &Integer::from(3u32).to_digits::<u8>(Order::Msf),
        );

        assert!(!proof
            .verify(&setup, &x_point, &ct_in, &wrong_ct_out)
            .expect("verify"));
    }
}
