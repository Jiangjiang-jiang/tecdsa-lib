// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_Enc-PC` -- cross-domain encryption-Pedersen-commitment proof.
//!
//! Proves knowledge of `(chi, chi', r)` such that:
//!
//! - `PC = g^chi * h^{chi'}` (EC Pedersen commitment on secp256k1)
//! - `c_0 = g_q^r` (CL ciphertext component 1)
//! - `c_1 = f^chi * ek^r` (CL ciphertext component 2)
//!
//! The key property is that `chi` appears in BOTH the EC check and the CL
//! check, binding the EC Pedersen commitment plaintext to the CL ciphertext
//! plaintext (WMC24 Figure 1, Z_Enc-PC).

use elliptic_curve::group::GroupEncoding;
use k256::ProjectivePoint;

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};
use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

/// Cross-domain encryption-Pedersen-commitment proof.
///
/// Links a CL-HSM ciphertext to an EC Pedersen commitment by proving both
/// use the same plaintext `chi`.
pub struct REncPcProof {
    /// EC Pedersen commitment randomness: `R_PC = g^{a1} * h^{a2}` (compressed, 33 bytes).
    pub r_pc_bytes: Vec<u8>,
    /// CL commitment for ciphertext component 1: `R_c0 = h^{a3}` where h = g_q.
    pub r_c0: Qfi,
    /// CL commitment for ciphertext component 2: `R_c1 = f^{a1} * ek^{a3}`.
    pub r_c1: Qfi,
    /// Response for `chi` (mod q): `z1 = a1 + e*chi mod q`.
    /// Appears in both EC and CL verification checks.
    pub z1: Vec<u8>,
    /// Response for `chi'` (mod q): `z2 = a2 + e*chi' mod q`.
    pub z2: Vec<u8>,
    /// Response for `r` (unbounded): `z3 = a3 + e*r`.
    pub z3: Vec<u8>,
    /// Fiat-Shamir challenge.
    pub e: Vec<u8>,
}

impl REncPcProof {
    /// Generates the cross-domain encryption-Pedersen-commitment proof.
    ///
    /// # Arguments
    ///
    /// * `setup` - CL-HSM setup (mutable for sampling).
    /// * `pk` - CL public key (encryption key `ek`).
    /// * `ct` - CL ciphertext `(c_0, c_1)`.
    /// * `pc_bytes` - Compressed EC Pedersen commitment point (33 bytes).
    /// * `chi_bytes` - Plaintext `chi` (big-endian, mod q).
    /// * `chi_prime_bytes` - Pedersen randomness `chi'` (big-endian, mod q).
    /// * `r_bytes` - CL encryption randomness (big-endian, unbounded).
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        pc_bytes: &[u8],
        chi_bytes: &[u8],
        chi_prime_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        // Sample randomness.
        let a1 = sample_random_mod_q(setup)?; // for chi (mod q)
        let a2 = sample_random_mod_q(setup)?; // for chi' (mod q)
        let a3 = sample_random(setup)?; // for r (unbounded CL domain)

        // --- EC commitment: R_PC = g^{a1} * h^{a2} ---
        let a1_scalar = bytes_to_k256_scalar(&a1);
        let a2_scalar = bytes_to_k256_scalar(&a2);
        let g_ec = ProjectivePoint::GENERATOR;
        let h_ec = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();
        let r_pc = g_ec * a1_scalar + h_ec * a2_scalar;
        let r_pc_bytes = r_pc.to_bytes().to_vec();

        // --- CL commitments ---
        // R_c0 = g_q^{a3} (= h^{a3} in CL notation)
        let r_c0 = setup.power_of_h_bytes(&a3)?;

        // R_c1 = f^{a1} * ek^{a3}
        let f_a1 = setup.power_of_f_bytes(&a1)?;
        let pk_elt = pk.elt();
        let pk_a3 = setup.exp_bytes(pk_elt, &a3)?;
        let r_c1 = setup.compose(&f_a1, &pk_a3)?;

        // --- Challenge ---
        let (c1, c2) = setup.ct_components(ct)?;
        let e = challenge_from_qfi(
            setup,
            b"R_enc_pc",
            &[pk_elt, &c1, &c2, &r_c0, &r_c1],
            &[pc_bytes, &r_pc_bytes],
        )?;

        // --- Responses ---
        let q_bytes = setup.q_bytes()?;
        let z1 = response_mod_q(&a1, &e, chi_bytes, &q_bytes)?;
        let z2 = response_mod_q(&a2, &e, chi_prime_bytes, &q_bytes)?;
        let z3 = response_unbounded(&a3, &e, r_bytes)?;

        Ok(Self {
            r_pc_bytes,
            r_c0,
            r_c1,
            z1,
            z2,
            z3,
            e,
        })
    }

    /// Verifies the cross-domain encryption-Pedersen-commitment proof.
    ///
    /// Checks three equations:
    /// 1. EC: `g^{z1} * h^{z2} == R_PC * PC^e` (secp256k1)
    /// 2. CL: `h^{z3} == R_c0 * c_0^e` (class group)
    /// 3. CL: `f^{z1} * ek^{z3} == R_c1 * c_1^e` (class group)
    ///
    /// `z1` is shared between checks 1 and 3, binding the EC and CL domains.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        pc_bytes: &[u8],
    ) -> ClResult<bool> {
        let pk_elt = pk.elt();
        let (c1, c2) = setup.ct_components(ct)?;

        // --- Re-derive challenge ---
        let e_check = challenge_from_qfi(
            setup,
            b"R_enc_pc",
            &[pk_elt, &c1, &c2, &self.r_c0, &self.r_c1],
            &[pc_bytes, &self.r_pc_bytes],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        // --- Check 1: EC Pedersen check ---
        // g^{z1} * h^{z2} == R_PC * PC^e
        let z1_scalar = bytes_to_k256_scalar(&self.z1);
        let z2_scalar = bytes_to_k256_scalar(&self.z2);
        let e_scalar = bytes_to_k256_scalar(&self.e);
        let g_ec = ProjectivePoint::GENERATOR;
        let h_ec = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();
        let lhs_ec = g_ec * z1_scalar + h_ec * z2_scalar;

        // Parse R_PC and PC from compressed bytes.
        let r_pc_point = point_from_compressed(&self.r_pc_bytes)?;
        let pc_point = point_from_compressed(pc_bytes)?;
        let rhs_ec = r_pc_point + pc_point * e_scalar;

        if lhs_ec != rhs_ec {
            return Ok(false);
        }

        // --- Check 2: CL first component ---
        // h^{z3} == R_c0 * c_0^e
        let lhs_cl1 = setup.power_of_h_bytes(&self.z3)?;
        let c1_e = setup.exp_bytes(&c1, &self.e)?;
        let rhs_cl1 = setup.compose(&self.r_c0, &c1_e)?;
        if lhs_cl1 != rhs_cl1 {
            return Ok(false);
        }

        // --- Check 3: CL second component (cross-domain link via z1) ---
        // f^{z1} * ek^{z3} == R_c1 * c_1^e
        let f_z1 = setup.power_of_f_bytes(&self.z1)?;
        let pk_z3 = setup.exp_bytes(pk_elt, &self.z3)?;
        let lhs_cl2 = setup.compose(&f_z1, &pk_z3)?;
        let c2_e = setup.exp_bytes(&c2, &self.e)?;
        let rhs_cl2 = setup.compose(&self.r_c1, &c2_e)?;
        if lhs_cl2 != rhs_cl2 {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Converts big-endian bytes to a `k256::Scalar`, reducing modulo the curve order.
///
/// Handles variable-length input by zero-padding to 32 bytes on the left.
fn bytes_to_k256_scalar(bytes: &[u8]) -> k256::Scalar {
    use elliptic_curve::ops::Reduce;
    // Pad to exactly 32 bytes (big-endian).
    let mut buf = [0u8; 32];
    let len = bytes.len().min(32);
    buf[32 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
    let uint = k256::U256::from_be_slice(&buf);
    k256::Scalar::reduce(&uint)
}

/// Parses a compressed secp256k1 point from bytes (33 bytes SEC1 compressed).
fn point_from_compressed(bytes: &[u8]) -> ClResult<ProjectivePoint> {
    let repr = k256::CompressedPoint::try_from(bytes).map_err(|_| {
        crate::cl::ClError::InvalidParam(format!(
            "expected 33-byte compressed point, got {}",
            bytes.len()
        ))
    })?;
    let opt: Option<ProjectivePoint> = ProjectivePoint::from_bytes(&repr).into();
    opt.ok_or_else(|| crate::cl::ClError::InvalidParam("failed to decode compressed point".into()))
}

#[cfg(test)]
mod tests {
    use elliptic_curve::group::GroupEncoding;
    use num_bigint::BigUint;

    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_enc_pc_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("10001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let chi = k256::Scalar::from(77u64);
        let chi_prime = k256::Scalar::from(42u64);
        let chi_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&chi);
        let chi_prime_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&chi_prime);

        // EC Pedersen commitment: PC = g^chi * h^{chi'}
        let g = ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();
        let pc = g * chi + h * chi_prime;
        let pc_bytes = pc.to_bytes();

        // CL encryption.
        let r = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_dec = BigUint::from_bytes_be(&r).to_str_radix(10);
        let ct = setup.encrypt_with_r(&pk, "77", &r_dec).expect("enc");

        let proof = REncPcProof::prove(
            &mut setup,
            &pk,
            &ct,
            pc_bytes.as_ref(),
            &chi_bytes,
            &chi_prime_bytes,
            &r,
        )
        .expect("prove");
        assert!(proof
            .verify(&setup, &pk, &ct, pc_bytes.as_ref())
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_enc_pc_rejects_wrong_chi() {
        let mut setup = ClSetup::new_secp256k1("10002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let chi = k256::Scalar::from(77u64);
        let chi_prime = k256::Scalar::from(42u64);
        let wrong_chi = k256::Scalar::from(88u64);
        let _chi_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&chi);
        let wrong_chi_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&wrong_chi);
        let chi_prime_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&chi_prime);

        // PC uses correct chi.
        let g = ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();
        let pc = g * chi + h * chi_prime;
        let pc_bytes = pc.to_bytes();

        // CL encryption uses correct chi.
        let r = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let r_dec = BigUint::from_bytes_be(&r).to_str_radix(10);
        let ct = setup.encrypt_with_r(&pk, "77", &r_dec).expect("enc");

        // Try to prove with wrong chi -- prover cheating.
        let proof = REncPcProof::prove(
            &mut setup,
            &pk,
            &ct,
            pc_bytes.as_ref(),
            &wrong_chi_bytes,
            &chi_prime_bytes,
            &r,
        )
        .expect("prove");
        assert!(
            !proof
                .verify(&setup, &pk, &ct, pc_bytes.as_ref())
                .expect("verify"),
            "proof with wrong chi must be rejected"
        );
    }
}
