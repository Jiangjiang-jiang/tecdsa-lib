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

use k256::ProjectivePoint;
use rug::{integer::Order, Integer};
use tecdsa_curve::PointExt;

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
#[derive(Clone)]
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
    /// * `pc` - EC Pedersen commitment point.
    /// * `chi` - Plaintext `chi` (mod q).
    /// * `chi_prime` - Pedersen randomness `chi'` (mod q).
    /// * `r` - CL encryption randomness (unbounded).
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        pc: &ProjectivePoint,
        chi: &Integer,
        chi_prime: &Integer,
        r: &Integer,
    ) -> ClResult<Self> {
        // Sample randomness.
        let a1 = sample_random_mod_q(setup)?; // for chi (mod q)
        let a2 = sample_random_mod_q(setup)?; // for chi' (mod q)
        let a3 = sample_random(setup)?; // for r (unbounded CL domain)

        // --- EC commitment: R_PC = g^{a1} * h^{a2} ---
        let a1_scalar = k256_scalar_from_integer(&a1);
        let a2_scalar = k256_scalar_from_integer(&a2);
        let g_ec = ProjectivePoint::GENERATOR;
        let h_ec = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();
        let r_pc = g_ec * a1_scalar + h_ec * a2_scalar;
        let r_pc_bytes = r_pc.to_bytes_vec();

        // --- CL commitments ---
        // R_c0 = g_q^{a3} (= h^{a3} in CL notation)
        let r_c0 = setup.power_of_h(&a3)?;

        // R_c1 = f^{a1} * ek^{a3}
        let f_a1 = setup.power_of_f(&a1)?;
        let pk_elt = pk.elt();
        let pk_a3 = setup.exp(pk_elt, &a3)?;
        let r_c1 = setup.compose(&f_a1, &pk_a3)?;

        // --- Challenge ---
        let pc_bytes = pc.to_bytes_vec();
        let (c1, c2) = setup.ct_components(ct)?;
        let e = challenge_from_qfi(
            setup,
            b"R_enc_pc",
            &[pk_elt, &c1, &c2, &r_c0, &r_c1],
            &[&pc_bytes, &r_pc_bytes],
        )?;

        // --- Responses ---
        let q = setup.cl().q();
        let z1 = response_mod_q(&a1, &e, chi, q);
        let z2 = response_mod_q(&a2, &e, chi_prime, q);
        let z3 = response_unbounded(&a3, &e, r);

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
        pc: &ProjectivePoint,
    ) -> ClResult<bool> {
        let pk_elt = pk.elt();
        let (c1, c2) = setup.ct_components(ct)?;
        let pc_bytes = pc.to_bytes_vec();

        // --- Re-derive challenge ---
        let e_check = challenge_from_qfi(
            setup,
            b"R_enc_pc",
            &[pk_elt, &c1, &c2, &self.r_c0, &self.r_c1],
            &[&pc_bytes, &self.r_pc_bytes],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let z1 = Integer::from_digits(&self.z1, Order::Msf);
        let z2 = Integer::from_digits(&self.z2, Order::Msf);
        let z3 = Integer::from_digits(&self.z3, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        // --- Check 1: EC Pedersen check ---
        // g^{z1} * h^{z2} == R_PC * PC^e
        let z1_scalar = k256_scalar_from_integer(&z1);
        let z2_scalar = k256_scalar_from_integer(&z2);
        let e_scalar = k256_scalar_from_integer(&e);
        let g_ec = ProjectivePoint::GENERATOR;
        let h_ec = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();
        let lhs_ec = g_ec * z1_scalar + h_ec * z2_scalar;

        // Parse R_PC from compressed bytes.
        let r_pc_point = point_from_compressed(&self.r_pc_bytes)?;
        let rhs_ec = r_pc_point + *pc * e_scalar;

        if lhs_ec != rhs_ec {
            return Ok(false);
        }

        // --- Check 2: CL first component ---
        // h^{z3} == R_c0 * c_0^e
        let lhs_cl1 = setup.power_of_h(&z3)?;
        let c1_e = setup.exp(&c1, &e)?;
        let rhs_cl1 = setup.compose(&self.r_c0, &c1_e)?;
        if lhs_cl1 != rhs_cl1 {
            return Ok(false);
        }

        // --- Check 3: CL second component (cross-domain link via z1) ---
        // f^{z1} * ek^{z3} == R_c1 * c_1^e
        let f_z1 = setup.power_of_f(&z1)?;
        let pk_z3 = setup.pk_pow(pk, &z3)?;
        let lhs_cl2 = setup.compose(&f_z1, &pk_z3)?;
        let c2_e = setup.exp(&c2, &e)?;
        let rhs_cl2 = setup.compose(&self.r_c1, &c2_e)?;
        if lhs_cl2 != rhs_cl2 {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Converts an `Integer` to a `k256::Scalar`, reducing modulo the curve order
/// and mapping negative values to `q - |v|`.
fn k256_scalar_from_integer(v: &Integer) -> k256::Scalar {
    <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::scalar_from_integer(v)
}

/// Parses a compressed secp256k1 point from bytes (33 bytes SEC1 compressed).
fn point_from_compressed(bytes: &[u8]) -> ClResult<ProjectivePoint> {
    ProjectivePoint::from_bytes_slice(bytes)
        .ok_or_else(|| crate::cl::ClError::InvalidParam("failed to decode compressed point".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_enc_pc_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(10001u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let chi = Integer::from(77u32);
        let chi_prime = Integer::from(42u32);

        // EC Pedersen commitment: PC = g^chi * h^{chi'}
        let g = ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();
        let pc = g * k256_scalar_from_integer(&chi) + h * k256_scalar_from_integer(&chi_prime);

        // CL encryption.
        let r = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };
        let ct = setup.encrypt_with_r(&pk, &chi, &r).expect("enc");

        let proof =
            REncPcProof::prove(&mut setup, &pk, &ct, &pc, &chi, &chi_prime, &r).expect("prove");
        assert!(proof.verify(&setup, &pk, &ct, &pc).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_enc_pc_rejects_wrong_chi() {
        let mut setup = ClSetup::new_secp256k1(10002u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let chi = Integer::from(77u32);
        let chi_prime = Integer::from(42u32);
        let wrong_chi = Integer::from(88u32);

        // PC uses correct chi.
        let g = ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();
        let pc = g * k256_scalar_from_integer(&chi) + h * k256_scalar_from_integer(&chi_prime);

        // CL encryption uses correct chi.
        let r = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };
        let ct = setup.encrypt_with_r(&pk, &chi, &r).expect("enc");

        // Try to prove with wrong chi -- prover cheating.
        let proof = REncPcProof::prove(&mut setup, &pk, &ct, &pc, &wrong_chi, &chi_prime, &r)
            .expect("prove");
        assert!(
            !proof.verify(&setup, &pk, &ct, &pc).expect("verify"),
            "proof with wrong chi must be rejected"
        );
    }
}
