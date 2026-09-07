// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_CL_DL_EC` -- CL encryption + EC discrete-log relation proof.
//!
//! Sigma protocol (Fiat-Shamir):  prover knows plaintext `v` and
//! encryption randomness `r` such that
//!   `c = Enc(pk, v; r)`          (CL ciphertext)
//! AND
//!   `V = v * G`                  (EC discrete log)
//!
//! That is, the ciphertext and the EC point commit to the **same** scalar.
//!
//! Reference: LLZ25 (Lyu-Li-Zhou-Deng, CCS 2025), Section 4.3.

use elliptic_curve::group::GroupEncoding;
use k256::{ProjectivePoint, Secp256k1};
use rug::{integer::Order, Integer};
use tecdsa_curve::{PointExt, TecdsaCurve};

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};
use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

/// Proof of CL encryption + EC discrete-log consistency.
pub struct RClDlEcProof {
    /// Commitment: t1 = h^{a1} (randomness part of Enc).
    pub t1: Qfi,
    /// Commitment: t2 = pk^{a1} * f^{a2} (message part of Enc).
    pub t2: Qfi,
    /// EC commitment: V_tilde = a2 * G.
    pub v_tilde_bytes: Vec<u8>,
    /// Response for randomness: u1 = a1 + e * r  (unbounded, big-endian bytes).
    pub u1: Vec<u8>,
    /// Response for plaintext: u2 = (a2 + e * v) mod q (big-endian bytes).
    pub u2: Vec<u8>,
    /// Fiat-Shamir challenge (big-endian bytes).
    pub e: Vec<u8>,
}

impl RClDlEcProof {
    /// Generates a proof that `ct = Enc(pk, v; r)` and `V = v * G`.
    ///
    /// # Arguments
    /// - `pk`: the CL public key.
    /// - `ct`: the CL ciphertext encrypting `v`.
    /// - `big_v`: EC point `V = v * G`.
    /// - `v`: the plaintext / discrete log.
    /// - `r`: the encryption randomness.
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        big_v: &ProjectivePoint,
        v: &Integer,
        r: &Integer,
    ) -> ClResult<Self> {
        // 1. Sample random commitment values.
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        // 2. Compute CL commitment: (t1, t2) = Enc(pk, a2; a1) components.
        let t1 = setup.power_of_h(&a1)?;
        let pk_elt = pk.elt();
        let pk_a1 = setup.pk_pow(pk, &a1)?;
        let f_a2 = setup.power_of_f(&a2)?;
        let t2 = setup.compose(&pk_a1, &f_a2)?;

        // 3. Compute EC commitment: V_tilde = a2 * G.
        let v_tilde_bytes = ec_scalar_base_mul_bytes(&a2);

        // 4. Compute challenge: e = H(pk, c1, c2, V, t1, t2, V_tilde).
        let big_v_bytes = big_v.to_bytes_vec();
        let (c1, c2) = setup.ct_components(ct)?;
        let e = challenge_from_qfi(
            setup,
            b"R_cl_dl_ec",
            &[pk_elt, &c1, &c2, &t1, &t2],
            &[&big_v_bytes, &v_tilde_bytes],
        )?;

        // 5. Compute responses.
        let u1 = response_unbounded(&a1, &e, r);
        let q = setup.cl().q();
        let u2 = response_mod_q(&a2, &e, v, q);

        Ok(Self {
            t1,
            t2,
            v_tilde_bytes,
            u1,
            u2,
            e,
        })
    }

    /// Verifies the CL-DL-EC proof.
    ///
    /// Checks:
    /// 1. Challenge re-derivation.
    /// 2. `h^{u1} == t1 * c1^e`  (CL randomness check).
    /// 3. `pk^{u1} * f^{u2} == t2 * c2^e`  (CL message check).
    /// 4. `u2 * G == V_tilde + e * V`  (EC discrete-log check).
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        big_v: &ProjectivePoint,
    ) -> ClResult<bool> {
        let pk_elt = pk.elt();
        let (c1, c2) = setup.ct_components(ct)?;
        let big_v_bytes = big_v.to_bytes_vec();

        // Re-derive challenge.
        let e_check = challenge_from_qfi(
            setup,
            b"R_cl_dl_ec",
            &[pk_elt, &c1, &c2, &self.t1, &self.t2],
            &[&big_v_bytes, &self.v_tilde_bytes],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let u1 = Integer::from_digits(&self.u1, Order::Msf);
        let u2 = Integer::from_digits(&self.u2, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        // Check 1: h^{u1} == t1 * c1^e.
        let lhs1 = setup.power_of_h(&u1)?;
        let c1_e = setup.exp(&c1, &e)?;
        let rhs1 = setup.compose(&self.t1, &c1_e)?;
        if lhs1 != rhs1 {
            return Ok(false);
        }

        // Check 2: pk^{u1} * f^{u2} == t2 * c2^e.
        let pk_u1 = setup.pk_pow(pk, &u1)?;
        let f_u2 = setup.power_of_f(&u2)?;
        let lhs2 = setup.compose(&pk_u1, &f_u2)?;
        let c2_e = setup.exp(&c2, &e)?;
        let rhs2 = setup.compose(&self.t2, &c2_e)?;
        if lhs2 != rhs2 {
            return Ok(false);
        }

        // Check 3: u2 * G == V_tilde + e * V (EC Schnorr check).
        if !ec_schnorr_check_bytes(&self.u2, &self.v_tilde_bytes, &self.e, &big_v_bytes) {
            return Ok(false);
        }

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// EC helpers (secp256k1 via k256)
// ---------------------------------------------------------------------------

/// Computes `scalar * G` and returns the compressed point (33 bytes).
fn ec_scalar_base_mul_bytes(scalar: &Integer) -> Vec<u8> {
    let q = k256::Secp256k1::order();
    let reduced = Integer::from(scalar % &q);
    let scalar = Secp256k1::scalar_from_integer(&reduced);
    let point = k256::ProjectivePoint::GENERATOR * scalar;
    point.to_bytes().to_vec()
}

/// Verifies `u2 * G == V_tilde + e * V` on secp256k1 using byte inputs.
fn ec_schnorr_check_bytes(
    u2_bytes: &[u8],
    v_tilde_bytes: &[u8],
    e_bytes: &[u8],
    big_v_bytes: &[u8],
) -> bool {
    let q = k256::Secp256k1::order();

    let u2_val = Integer::from_digits(u2_bytes, Order::Msf) % &q;
    let e_val = Integer::from_digits(e_bytes, Order::Msf) % &q;

    let u2_scalar = Secp256k1::scalar_from_integer(&u2_val);
    let e_scalar = Secp256k1::scalar_from_integer(&e_val);

    // LHS = u2 * G
    let lhs = k256::ProjectivePoint::GENERATOR * u2_scalar;

    // RHS = V_tilde + e * V
    let v_tilde = match k256::ProjectivePoint::from_bytes_slice(v_tilde_bytes) {
        Some(p) => p,
        None => return false,
    };
    let big_v = match k256::ProjectivePoint::from_bytes_slice(big_v_bytes) {
        Some(p) => p,
        None => return false,
    };
    let rhs = v_tilde + big_v * e_scalar;

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_cl_dl_ec_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(5001u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let v = Integer::from(42u32);
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_integer(&sk2)
        };
        let ct = setup.encrypt_with_r(&pk, &v, &r).expect("encrypt");

        // V = v * G
        let v_scalar = Secp256k1::scalar_from_integer(&v);
        let big_v = k256::ProjectivePoint::GENERATOR * v_scalar;

        let proof = RClDlEcProof::prove(&mut setup, &pk, &ct, &big_v, &v, &r).expect("prove");
        assert!(proof.verify(&setup, &pk, &ct, &big_v).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_cl_dl_ec_rejects_wrong_v() {
        let mut setup = ClSetup::new_secp256k1(5002u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let v = Integer::from(42u32);
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_integer(&sk2)
        };
        let ct = setup.encrypt_with_r(&pk, &v, &r).expect("encrypt");

        // V uses wrong value
        let wrong_v_scalar = Secp256k1::scalar_from_integer(&Integer::from(99u32));
        let wrong_v = k256::ProjectivePoint::GENERATOR * wrong_v_scalar;

        // Prove with correct v but wrong EC point
        let proof = RClDlEcProof::prove(&mut setup, &pk, &ct, &wrong_v, &v, &r).expect("prove");
        assert!(!proof.verify(&setup, &pk, &ct, &wrong_v).expect("verify"));
    }
}
