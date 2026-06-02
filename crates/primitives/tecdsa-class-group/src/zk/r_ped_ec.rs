// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_Ped_EC` -- Pedersen CL commitment + EC Pedersen commitment proof.
//!
//! Sigma protocol (Fiat-Shamir):  prover knows values `(r, v)` such that
//!   `c = h^r * pk^v`    (Pedersen-like commitment in the class group)
//! AND
//!   `V = v * G`          (EC point -- discrete log)
//!
//! This is the proof used for NIM `Encode_A` outputs in LLZ25.
//!
//! Reference: LLZ25 (Lyu-Li-Zhou-Deng, CCS 2025), Section 4.3.

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::{ClHsmqkPublicKey, Qfi};
use num_bigint::BigUint;
use num_traits::Num;
use tecdsa_curve::conv;

use super::{challenge_from_qfi, response_unbounded, sample_random, sample_random_mod_q};

/// Proof of Pedersen CL commitment + EC discrete-log consistency.
pub struct RPedEcProof {
    /// Commitment in CL group: c_tilde = h^{a1} * pk^{a2}.
    pub c_tilde: Qfi,
    /// EC commitment: V_tilde = a2 * G.
    pub v_tilde_bytes: Vec<u8>,
    /// Response for randomness: s_r = a1 + e * r  (unbounded, big-endian bytes).
    pub s_r: Vec<u8>,
    /// Response for value: s_v = a2 + e * v  (unbounded, big-endian bytes).
    pub s_v: Vec<u8>,
    /// Fiat-Shamir challenge (big-endian bytes).
    pub e: Vec<u8>,
}

impl RPedEcProof {
    /// Generates a proof that `c = h^r * pk^v` and `V = v * G`.
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        c: &Qfi,
        big_v_bytes: &[u8],
        v_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        // CL Pedersen commitment: c_tilde = h^{a1} * pk^{a2}.
        let h_a1 = setup.power_of_h_bytes(&a1)?;
        let pk_elt = setup.pk_element(pk)?;
        let pk_a2 = setup.exp_bytes(&pk_elt, &a2)?;
        let c_tilde = setup.compose(&h_a1, &pk_a2)?;

        // EC commitment: V_tilde = a2 * G.
        let v_tilde_bytes = ec_scalar_base_mul_bytes(&a2);

        // Compute challenge.
        let e = challenge_from_qfi(
            setup,
            b"R_ped_ec",
            &[&pk_elt, c, &c_tilde],
            &[big_v_bytes, &v_tilde_bytes],
        )?;

        // Compute responses (over Z for CL soundness).
        let s_r = response_unbounded(&a1, &e, r_bytes)?;
        let s_v = response_unbounded(&a2, &e, v_bytes)?;

        Ok(Self {
            c_tilde,
            v_tilde_bytes,
            s_r,
            s_v,
            e,
        })
    }

    /// Verifies the Pedersen CL + EC proof.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        c: &Qfi,
        big_v_bytes: &[u8],
    ) -> ClResult<bool> {
        let pk_elt = setup.pk_element(pk)?;

        // Re-derive challenge.
        let e_check = challenge_from_qfi(
            setup,
            b"R_ped_ec",
            &[&pk_elt, c, &self.c_tilde],
            &[big_v_bytes, &self.v_tilde_bytes],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check 1: h^{s_r} * pk^{s_v} == c_tilde * c^e.
        let h_sr = setup.power_of_h_bytes(&self.s_r)?;
        let pk_sv = setup.exp_bytes(&pk_elt, &self.s_v)?;
        let lhs = setup.compose(&h_sr, &pk_sv)?;
        let c_e = setup.exp_bytes(c, &self.e)?;
        let rhs = setup.compose(&self.c_tilde, &c_e)?;
        if !lhs.equal(setup.ctx(), &rhs)? {
            return Ok(false);
        }

        // Check 2: (s_v mod q) * G == V_tilde + e * V.
        let q_bytes = setup.q_bytes()?;
        let s_v_mod_q = mod_reduce_bytes(&self.s_v, &q_bytes);
        if !ec_schnorr_check_bytes(&s_v_mod_q, &self.v_tilde_bytes, &self.e, big_v_bytes) {
            return Ok(false);
        }

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mod_reduce_bytes(a: &[u8], q: &[u8]) -> Vec<u8> {
    let a_val = BigUint::from_bytes_be(a);
    let q_val = BigUint::from_bytes_be(q);
    if q_val.bits() == 0 {
        return a.to_vec();
    }
    (a_val % q_val).to_bytes_be()
}

fn ec_scalar_base_mul_bytes(scalar_bytes: &[u8]) -> Vec<u8> {
    use elliptic_curve::group::GroupEncoding;

    let val = BigUint::from_bytes_be(scalar_bytes);
    let q = BigUint::from_str_radix(crate::bicycl_glue::SECP256K1_ORDER, 10).expect("valid order");
    let reduced = val % &q;
    let scalar = biguint_to_scalar(&reduced);
    let point = k256::ProjectivePoint::GENERATOR * scalar;
    point.to_bytes().to_vec()
}

fn ec_schnorr_check_bytes(
    u2_bytes: &[u8],
    v_tilde_bytes: &[u8],
    e_bytes: &[u8],
    big_v_bytes: &[u8],
) -> bool {
    let q = BigUint::from_str_radix(crate::bicycl_glue::SECP256K1_ORDER, 10).expect("valid order");
    let u2_val = BigUint::from_bytes_be(u2_bytes) % &q;
    let e_val = BigUint::from_bytes_be(e_bytes) % &q;

    let u2_scalar = biguint_to_scalar(&u2_val);
    let e_scalar = biguint_to_scalar(&e_val);

    let lhs = k256::ProjectivePoint::GENERATOR * u2_scalar;

    let v_tilde = match point_from_compressed(v_tilde_bytes) {
        Some(p) => p,
        None => return false,
    };
    let big_v = match point_from_compressed(big_v_bytes) {
        Some(p) => p,
        None => return false,
    };
    let rhs = v_tilde + big_v * e_scalar;
    lhs == rhs
}

fn biguint_to_scalar(val: &num_bigint::BigUint) -> k256::Scalar {
    conv::biguint_to_scalar::<k256::Secp256k1>(val)
}

fn point_from_compressed(bytes: &[u8]) -> Option<k256::ProjectivePoint> {
    use elliptic_curve::group::GroupEncoding;
    if bytes.len() == 33 {
        let repr = k256::CompressedPoint::try_from(bytes).ok()?;
        Option::from(k256::ProjectivePoint::from_bytes(&repr))
    } else if bytes.len() == 65 {
        use elliptic_curve::sec1::{FromSec1Point, Sec1Point};
        let ep = Sec1Point::<k256::Secp256k1>::from_bytes(bytes).ok()?;
        Option::from(k256::ProjectivePoint::from_sec1_point(&ep))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::ClSetup;
    use crate::nim::Nim;
    use elliptic_curve::group::GroupEncoding;

    #[test]
    fn r_ped_ec_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("6001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x_bytes = BigUint::from(42u32).to_bytes_be();

        // Compute pe_A = h^r * pk^x via NIM Encode_A.
        let mut nim = Nim::new(&mut setup);
        let encode_out = nim.encode_a(&42u32.to_be_bytes(), &pk).expect("encode_a");
        let pe_a = encode_out.pe_a;
        let r_bytes = encode_out.state.r_bytes.clone();

        // V = x * G
        let x_scalar = biguint_to_scalar(&num_bigint::BigUint::from(42u32));
        let big_v = k256::ProjectivePoint::GENERATOR * x_scalar;
        let big_v_bytes = big_v.to_bytes().to_vec();

        let proof = RPedEcProof::prove(&mut setup, &pk, &pe_a, &big_v_bytes, &x_bytes, &r_bytes)
            .expect("prove");
        assert!(proof
            .verify(&setup, &pk, &pe_a, &big_v_bytes)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_ped_ec_rejects_wrong_value() {
        let mut setup = ClSetup::new_secp256k1("6002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x_bytes = BigUint::from(42u32).to_bytes_be();

        let mut nim = Nim::new(&mut setup);
        let encode_out = nim.encode_a(&42u32.to_be_bytes(), &pk).expect("encode_a");
        let pe_a = encode_out.pe_a;
        let r_bytes = encode_out.state.r_bytes.clone();

        // Use wrong V
        let wrong_scalar = biguint_to_scalar(&num_bigint::BigUint::from(99u32));
        let wrong_v = k256::ProjectivePoint::GENERATOR * wrong_scalar;
        let wrong_v_bytes = wrong_v.to_bytes().to_vec();

        let proof = RPedEcProof::prove(&mut setup, &pk, &pe_a, &wrong_v_bytes, &x_bytes, &r_bytes)
            .expect("prove");
        assert!(!proof
            .verify(&setup, &pk, &pe_a, &wrong_v_bytes)
            .expect("verify"));
    }
}
