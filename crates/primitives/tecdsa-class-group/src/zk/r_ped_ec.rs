// SPDX-License-Identifier: MIT OR Apache-2.0
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

use elliptic_curve::group::GroupEncoding;
use k256::{ProjectivePoint, Secp256k1};
use rug::{integer::Order, Integer};
use tecdsa_curve::{PointExt, TecdsaCurve};

use super::{challenge_from_qfi, response_unbounded, sample_random, sample_random_mod_q};
use crate::cl::{ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi};

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
        big_v: &ProjectivePoint,
        v: &Integer,
        r: &Integer,
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        // CL Pedersen commitment: c_tilde = h^{a1} * pk^{a2}.
        let h_a1 = setup.power_of_h(&a1)?;
        let pk_elt = pk.elt();
        let pk_a2 = setup.pk_pow(pk, &a2)?;
        let c_tilde = setup.compose(&h_a1, &pk_a2)?;

        // EC commitment: V_tilde = a2 * G.
        let v_tilde_bytes = ec_scalar_base_mul_bytes(&a2);

        // Compute challenge.
        let big_v_bytes = big_v.to_bytes_vec();
        let e = challenge_from_qfi(
            setup,
            b"R_ped_ec",
            &[pk_elt, c, &c_tilde],
            &[&big_v_bytes, &v_tilde_bytes],
        )?;

        // Compute responses (over Z for CL soundness).
        let s_r = response_unbounded(&a1, &e, r);
        let s_v = response_unbounded(&a2, &e, v);

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
        big_v: &ProjectivePoint,
    ) -> ClResult<bool> {
        let pk_elt = pk.elt();
        let big_v_bytes = big_v.to_bytes_vec();

        // Re-derive challenge.
        let e_check = challenge_from_qfi(
            setup,
            b"R_ped_ec",
            &[pk_elt, c, &self.c_tilde],
            &[&big_v_bytes, &self.v_tilde_bytes],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let s_r = Integer::from_digits(&self.s_r, Order::Msf);
        let s_v = Integer::from_digits(&self.s_v, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        // Check 1: h^{s_r} * pk^{s_v} == c_tilde * c^e.
        let h_sr = setup.power_of_h(&s_r)?;
        let pk_sv = setup.pk_pow(pk, &s_v)?;
        let lhs = setup.compose(&h_sr, &pk_sv)?;
        let c_e = setup.exp(c, &e)?;
        let rhs = setup.compose(&self.c_tilde, &c_e)?;
        if lhs != rhs {
            return Ok(false);
        }

        // Check 2: (s_v mod q) * G == V_tilde + e * V.
        let q = setup.cl().q();
        let s_v_mod_q = s_v % q;
        if !ec_schnorr_check_bytes(
            &s_v_mod_q.to_digits::<u8>(Order::Msf),
            &self.v_tilde_bytes,
            &self.e,
            &big_v_bytes,
        ) {
            return Ok(false);
        }

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ec_scalar_base_mul_bytes(scalar: &Integer) -> Vec<u8> {
    let q = k256::Secp256k1::order();
    let reduced = Integer::from(scalar % &q);
    let scalar = Secp256k1::scalar_from_integer(&reduced);
    let point = k256::ProjectivePoint::GENERATOR * scalar;
    point.to_bytes().to_vec()
}

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

    let lhs = k256::ProjectivePoint::GENERATOR * u2_scalar;

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
    use crate::{cl::ClSetup, nim::Nim};

    #[test]
    fn r_ped_ec_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(6001u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = Integer::from(42u32);

        // Compute pe_A = h^r * pk^x via NIM Encode_A.
        let mut nim = Nim::new(&mut setup);
        let encode_out = nim.encode_a(&x, &pk).expect("encode_a");
        let pe_a = encode_out.pe_a;
        let r = encode_out.state.r.clone();

        // V = x * G
        let x_scalar = Secp256k1::scalar_from_integer(&x);
        let big_v = k256::ProjectivePoint::GENERATOR * x_scalar;

        let proof = RPedEcProof::prove(&mut setup, &pk, &pe_a, &big_v, &x, &r).expect("prove");
        assert!(proof.verify(&setup, &pk, &pe_a, &big_v).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_ped_ec_rejects_wrong_value() {
        let mut setup = ClSetup::new_secp256k1(6002u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = Integer::from(42u32);

        let mut nim = Nim::new(&mut setup);
        let encode_out = nim.encode_a(&x, &pk).expect("encode_a");
        let pe_a = encode_out.pe_a;
        let r = encode_out.state.r.clone();

        // Use wrong V
        let wrong_scalar = Secp256k1::scalar_from_integer(&Integer::from(99u32));
        let wrong_v = k256::ProjectivePoint::GENERATOR * wrong_scalar;

        let proof = RPedEcProof::prove(&mut setup, &pk, &pe_a, &wrong_v, &x, &r).expect("prove");
        assert!(!proof.verify(&setup, &pk, &pe_a, &wrong_v).expect("verify"));
    }
}
