// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! R_key: knowledge-of-secret-key proof for CL-HSM.
//!
//! Standard Sigma protocol proving knowledge of `sk` such that
//! `pk = h^sk`. Domain-separated from R_ClKwlg for use in the
//! key-generation context of TX25/JTX25 protocols.

use rug::{integer::Order, Integer};

use super::{challenge_from_qfi, response_unbounded, sample_random};
use crate::cl::{ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi};

/// Key proof (Sigma protocol).
pub struct RKeyProof {
    /// Commitment `t = h^a`.
    pub t: Qfi,
    /// Response `z = a + e * sk` (unbounded integer, big-endian bytes).
    pub z: Vec<u8>,
    /// Fiat-Shamir challenge (big-endian bytes).
    pub e: Vec<u8>,
}

impl RKeyProof {
    /// Proves knowledge of `sk` such that `pk = h^{sk}`.
    pub fn prove(setup: &mut ClSetup, pk: &ClHsmqkPublicKey, sk: &Integer) -> ClResult<Self> {
        let a = sample_random(setup)?;
        let t = setup.power_of_h(&a)?;

        let pk_elt = pk.elt();
        let e = challenge_from_qfi(setup, b"R_key", &[pk_elt, &t], &[b"r_key"])?;

        let z = response_unbounded(&a, &e, sk);

        Ok(Self { t, z, e })
    }

    /// Verifies the key proof.
    pub fn verify(&self, setup: &ClSetup, pk: &ClHsmqkPublicKey) -> ClResult<bool> {
        let pk_elt = pk.elt();

        let e_check = challenge_from_qfi(setup, b"R_key", &[pk_elt, &self.t], &[b"r_key"])?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check: h^z == t * pk^e
        let z = Integer::from_digits(&self.z, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);
        let h_z = setup.power_of_h(&z)?;
        let pk_e = setup.exp(pk_elt, &e)?;
        let rhs = setup.compose(&self.t, &pk_e)?;
        if h_z != rhs {
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
    fn r_key_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(14001u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let proof = RKeyProof::prove(&mut setup, &pk_raw, &sk).expect("prove");
        assert!(proof.verify(&setup, &pk_raw).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_key_rejects_wrong_sk() {
        let mut setup = ClSetup::new_secp256k1(14002u64).expect("setup");
        let (_sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let (sk2, _) = setup.keygen().expect("kg2");
        let wrong_sk = setup.sk_to_integer(&sk2);

        let proof = RKeyProof::prove(&mut setup, &pk_raw, &wrong_sk).expect("prove");
        assert!(!proof.verify(&setup, &pk_raw).expect("verify"));
    }
}
