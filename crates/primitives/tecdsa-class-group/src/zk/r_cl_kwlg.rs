// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_cl_kwlg` — CL knowledge proof (prove knowledge of secret key).
//!
//! Sigma protocol: prover knows `sk` such that `pk = h^{sk}`.

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::{ClHsmqkPublicKey, Qfi};

use super::{challenge_from_qfi, response_unbounded, sample_random};

/// CL knowledge proof (secret key knowledge).
pub struct RClKwlgProof {
    /// Commitment: t = h^a.
    pub(crate) t: Qfi,
    /// Response: z = a + e * sk (big-endian bytes).
    pub(crate) z: Vec<u8>,
    /// Fiat-Shamir challenge (big-endian bytes).
    pub(crate) e: Vec<u8>,
}

impl RClKwlgProof {
    /// Proves knowledge of `sk` such that `pk = h^{sk}`.
    pub fn prove(setup: &mut ClSetup, pk: &ClHsmqkPublicKey, sk_bytes: &[u8]) -> ClResult<Self> {
        let a = sample_random(setup)?;
        let t = setup.power_of_h_bytes(&a)?;

        let pk_elt = setup.pk_element(pk)?;
        let e = challenge_from_qfi(setup, b"R_cl_kwlg", &[&pk_elt, &t], &[])?;

        let z = response_unbounded(&a, &e, sk_bytes)?;

        Ok(Self { t, z, e })
    }

    /// Verifies the CL knowledge proof.
    pub fn verify(&self, setup: &ClSetup, pk: &ClHsmqkPublicKey) -> ClResult<bool> {
        let pk_elt = setup.pk_element(pk)?;

        let e_check = challenge_from_qfi(setup, b"R_cl_kwlg", &[&pk_elt, &self.t], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check: h^z == t * pk^e
        let lhs = setup.power_of_h_bytes(&self.z)?;
        let pk_e = setup.exp_bytes(&pk_elt, &self.e)?;
        let rhs = setup.compose(&self.t, &pk_e)?;
        if !lhs.equal(setup.ctx(), &rhs)? {
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
    fn r_cl_kwlg_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("4001").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_bytes");

        let proof = RClKwlgProof::prove(&mut setup, &pk_raw, &sk_bytes).expect("prove");
        assert!(proof.verify(&setup, &pk_raw).expect("verify"));
    }

    #[test]
    fn r_cl_kwlg_rejects_wrong_sk() {
        let mut setup = ClSetup::new_secp256k1("4002").expect("setup");
        let (_sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let (sk_raw2, _) = setup.keygen().expect("keygen2");
        let wrong_sk = setup.sk_to_bytes(&sk_raw2).expect("sk_bytes");

        let proof = RClKwlgProof::prove(&mut setup, &pk_raw, &wrong_sk).expect("prove");
        assert!(!proof.verify(&setup, &pk_raw).expect("verify"));
    }
}
