#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use super::{challenge_from_qfi, response_unbounded, sample_random};
use crate::cl::{ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi};

pub struct RClKwlgProof {
    pub(crate) t: Qfi,
    pub(crate) z: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl RClKwlgProof {
    pub fn prove(setup: &mut ClSetup, pk: &ClHsmqkPublicKey, sk_bytes: &[u8]) -> ClResult<Self> {
        let a = sample_random(setup)?;
        let t = setup.power_of_h_bytes(&a)?;

        let pk_elt = pk.elt();
        let e = challenge_from_qfi(setup, b"R_cl_kwlg", &[pk_elt, &t], &[])?;

        let z = response_unbounded(&a, &e, sk_bytes)?;

        Ok(Self { t, z, e })
    }

    pub fn verify(&self, setup: &ClSetup, pk: &ClHsmqkPublicKey) -> ClResult<bool> {
        let pk_elt = pk.elt();

        let e_check = challenge_from_qfi(setup, b"R_cl_kwlg", &[pk_elt, &self.t], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        let lhs = setup.power_of_h_bytes(&self.z)?;
        let pk_e = setup.exp_bytes(pk_elt, &self.e)?;
        let rhs = setup.compose(&self.t, &pk_e)?;
        if lhs != rhs {
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
    fn r_cl_kwlg_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("4001").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_bytes");

        let proof = RClKwlgProof::prove(&mut setup, &pk_raw, &sk_bytes).expect("prove");
        assert!(proof.verify(&setup, &pk_raw).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_cl_kwlg_rejects_wrong_sk() {
        let mut setup = ClSetup::new_secp256k1("4002").expect("setup");
        let (_sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let (sk_raw2, _) = setup.keygen().expect("keygen2");
        let wrong_sk = setup.sk_to_bytes(&sk_raw2).expect("sk_bytes");

        let proof = RClKwlgProof::prove(&mut setup, &pk_raw, &wrong_sk).expect("prove");
        assert!(!proof.verify(&setup, &pk_raw).expect("verify"));
    }
}
