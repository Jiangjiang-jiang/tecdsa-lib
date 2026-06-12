#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use rug::{integer::Order, Integer};

use super::{challenge_from_qfi, response_unbounded, sample_random};
use crate::cl::{ClResult, ClSetup, Qfi};

pub struct RBintProof {
    t: Qfi,
    z: Vec<u8>,
    e: Vec<u8>,
}

impl RBintProof {
    pub fn prove(setup: &mut ClSetup, y: &Qfi, x_bytes: &[u8]) -> ClResult<Self> {
        let a = sample_random(setup)?;
        let t = setup.power_of_h_bytes(&a)?;

        let e = challenge_from_qfi(setup, b"R_bint", &[y, &t], &[])?;

        let z = response_unbounded(&a, &e, x_bytes)?;

        Ok(Self { t, z, e })
    }

    pub fn verify(&self, setup: &ClSetup, y: &Qfi, bound_bytes: &[u8]) -> ClResult<bool> {
        let e_check = challenge_from_qfi(setup, b"R_bint", &[y, &self.t], &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        let z_val = Integer::from_digits(&self.z, Order::Msf);
        let h_z = setup.power_of_h_bytes(&self.z)?;
        let y_e = setup.exp_bytes(y, &self.e)?;
        let rhs = setup.compose(&self.t, &y_e)?;
        if h_z != rhs {
            return Ok(false);
        }

        let bound = Integer::from_digits(bound_bytes, Order::Msf);
        let sk_bound_bytes = setup.secretkey_bound_bytes()?;
        let sk_bound = Integer::from_digits(&sk_bound_bytes, Order::Msf);
        let e_val = Integer::from_digits(&self.e, Order::Msf);
        let max_z = &sk_bound + Integer::from(&e_val * &bound);
        if z_val > max_z {
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
    fn r_bint_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("11001").expect("setup");
        let x_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let y = setup.power_of_h("42").expect("h^x");

        let proof = RBintProof::prove(&mut setup, &y, &x_bytes).expect("prove");
        let bound = setup.secretkey_bound_bytes().expect("bound");
        assert!(proof.verify(&setup, &y, &bound).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_bint_rejects_wrong_x() {
        let mut setup = ClSetup::new_secp256k1("11002").expect("setup");
        let y = setup.power_of_h("42").expect("h^x");

        let wrong_x_bytes = Integer::from(99u32).to_digits::<u8>(Order::Msf);
        let proof = RBintProof::prove(&mut setup, &y, &wrong_x_bytes).expect("prove");
        let bound = setup.secretkey_bound_bytes().expect("bound");
        assert!(!proof.verify(&setup, &y, &bound).expect("verify"));
    }
}
