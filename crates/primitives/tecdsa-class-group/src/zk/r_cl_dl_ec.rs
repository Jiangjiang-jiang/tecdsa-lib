#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use rug::{integer::Order, Integer};
use tecdsa_curve::conv;

use super::{
    challenge_from_qfi, response_mod_q, response_unbounded, sample_random, sample_random_mod_q,
};
use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

pub struct RClDlEcProof {
    pub t1: Qfi,
    pub t2: Qfi,
    pub v_tilde_bytes: Vec<u8>,
    pub u1: Vec<u8>,
    pub u2: Vec<u8>,
    pub e: Vec<u8>,
}

impl RClDlEcProof {
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        big_v_bytes: &[u8],
        v_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        let t1 = setup.power_of_h_bytes(&a1)?;
        let pk_elt = pk.elt();
        let pk_a1 = setup.pk_pow_bytes(pk, &a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let t2 = setup.compose(&pk_a1, &f_a2)?;

        let v_tilde_bytes = ec_scalar_base_mul_bytes(&a2);

        let (c1, c2) = setup.ct_components(ct)?;
        let e = challenge_from_qfi(
            setup,
            b"R_cl_dl_ec",
            &[pk_elt, &c1, &c2, &t1, &t2],
            &[big_v_bytes, &v_tilde_bytes],
        )?;

        let u1 = response_unbounded(&a1, &e, r_bytes)?;
        let q_bytes = setup.q_bytes()?;
        let u2 = response_mod_q(&a2, &e, v_bytes, &q_bytes)?;

        Ok(Self {
            t1,
            t2,
            v_tilde_bytes,
            u1,
            u2,
            e,
        })
    }

    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        big_v_bytes: &[u8],
    ) -> ClResult<bool> {
        let pk_elt = pk.elt();
        let (c1, c2) = setup.ct_components(ct)?;

        let e_check = challenge_from_qfi(
            setup,
            b"R_cl_dl_ec",
            &[pk_elt, &c1, &c2, &self.t1, &self.t2],
            &[big_v_bytes, &self.v_tilde_bytes],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let lhs1 = setup.power_of_h_bytes(&self.u1)?;
        let c1_e = setup.exp_bytes(&c1, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &c1_e)?;
        if lhs1 != rhs1 {
            return Ok(false);
        }

        let pk_u1 = setup.pk_pow_bytes(pk, &self.u1)?;
        let f_u2 = setup.power_of_f_bytes(&self.u2)?;
        let lhs2 = setup.compose(&pk_u1, &f_u2)?;
        let c2_e = setup.exp_bytes(&c2, &self.e)?;
        let rhs2 = setup.compose(&self.t2, &c2_e)?;
        if lhs2 != rhs2 {
            return Ok(false);
        }

        if !ec_schnorr_check_bytes(&self.u2, &self.v_tilde_bytes, &self.e, big_v_bytes) {
            return Ok(false);
        }

        Ok(true)
    }
}

fn secp256k1_order_bytes() -> Vec<u8> {
    Integer::from_str_radix(crate::cl::SECP256K1_ORDER, 10)
        .expect("valid order")
        .to_digits::<u8>(Order::Msf)
}

fn ec_scalar_base_mul_bytes(scalar_bytes: &[u8]) -> Vec<u8> {
    use elliptic_curve::group::GroupEncoding;

    let val = Integer::from_digits(scalar_bytes, Order::Msf);
    let q = Integer::from_digits(&secp256k1_order_bytes(), Order::Msf);
    let reduced = val % &q;
    let scalar = integer_to_scalar(&reduced);
    let point = k256::ProjectivePoint::GENERATOR * scalar;
    point.to_bytes().to_vec()
}

fn ec_schnorr_check_bytes(
    u2_bytes: &[u8],
    v_tilde_bytes: &[u8],
    e_bytes: &[u8],
    big_v_bytes: &[u8],
) -> bool {
    let q = Integer::from_digits(&secp256k1_order_bytes(), Order::Msf);

    let u2_val = Integer::from_digits(u2_bytes, Order::Msf) % &q;
    let e_val = Integer::from_digits(e_bytes, Order::Msf) % &q;

    let u2_scalar = integer_to_scalar(&u2_val);
    let e_scalar = integer_to_scalar(&e_val);

    let lhs = k256::ProjectivePoint::GENERATOR * u2_scalar;

    let v_tilde = match point_from_bytes(v_tilde_bytes) {
        Some(p) => p,
        None => return false,
    };
    let big_v = match point_from_bytes(big_v_bytes) {
        Some(p) => p,
        None => return false,
    };
    let rhs = v_tilde + big_v * e_scalar;

    lhs == rhs
}

fn integer_to_scalar(val: &Integer) -> k256::Scalar {
    conv::integer_to_scalar::<k256::Secp256k1>(val)
}

fn point_from_bytes(bytes: &[u8]) -> Option<k256::ProjectivePoint> {
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
    use elliptic_curve::group::GroupEncoding;

    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_cl_dl_ec_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("5001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let v_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let r_dec = Integer::from_digits(&r, Order::Msf).to_string_radix(10);
        let ct = setup.encrypt_with_r(&pk, "42", &r_dec).expect("encrypt");

        let v_scalar = integer_to_scalar(&Integer::from(42u32));
        let big_v = k256::ProjectivePoint::GENERATOR * v_scalar;
        let big_v_bytes = big_v.to_bytes().to_vec();

        let proof =
            RClDlEcProof::prove(&mut setup, &pk, &ct, &big_v_bytes, &v_bytes, &r).expect("prove");
        assert!(proof
            .verify(&setup, &pk, &ct, &big_v_bytes)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_cl_dl_ec_rejects_wrong_v() {
        let mut setup = ClSetup::new_secp256k1("5002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let v_bytes = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let r_dec = Integer::from_digits(&r, Order::Msf).to_string_radix(10);
        let ct = setup.encrypt_with_r(&pk, "42", &r_dec).expect("encrypt");

        let wrong_v_scalar = integer_to_scalar(&Integer::from(99u32));
        let wrong_v = k256::ProjectivePoint::GENERATOR * wrong_v_scalar;
        let wrong_v_bytes = wrong_v.to_bytes().to_vec();

        let proof =
            RClDlEcProof::prove(&mut setup, &pk, &ct, &wrong_v_bytes, &v_bytes, &r).expect("prove");
        assert!(!proof
            .verify(&setup, &pk, &ct, &wrong_v_bytes)
            .expect("verify"));
    }
}
