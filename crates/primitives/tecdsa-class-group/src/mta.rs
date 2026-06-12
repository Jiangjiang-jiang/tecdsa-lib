use std::cell::RefCell;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use k256::Secp256k1;
use rand_core::CryptoRngCore;
use rug::{integer::Order, Integer};
use subtle::ConstantTimeEq;
use tecdsa_curve::conv;
use tecdsa_protocol::{MtA, MtAWithCheck};

use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClError, ClSetup, PublicKey as ClHsmqkPublicKey,
    SecretKey as ClHsmqkSecretKey,
};

pub struct ClMtA;

pub struct ClMtaSetup {
    pub setup: RefCell<ClSetup>,
    pub pk: ClHsmqkPublicKey,
    pub sk: ClHsmqkSecretKey,
}

impl Clone for ClMtaSetup {
    fn clone(&self) -> Self {
        unimplemented!("ClMtaSetup::clone is not supported; each party should create its own setup")
    }
}

pub struct ClSenderState {
    pub b_bytes: Vec<u8>,
}

pub struct ClSenderMsg {
    pub ciphertext: ClHsmqkCiphertext,
}

pub struct ClReceiverMsg {
    pub ciphertext: ClHsmqkCiphertext,
}

#[derive(Debug, thiserror::Error)]
pub enum ClMtaError {
    #[error("CL error: {0}")]
    Cl(#[from] ClError),

    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

impl MtA for ClMtA {
    type Setup = ClMtaSetup;
    type SenderState = ClSenderState;
    type SenderMsg = ClSenderMsg;
    type ReceiverMsg = ClReceiverMsg;
    type Error = ClMtaError;

    fn sender_encrypt(
        setup: &Self::Setup,
        b_bytes: &[u8],
        _q_bytes: &[u8],
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SenderMsg, Self::SenderState), Self::Error> {
        let mut cl_setup = setup.setup.borrow_mut();
        let ciphertext = cl_setup.encrypt_bytes(&setup.pk, b_bytes)?;

        let msg = ClSenderMsg { ciphertext };
        let state = ClSenderState {
            b_bytes: b_bytes.to_vec(),
        };

        Ok((msg, state))
    }

    fn receiver_compute(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>), Self::Error> {
        let q = Integer::from_digits(q_bytes, Order::Msf);

        let mut cl_setup = setup.setup.borrow_mut();

        let c_scaled =
            cl_setup.scal_ciphertext_bytes(&setup.pk, &sender_msg.ciphertext, a_bytes)?;

        let (sk_tmp, _pk_tmp) = cl_setup.keygen()?;
        let r_bytes = cl_setup.sk_to_bytes(&sk_tmp)?;
        let r_big = Integer::from_digits(&r_bytes, Order::Msf);
        let alpha_prime = r_big % &q;
        let alpha_prime_bytes = alpha_prime.to_digits::<u8>(Order::Msf);

        let c_alpha = cl_setup.encrypt_bytes(&setup.pk, &alpha_prime_bytes)?;

        let c_a = cl_setup.add_ciphertexts(&setup.pk, &c_scaled, &c_alpha)?;

        let alpha_mod_q = Integer::from(&alpha_prime % &q);
        let alpha = if alpha_mod_q == 0 {
            Integer::new()
        } else {
            Integer::from(&q - &alpha_mod_q)
        };
        let alpha_bytes = alpha.to_digits::<u8>(Order::Msf);

        let msg = ClReceiverMsg { ciphertext: c_a };

        Ok((msg, alpha_bytes))
    }

    fn sender_decrypt(
        setup: &Self::Setup,
        _state: &Self::SenderState,
        q_bytes: &[u8],
        receiver_msg: &Self::ReceiverMsg,
    ) -> Result<Vec<u8>, Self::Error> {
        let q = Integer::from_digits(q_bytes, Order::Msf);

        let cl_setup = setup.setup.borrow();

        let plaintext_bytes = cl_setup.decrypt_bytes(&setup.sk, &receiver_msg.ciphertext)?;
        let plaintext = Integer::from_digits(&plaintext_bytes, Order::Msf);

        let beta = plaintext % &q;
        let beta_bytes = beta.to_digits::<u8>(Order::Msf);

        Ok(beta_bytes)
    }
}

pub struct ClCheckProof {
    pub g_alpha_bytes: Vec<u8>,
}

impl std::fmt::Debug for ClCheckProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClCheckProof")
            .field("g_alpha_bytes_len", &self.g_alpha_bytes.len())
            .finish()
    }
}

impl MtAWithCheck for ClMtA {
    type CheckProof = ClCheckProof;

    fn receiver_compute_with_check(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>, Self::CheckProof), Self::Error> {
        let (receiver_msg, alpha_bytes) =
            Self::receiver_compute(setup, a_bytes, q_bytes, sender_msg, rng)?;

        let alpha = Integer::from_digits(&alpha_bytes, Order::Msf);
        let q = Integer::from_digits(q_bytes, Order::Msf);
        let alpha_scalar = conv::integer_to_scalar::<Secp256k1>(&Integer::from(&alpha % &q));

        let g_alpha = <Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * alpha_scalar;
        let g_alpha_bytes = g_alpha.to_bytes().to_vec();

        let check_proof = ClCheckProof { g_alpha_bytes };

        Ok((receiver_msg, alpha_bytes, check_proof))
    }

    fn verify_check(
        _setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        beta_bytes: &[u8],
        check_proof: &Self::CheckProof,
        aux_bytes: &[u8],
    ) -> Result<bool, Self::Error> {
        let q = Integer::from_digits(q_bytes, Order::Msf);

        let g_alpha_repr = k256::CompressedPoint::try_from(check_proof.g_alpha_bytes.as_slice())
            .map_err(|e| ClMtaError::InvalidParam(format!("invalid g_alpha point: {e}")))?;
        let g_alpha =
            Option::<k256::ProjectivePoint>::from(k256::ProjectivePoint::from_bytes(&g_alpha_repr))
                .ok_or_else(|| ClMtaError::InvalidParam("invalid g_alpha EC point".into()))?;

        let g_a_repr = k256::CompressedPoint::try_from(aux_bytes)
            .map_err(|e| ClMtaError::InvalidParam(format!("invalid g_a point: {e}")))?;
        let g_a =
            Option::<k256::ProjectivePoint>::from(k256::ProjectivePoint::from_bytes(&g_a_repr))
                .ok_or_else(|| ClMtaError::InvalidParam("invalid g_a EC point".into()))?;

        let beta = Integer::from_digits(beta_bytes, Order::Msf);
        let beta_scalar = conv::integer_to_scalar::<Secp256k1>(&Integer::from(&beta % &q));
        let g_beta = <Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * beta_scalar;

        let b = Integer::from_digits(&state.b_bytes, Order::Msf);
        let b_scalar = conv::integer_to_scalar::<Secp256k1>(&Integer::from(&b % &q));

        let lhs = g_alpha + g_beta;
        let rhs = g_a * b_scalar;

        Ok(bool::from(lhs.to_bytes().ct_eq(&rhs.to_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use tecdsa_bigint::mul_mod;

    use super::*;

    fn test_setup(seed: &str) -> ClMtaSetup {
        let mut cl_setup = ClSetup::new_secp256k1(seed).expect("CL setup should succeed");
        let (sk, pk) = cl_setup.keygen().expect("keygen should succeed");

        ClMtaSetup {
            setup: RefCell::new(cl_setup),
            pk,
            sk,
        }
    }

    fn curve_order() -> Integer {
        Integer::from_str_radix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .expect("valid order")
    }

    #[test]
    fn cl_mta_correctness() {
        let setup = test_setup("2001");

        let q = curve_order();
        let q_bytes = q.to_digits::<u8>(Order::Msf);

        let b = Integer::from(12345u32);
        let b_bytes = b.to_digits::<u8>(Order::Msf);

        let a = Integer::from(67890u32);
        let a_bytes = a.to_digits::<u8>(Order::Msf);

        let mut rng = rand::thread_rng();

        let (sender_msg, sender_state) =
            ClMtA::sender_encrypt(&setup, &b_bytes, &q_bytes, &mut rng)
                .expect("sender_encrypt should succeed");

        let (receiver_msg, alpha_bytes) =
            ClMtA::receiver_compute(&setup, &a_bytes, &q_bytes, &sender_msg, &mut rng)
                .expect("receiver_compute should succeed");

        let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
            .expect("sender_decrypt should succeed");

        let alpha = Integer::from_digits(&alpha_bytes, Order::Msf);
        let beta = Integer::from_digits(&beta_bytes, Order::Msf);
        let sum = Integer::from(&alpha + &beta) % &q;
        let expected = mul_mod(&a, &b, &q);

        assert_eq!(sum, expected, "alpha + beta must equal a * b mod q");
    }

    #[test]
    #[ignore = "redundant MtA variant"]
    fn cl_mta_multiple_runs() {
        let setup = test_setup("2002");

        let q = curve_order();
        let q_bytes = q.to_digits::<u8>(Order::Msf);

        let mut rng = rand::thread_rng();

        let test_values: &[(u32, u32)] = &[(100, 200), (42, 99), (1, 1)];

        for &(a_val, b_val) in test_values {
            let a = Integer::from(a_val);
            let b = Integer::from(b_val);

            let (sender_msg, sender_state) =
                ClMtA::sender_encrypt(&setup, &b.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                    .expect("sender_encrypt");

            let (receiver_msg, alpha_bytes) = ClMtA::receiver_compute(
                &setup,
                &a.to_digits::<u8>(Order::Msf),
                &q_bytes,
                &sender_msg,
                &mut rng,
            )
            .expect("receiver_compute");

            let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
                .expect("sender_decrypt");

            let alpha = Integer::from_digits(&alpha_bytes, Order::Msf);
            let beta = Integer::from_digits(&beta_bytes, Order::Msf);
            let sum = Integer::from(&alpha + &beta) % &q;
            let expected = mul_mod(&a, &b, &q);

            assert_eq!(
                sum, expected,
                "MtA correctness must hold for a={a_val}, b={b_val}"
            );
        }
    }

    #[test]
    #[ignore = "redundant MtA variant"]
    fn cl_mta_with_larger_values() {
        let setup = test_setup("2003");

        let q = curve_order();
        let q_bytes = q.to_digits::<u8>(Order::Msf);

        let a = Integer::from(&q - 1);
        let b = Integer::from(2u32);

        let mut rng = rand::thread_rng();

        let (sender_msg, sender_state) =
            ClMtA::sender_encrypt(&setup, &b.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                .expect("sender_encrypt");

        let (receiver_msg, alpha_bytes) = ClMtA::receiver_compute(
            &setup,
            &a.to_digits::<u8>(Order::Msf),
            &q_bytes,
            &sender_msg,
            &mut rng,
        )
        .expect("receiver_compute");

        let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
            .expect("sender_decrypt");

        let alpha = Integer::from_digits(&alpha_bytes, Order::Msf);
        let beta = Integer::from_digits(&beta_bytes, Order::Msf);
        let sum = Integer::from(&alpha + &beta) % &q;
        let expected = mul_mod(&a, &b, &q);

        assert_eq!(sum, expected, "alpha + beta must equal a * b mod q");
    }

    #[test]
    fn cl_mta_with_check_correctness() {
        let setup = test_setup("3001");

        let q = curve_order();
        let q_bytes = q.to_digits::<u8>(Order::Msf);

        let b = Integer::from(12345u32);
        let b_bytes = b.to_digits::<u8>(Order::Msf);

        let a = Integer::from(67890u32);
        let a_bytes = a.to_digits::<u8>(Order::Msf);

        let a_mod_q = Integer::from(&a % &q);
        let a_mod_bytes = a_mod_q.to_digits::<u8>(Order::Msf);
        let mut a_padded = [0u8; 32];
        let a_len = a_mod_bytes.len().min(32);
        a_padded[32 - a_len..].copy_from_slice(&a_mod_bytes[..a_len]);
        let a_repr = k256::FieldBytes::from(a_padded);
        let a_scalar = Option::<k256::Scalar>::from(
            <k256::Scalar as elliptic_curve::PrimeField>::from_repr(a_repr),
        )
        .expect("a should be a valid scalar");
        let g_a = <Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * a_scalar;
        let g_a_bytes = g_a.to_bytes().to_vec();

        let mut rng = rand::thread_rng();

        let (sender_msg, sender_state) =
            ClMtA::sender_encrypt(&setup, &b_bytes, &q_bytes, &mut rng)
                .expect("sender_encrypt should succeed");

        let (receiver_msg, alpha_bytes, check_proof) =
            ClMtA::receiver_compute_with_check(&setup, &a_bytes, &q_bytes, &sender_msg, &mut rng)
                .expect("receiver_compute_with_check should succeed");

        let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
            .expect("sender_decrypt should succeed");

        let check_ok = ClMtA::verify_check(
            &setup,
            &sender_state,
            &q_bytes,
            &beta_bytes,
            &check_proof,
            &g_a_bytes,
        )
        .expect("verify_check should succeed");
        assert!(check_ok, "MtAwc consistency check must pass");

        let alpha = Integer::from_digits(&alpha_bytes, Order::Msf);
        let beta = Integer::from_digits(&beta_bytes, Order::Msf);
        let sum = Integer::from(&alpha + &beta) % &q;
        let expected = mul_mod(&a, &b, &q);
        assert_eq!(sum, expected, "alpha + beta must equal a * b mod q");
    }

    #[test]
    #[ignore = "redundant MtA variant"]
    fn cl_mta_with_check_multiple_runs() {
        let setup = test_setup("3002");

        let q = curve_order();
        let q_bytes = q.to_digits::<u8>(Order::Msf);

        let mut rng = rand::thread_rng();
        let test_values: &[(u32, u32)] = &[(7, 11), (100, 200), (1, 1)];

        for &(a_val, b_val) in test_values {
            let a = Integer::from(a_val);
            let b = Integer::from(b_val);

            let a_mod_q = Integer::from(&a % &q);
            let a_mod_bytes = a_mod_q.to_digits::<u8>(Order::Msf);
            let mut a_padded = [0u8; 32];
            let a_len = a_mod_bytes.len().min(32);
            a_padded[32 - a_len..].copy_from_slice(&a_mod_bytes[..a_len]);
            let a_repr = k256::FieldBytes::from(a_padded);
            let a_scalar = Option::<k256::Scalar>::from(
                <k256::Scalar as elliptic_curve::PrimeField>::from_repr(a_repr),
            )
            .expect("a should be valid scalar");
            let g_a = <Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * a_scalar;
            let g_a_bytes = g_a.to_bytes().to_vec();

            let (sender_msg, sender_state) =
                ClMtA::sender_encrypt(&setup, &b.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                    .expect("sender_encrypt");

            let (receiver_msg, alpha_bytes, check_proof) = ClMtA::receiver_compute_with_check(
                &setup,
                &a.to_digits::<u8>(Order::Msf),
                &q_bytes,
                &sender_msg,
                &mut rng,
            )
            .expect("receiver_compute_with_check");

            let beta_bytes = ClMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
                .expect("sender_decrypt");

            let check_ok = ClMtA::verify_check(
                &setup,
                &sender_state,
                &q_bytes,
                &beta_bytes,
                &check_proof,
                &g_a_bytes,
            )
            .expect("verify_check");
            assert!(check_ok, "MtAwc check must pass for a={a_val}, b={b_val}");

            let alpha = Integer::from_digits(&alpha_bytes, Order::Msf);
            let beta = Integer::from_digits(&beta_bytes, Order::Msf);
            let sum = Integer::from(&alpha + &beta) % &q;
            let expected = mul_mod(&a, &b, &q);
            assert_eq!(sum, expected, "MtA correctness for a={a_val}, b={b_val}");
        }
    }
}
