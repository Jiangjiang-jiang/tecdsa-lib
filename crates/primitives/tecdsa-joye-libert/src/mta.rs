use rand_core::CryptoRngCore;
use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use tecdsa_bigint::{mul_mod, multi_exp, pow_mod, random_below};
use zeroize::Zeroize;

use crate::{
    enc_dec::{decrypt, encrypt, JlCiphertext},
    kgen::{JlPublicKey, JlSecretKey},
    zk::{zkjl_aff::ZkJlAffProof, zkjl_enc::ZkJlEncProof},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct JlMtaSender {
    #[serde(with = "tecdsa_bigint::int_wire")]
    share: Integer,
}

impl Zeroize for JlMtaSender {
    fn zeroize(&mut self) {
        self.share = Integer::new();
    }
}

impl Drop for JlMtaSender {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for JlMtaSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JlMtaSender")
            .field("share", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JlMtaReceiver {
    #[serde(with = "tecdsa_bigint::int_wire")]
    share: Integer,
}

impl Zeroize for JlMtaReceiver {
    fn zeroize(&mut self) {
        self.share = Integer::new();
    }
}

impl Drop for JlMtaReceiver {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for JlMtaReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JlMtaReceiver")
            .field("share", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtaReceiverMsg1 {
    pub ct: JlCiphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtaSenderMsg1 {
    pub ct: JlCiphertext,
}

#[derive(Clone, Debug)]
pub struct MtaSenderOutput {
    pub alpha: Integer,
}

#[derive(Clone, Debug)]
pub struct MtaReceiverOutput {
    pub beta: Integer,
}

impl JlMtaSender {
    #[must_use]
    pub fn new(share: Integer) -> Self {
        Self { share }
    }
}

impl JlMtaReceiver {
    #[must_use]
    pub fn new(share: Integer) -> Self {
        Self { share }
    }
}

pub fn mta_receiver_step1(
    receiver: &JlMtaReceiver,
    pk_receiver: &JlPublicKey,
    rng: &mut impl CryptoRngCore,
) -> (MtaReceiverMsg1, Integer) {
    let (ct, r) = encrypt(pk_receiver, &receiver.share, rng);
    (MtaReceiverMsg1 { ct }, r)
}

pub fn mta_sender_step(
    sender: &JlMtaSender,
    pk_receiver: &JlPublicKey,
    receiver_msg: &MtaReceiverMsg1,
    q: &Integer,
    rng: &mut impl CryptoRngCore,
) -> (MtaSenderMsg1, MtaSenderOutput) {
    mta_sender_step_with_sec(sender, pk_receiver, receiver_msg, q, 40, 40, rng)
}

pub fn mta_sender_step_with_sec(
    sender: &JlMtaSender,
    pk_receiver: &JlPublicKey,
    receiver_msg: &MtaReceiverMsg1,
    q: &Integer,
    s: u32,
    t: u32,
    rng: &mut impl CryptoRngCore,
) -> (MtaSenderMsg1, MtaSenderOutput) {
    let a = &sender.share;

    let q_sq = Integer::from(q * q);
    let alpha_prime_bound = q_sq << (2 * s + t);
    let alpha_prime = random_below(&alpha_prime_bound, rng);

    let shift = Integer::from(q << (s + t));

    let y_shift = pow_mod(&pk_receiver.y, &shift, &pk_receiver.n);
    let c_shifted = mul_mod(&receiver_msg.ct.c, &y_shift, &pk_receiver.n);

    let c_shifted_a = pow_mod(&c_shifted, a, &pk_receiver.n);
    let y_alpha = pow_mod(&pk_receiver.y, &alpha_prime, &pk_receiver.n);
    let r = random_below(&pk_receiver.n, rng);
    let h_r = pow_mod(&pk_receiver.h, &r, &pk_receiver.n);
    let c_1 = mul_mod(
        &mul_mod(&c_shifted_a, &y_alpha, &pk_receiver.n),
        &h_r,
        &pk_receiver.n,
    );

    let msg = MtaSenderMsg1 {
        ct: JlCiphertext { c: c_1 },
    };

    let alpha_mod_q = Integer::from(&alpha_prime % q);
    let alpha = if alpha_mod_q == 0 {
        Integer::new()
    } else {
        Integer::from(q - &alpha_mod_q)
    };

    (msg, MtaSenderOutput { alpha })
}

pub fn mta_receiver_step2(
    sk: &JlSecretKey,
    pk: &JlPublicKey,
    sender_msg: &MtaSenderMsg1,
    q: &Integer,
) -> MtaReceiverOutput {
    let plaintext = decrypt(sk, pk, &sender_msg.ct);
    let beta = Integer::from(&plaintext % q);
    MtaReceiverOutput { beta }
}

use tecdsa_protocol::MtA;

pub struct JlMtA;

#[derive(Clone)]
pub struct JlMtaSetup {
    pub pk: JlPublicKey,
    pub pk0: JlPublicKey,
    pub sk: JlSecretKey,
    pub s: u32,
    pub t: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlMtaSenderState {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub nonce: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub plaintext: Integer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlMtaSenderMsg {
    pub ciphertext: JlCiphertext,
    pub proof_enc: ZkJlEncProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlMtaReceiverMsg {
    pub ciphertext: JlCiphertext,
    pub proof_aff: ZkJlAffProof,
}

#[derive(Debug, thiserror::Error)]
pub enum JlMtaError {
    #[error("plaintext overflow: value exceeds 2^k")]
    Overflow,

    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    #[error("ZK proof verification failed: {0}")]
    ProofVerificationFailed(&'static str),
}

impl MtA for JlMtA {
    type Setup = JlMtaSetup;
    type SenderState = JlMtaSenderState;
    type SenderMsg = JlMtaSenderMsg;
    type ReceiverMsg = JlMtaReceiverMsg;
    type Error = JlMtaError;

    fn sender_encrypt(
        setup: &Self::Setup,
        b_bytes: &[u8],
        _q_bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SenderMsg, Self::SenderState), Self::Error> {
        let b = Integer::from_digits(b_bytes, Order::Msf);

        let (ciphertext, nonce) = encrypt(&setup.pk, &b, rng);

        let msg_bits = setup.pk.k;

        let proof_enc = ZkJlEncProof::prove(&setup.pk, &ciphertext.c, &b, &nonce, msg_bits, rng);

        let msg = JlMtaSenderMsg {
            ciphertext,
            proof_enc,
        };
        let state = JlMtaSenderState {
            nonce,
            plaintext: b,
        };

        Ok((msg, state))
    }

    fn receiver_compute(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>), Self::Error> {
        if !sender_msg
            .proof_enc
            .verify(&setup.pk, &sender_msg.ciphertext.c)
        {
            return Err(JlMtaError::ProofVerificationFailed("ZkJlEncProof"));
        }

        let a = Integer::from_digits(a_bytes, Order::Msf);
        let q = Integer::from_digits(q_bytes, Order::Msf);

        let q_sq = Integer::from(&q * &q);
        let alpha_prime_bound = q_sq << (2 * setup.s + setup.t);
        let alpha_prime = random_below(&alpha_prime_bound, rng);

        let shift = Integer::from(&q << (setup.s + setup.t));

        let y_shift = pow_mod(&setup.pk.y, &shift, &setup.pk.n);
        let c_shifted = mul_mod(&sender_msg.ciphertext.c, &y_shift, &setup.pk.n);

        let r_aff = random_below(&setup.pk.n, rng);
        let c_1 = multi_exp(
            &[&c_shifted, &setup.pk.y, &setup.pk.h],
            &[&a, &alpha_prime, &r_aff],
            &setup.pk.n,
        );

        let alpha_mod_q = Integer::from(&alpha_prime % &q);
        let alpha = if alpha_mod_q == 0 {
            Integer::new()
        } else {
            Integer::from(&q - &alpha_mod_q)
        };

        let q_bits = q.significant_bits();
        let b1_bits = q_bits;
        let b2_bits = 2 * q_bits + 2 * setup.s + setup.t;

        let proof_aff = ZkJlAffProof::prove(
            &setup.pk,
            &c_shifted,
            &c_1,
            &a,
            &alpha_prime,
            &r_aff,
            b1_bits,
            b2_bits,
            rng,
        );

        let msg = JlMtaReceiverMsg {
            ciphertext: JlCiphertext { c: c_1 },
            proof_aff,
        };

        let alpha_bytes = alpha.to_digits::<u8>(Order::Msf);

        Ok((msg, alpha_bytes))
    }

    fn sender_decrypt(
        setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        receiver_msg: &Self::ReceiverMsg,
    ) -> Result<Vec<u8>, Self::Error> {
        let q = Integer::from_digits(q_bytes, Order::Msf);

        let ct = crate::enc_dec::encrypt_with_randomness(&setup.pk, &state.plaintext, &state.nonce);
        let shift = Integer::from(&q << (setup.s + setup.t));
        let y_shift = pow_mod(&setup.pk.y, &shift, &setup.pk.n);
        let c_shifted = mul_mod(&ct.c, &y_shift, &setup.pk.n);

        if !receiver_msg
            .proof_aff
            .verify(&setup.pk, &c_shifted, &receiver_msg.ciphertext.c)
        {
            return Err(JlMtaError::ProofVerificationFailed("ZkJlAffProof"));
        }

        let plaintext = decrypt(&setup.sk, &setup.pk, &receiver_msg.ciphertext);
        let beta = Integer::from(&plaintext % &q);

        Ok(beta.to_digits::<u8>(Order::Msf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_params;

    #[test]
    fn mta_correctness_small() {
        let mut rng = rand::thread_rng();

        let q_bits = 8u32;
        let k = 128u32;
        let (pk, sk) = generate_keypair_with_params(256, k, &mut rng);

        let q = Integer::from(1) << q_bits;

        let a = Integer::from(10u32);
        let b = Integer::from(11u32);
        let ab_mod_q = mul_mod(&a, &b, &q);

        let sender = JlMtaSender::new(a);
        let receiver = JlMtaReceiver::new(b);

        let (recv_msg, _r_b) = mta_receiver_step1(&receiver, &pk, &mut rng);
        let (send_msg, sender_out) = mta_sender_step(&sender, &pk, &recv_msg, &q, &mut rng);
        let receiver_out = mta_receiver_step2(&sk, &pk, &send_msg, &q);

        let sum = Integer::from(&sender_out.alpha + &receiver_out.beta) % &q;
        assert_eq!(
            sum, ab_mod_q,
            "MtA failed: alpha={}, beta={}, a*b mod q={}",
            sender_out.alpha, receiver_out.beta, ab_mod_q
        );
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn mta_with_random_shares() {
        let mut rng = rand::thread_rng();

        let q_bits = 16u32;
        let k = 160u32;
        let (pk, sk) = generate_keypair_with_params(256, k, &mut rng);

        let q = Integer::from(1) << q_bits;

        let a = random_below(&q, &mut rng);
        let b = random_below(&q, &mut rng);
        let ab_mod_q = mul_mod(&a, &b, &q);

        let sender = JlMtaSender::new(a);
        let receiver = JlMtaReceiver::new(b);

        let (recv_msg, _r_b) = mta_receiver_step1(&receiver, &pk, &mut rng);
        let (send_msg, sender_out) = mta_sender_step(&sender, &pk, &recv_msg, &q, &mut rng);
        let receiver_out = mta_receiver_step2(&sk, &pk, &send_msg, &q);

        let sum = Integer::from(&sender_out.alpha + &receiver_out.beta) % &q;
        assert_eq!(sum, ab_mod_q);
    }

    #[test]
    fn jl_mta_trait_correctness() {
        let mut rng = rand::thread_rng();

        let q_bits = 8u32;
        let k = 128u32;
        let (pk, sk) = generate_keypair_with_params(256, k, &mut rng);
        let (pk0, _sk0) = generate_keypair_with_params(256, k, &mut rng);

        let q = Integer::from(1) << q_bits;
        let q_bytes = q.to_digits::<u8>(Order::Msf);

        let setup = JlMtaSetup {
            pk: pk.clone(),
            pk0: pk0.clone(),
            sk: sk.clone(),
            s: 40,
            t: 40,
        };

        let b = Integer::from(11u32);
        let b_bytes = b.to_digits::<u8>(Order::Msf);

        let a = Integer::from(10u32);
        let a_bytes = a.to_digits::<u8>(Order::Msf);

        let (sender_msg, sender_state) =
            JlMtA::sender_encrypt(&setup, &b_bytes, &q_bytes, &mut rng)
                .expect("sender_encrypt should succeed");

        let (receiver_msg, alpha_bytes) =
            JlMtA::receiver_compute(&setup, &a_bytes, &q_bytes, &sender_msg, &mut rng)
                .expect("receiver_compute should succeed");

        let beta_bytes = JlMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
            .expect("sender_decrypt should succeed");

        let alpha = Integer::from_digits(&alpha_bytes, Order::Msf);
        let beta = Integer::from_digits(&beta_bytes, Order::Msf);
        let sum = Integer::from(&alpha + &beta) % &q;
        let expected = mul_mod(&a, &b, &q);

        assert_eq!(sum, expected, "alpha + beta must equal a * b mod q");
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn jl_mta_trait_multiple_runs() {
        let mut rng = rand::thread_rng();

        let q_bits = 8u32;
        let k = 128u32;
        let (pk, sk) = generate_keypair_with_params(256, k, &mut rng);
        let (pk0, _sk0) = generate_keypair_with_params(256, k, &mut rng);

        let q = Integer::from(1) << q_bits;
        let q_bytes = q.to_digits::<u8>(Order::Msf);

        let setup = JlMtaSetup {
            pk: pk.clone(),
            pk0: pk0.clone(),
            sk: sk.clone(),
            s: 40,
            t: 40,
        };

        let test_pairs: &[(u32, u32)] = &[(5, 7), (100, 200), (1, 255)];

        for &(a_val, b_val) in test_pairs {
            let a = Integer::from(a_val);
            let b = Integer::from(b_val);

            let (sender_msg, sender_state) =
                JlMtA::sender_encrypt(&setup, &b.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                    .expect("sender_encrypt");

            let (receiver_msg, alpha_bytes) = JlMtA::receiver_compute(
                &setup,
                &a.to_digits::<u8>(Order::Msf),
                &q_bytes,
                &sender_msg,
                &mut rng,
            )
            .expect("receiver_compute");

            let beta_bytes = JlMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
                .expect("sender_decrypt");

            let alpha = Integer::from_digits(&alpha_bytes, Order::Msf);
            let beta = Integer::from_digits(&beta_bytes, Order::Msf);
            let sum = Integer::from(&alpha + &beta) % &q;
            let expected = mul_mod(&a, &b, &q);

            assert_eq!(
                sum, expected,
                "MtA trait correctness must hold for a={a_val}, b={b_val}"
            );
        }
    }
}
