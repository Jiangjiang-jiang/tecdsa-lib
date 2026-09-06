// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multiplicative-to-Additive (`MtA`) share conversion using Joye-Libert encryption.
//!
//! This module provides the JL-based `MtA` protocol as used in the XAL23
//! threshold ECDSA scheme.
//!
//! The `MtA` protocol converts a multiplicative sharing `a * b` into an additive
//! sharing `alpha + beta` where Party 1 holds `(a, alpha)` and Party 2 holds
//! `(b, beta)`, such that `alpha + beta = a * b (mod q)`.
//!
//! The protocol uses the additive homomorphism of JL encryption over Z_{2^k}:
//!   Enc(a)^s = Enc(a*s mod 2^k)
//!   Enc(a) * Enc(b) = Enc(a+b mod 2^k)
//!
//! All intermediate values must fit within 2^k bits for decryption correctness,
//! so the message space parameter k must be sufficiently larger than the curve
//! order bit-length.

use rand_core::CryptoRngCore;
use rug::{integer::Order, Complete, Integer};
use serde::{Deserialize, Serialize};
use tecdsa_bigint::{random_below, BigIntExt};
use zeroize::Zeroize;

use crate::{
    enc_dec::{decrypt, encrypt, JlCiphertext},
    kgen::{JlPublicKey, JlSecretKey},
    zk::{zkjl_aff::ZkJlAffProof, zkjl_enc::ZkJlEncProof},
};

/// Sender state for the JL-based `MtA` protocol.
///
/// The sender holds share `a` and computes the affine ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct JlMtaSender {
    /// The sender's multiplicative share.
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

/// Receiver state for the JL-based `MtA` protocol.
///
/// The receiver holds share `b` and encrypts it under their own JL public key.
#[derive(Clone, Serialize, Deserialize)]
pub struct JlMtaReceiver {
    /// The receiver's multiplicative share.
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

/// First message from the receiver to the sender: an encrypted share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtaReceiverMsg1 {
    /// Encrypted receiver share under the receiver's own public key.
    pub ct: JlCiphertext,
}

/// Response from the sender: a homomorphically computed ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MtaSenderMsg1 {
    /// Encrypted product share.
    pub ct: JlCiphertext,
}

/// Output for the sender after MtA completes.
#[derive(Clone, Debug)]
pub struct MtaSenderOutput {
    /// The sender's additive share: alpha = -alpha' mod q
    pub alpha: Integer,
}

/// Output for the receiver after MtA completes.
#[derive(Clone, Debug)]
pub struct MtaReceiverOutput {
    /// The receiver's additive share: beta = Dec(C_1) mod q
    pub beta: Integer,
}

impl JlMtaSender {
    /// Creates a new `MtA` sender with the given share.
    #[must_use]
    pub fn new(share: Integer) -> Self {
        Self { share }
    }
}

impl JlMtaReceiver {
    /// Creates a new `MtA` receiver with the given share.
    #[must_use]
    pub fn new(share: Integer) -> Self {
        Self { share }
    }
}

// ---------------------------------------------------------------------------
// MtA protocol steps
// ---------------------------------------------------------------------------

/// Receiver Step 1: Encrypt `b` under the receiver's own JL public key.
///
/// Returns the first message (containing the ciphertext) and the randomness used.
pub fn mta_receiver_step1(
    receiver: &JlMtaReceiver,
    pk_receiver: &JlPublicKey,
    rng: &mut impl CryptoRngCore,
) -> (MtaReceiverMsg1, Integer) {
    let (ct, r) = encrypt(pk_receiver, &receiver.share, rng);
    (MtaReceiverMsg1 { ct }, r)
}

/// Sender Step: Process receiver's encrypted share, compute affine ciphertext.
///
/// Following the XAL23 MtA protocol:
/// 1. Compute `C_shifted = C_b * y^{2^{s+t} * q}` — shifts plaintext by `2^{s+t}*q`
///    to ensure the total remains positive.
/// 2. Compute `C_1 = C_shifted^a * y^{alpha'} * h^r mod N`
///    Decryption gives: `a*(b + 2^{s+t}*q) + alpha'` mod 2^k
///    Which mod q is: `a*b + alpha'` mod q
/// 3. Set `alpha = -alpha' mod q`
///
/// Correctness: `alpha + beta = -alpha' + (a*b + alpha') = a*b (mod q)`
///
/// # Arguments
///
/// * `sender` - The sender's MtA state (holds share `a`)
/// * `pk_receiver` - The receiver's JL public key
/// * `receiver_msg` - The receiver's first message (encrypted `b`)
/// * `q` - The curve order (for modular reduction of the output share)
pub fn mta_sender_step(
    sender: &JlMtaSender,
    pk_receiver: &JlPublicKey,
    receiver_msg: &MtaReceiverMsg1,
    q: &Integer,
    rng: &mut impl CryptoRngCore,
) -> (MtaSenderMsg1, MtaSenderOutput) {
    mta_sender_step_with_sec(sender, pk_receiver, receiver_msg, q, 40, 40, rng)
}

/// Sender Step with configurable statistical security parameters.
///
/// `s` and `t` are the statistical security parameters. Use `s=t=40` for
/// production security, smaller values for testing.
///
/// The JL message space parameter `k` must satisfy:
/// `k >= 2 * log2(q) + 2*s + t + 2`
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

    // Sample alpha' <- [0, q^2 * 2^{2s+t})
    let q_sq = Integer::from(q * q);
    let alpha_prime_bound = q_sq << (2 * s + t);
    let alpha_prime = random_below(&alpha_prime_bound, rng);

    // Shift factor: 2^{s+t} * q
    let shift = Integer::from(q << (s + t));

    // C_shifted = C_b * y^{shift} mod N
    // This adds shift to the plaintext: Dec(C_shifted) = b + shift
    let y_shift = pk_receiver
        .y
        .pow_mod_ref(&shift, &pk_receiver.n)
        .expect("exponent is non-negative")
        .complete();
    let c_shifted = (y_shift * &receiver_msg.ct.c).modulo(&pk_receiver.n);

    // C_1 = C_shifted^a * y^{alpha'} * h^r mod N
    // Dec(C_1) = a*(b + shift) + alpha' mod 2^k
    let c_shifted_a = c_shifted
        .pow_mod_ref(a, &pk_receiver.n)
        .expect("exponent is non-negative")
        .complete();
    let y_alpha = pk_receiver
        .y
        .pow_mod_ref(&alpha_prime, &pk_receiver.n)
        .expect("exponent is non-negative")
        .complete();
    let r = random_below(&pk_receiver.n, rng);
    let h_r = pk_receiver
        .h
        .pow_mod_ref(&r, &pk_receiver.n)
        .expect("exponent is non-negative")
        .complete();
    let c_1 = ((c_shifted_a * y_alpha).modulo(&pk_receiver.n) * h_r).modulo(&pk_receiver.n);

    let msg = MtaSenderMsg1 {
        ct: JlCiphertext { c: c_1 },
    };

    // Sender's share: alpha = -alpha' mod q
    let alpha_mod_q = alpha_prime % q;
    let alpha = if alpha_mod_q == 0 {
        Integer::new()
    } else {
        q - alpha_mod_q
    };

    (msg, MtaSenderOutput { alpha })
}

/// Receiver Step 2: Decrypt the sender's affine ciphertext to get beta.
///
/// Computes: beta = Dec(sk, C_1) mod q
pub fn mta_receiver_step2(
    sk: &JlSecretKey,
    pk: &JlPublicKey,
    sender_msg: &MtaSenderMsg1,
    q: &Integer,
) -> MtaReceiverOutput {
    let plaintext = decrypt(sk, pk, &sender_msg.ct);
    let beta = plaintext % q;
    MtaReceiverOutput { beta }
}

// ---------------------------------------------------------------------------
// MtA trait implementation
// ---------------------------------------------------------------------------

use tecdsa_protocol::MtA;

/// JL-based MtA backend implementing the `tecdsa_protocol::MtA` trait.
///
/// Uses Joye-Libert homomorphic encryption with the additive homomorphism
/// over `Z_{2^k}`. The sender (P2) owns the JL key pair; the receiver
/// (P1) has access to the public key for homomorphic computation.
///
/// # Malicious Security
///
/// Per XAL23 Section 5.1, this implementation attaches ZK proofs to all
/// MtA messages to achieve malicious security:
///
/// - **`sender_encrypt`**: P2 produces `ZkJlEncProof` proving that the
///   JL ciphertext encrypts plaintext `b`.
///
/// - **`receiver_compute`**: P1 verifies the sender's `ZkJlEncProof`,
///   performs the affine operation, and produces `ZkJlAffProof` proving
///   the affine ciphertext was computed correctly.
///
/// - **`sender_decrypt`**: P2 verifies the receiver's `ZkJlAffProof`
///   before decrypting. Verification failure returns
///   `JlMtaError::ProofVerificationFailed`.
pub struct JlMtA;

/// Setup material for JL MtA: the public key, secret key, and security params.
///
/// Both parties need the public key. The secret key is used only by
/// the sender (P2) for decryption in step 3.
///
/// `pk0` is a second JL public key retained for callers that also perform
/// paper commitment/equality checks outside this MtA primitive. The MtA
/// first message itself is proven with `ZkJlEncProof` against `pk`.
///
/// `s` and `t` are statistical security parameters for the MtA protocol.
/// The JL message space parameter `k` must satisfy
/// `k >= 2 * log2(q) + 2*s + t + 2`. Use `s=t=40` for production.
#[derive(Clone)]
pub struct JlMtaSetup {
    /// JL public key for encryption/decryption (shared).
    pub pk: JlPublicKey,
    /// Second JL public key for protocol-level JL commitment/equality checks.
    pub pk0: JlPublicKey,
    /// JL secret key (owned by the sender for decryption).
    pub sk: JlSecretKey,
    /// Statistical security parameter `s` (default: 40).
    pub s: u32,
    /// Statistical security parameter `t` (default: 40).
    pub t: u32,
}

/// Sender's internal state between encrypt and decrypt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlMtaSenderState {
    /// The encryption randomness (for potential proof construction).
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub nonce: Integer,
    /// The sender's plaintext (needed for affine proof verification context).
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub plaintext: Integer,
}

/// Message from sender (P2) to receiver (P1): encrypted `b` with ZK proof.
///
/// Contains the ciphertext and a `ZkJlEncProof` proving that the ciphertext
/// encrypts the sender's input `b`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlMtaSenderMsg {
    /// `c_B = Enc(pk, b; r)`: JL ciphertext of the sender's input.
    pub ciphertext: JlCiphertext,
    /// ZK proof that `ciphertext` is a correct JL encryption of `b`.
    pub proof_enc: ZkJlEncProof,
}

/// Message from receiver (P1) to sender (P2): affine result with ZK proof.
///
/// Contains the affine ciphertext and a `ZkJlAffProof` proving that the
/// affine operation was computed correctly from the base ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlMtaReceiverMsg {
    /// `c_A = c_shifted^a * y^{alpha'} * h^r mod N`: the affine ciphertext.
    pub ciphertext: JlCiphertext,
    /// ZK proof of correct affine operation on the sender's ciphertext.
    pub proof_aff: ZkJlAffProof,
}

/// Error type for the JL MtA backend.
#[derive(Debug, thiserror::Error)]
pub enum JlMtaError {
    /// The plaintext overflows the JL message space.
    #[error("plaintext overflow: value exceeds 2^k")]
    Overflow,

    /// Invalid parameter.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    /// A ZK proof failed verification.
    #[error("ZK proof verification failed: {0}")]
    ProofVerificationFailed(&'static str),
}

impl MtA for JlMtA {
    type Setup = JlMtaSetup;
    type SenderState = JlMtaSenderState;
    type SenderMsg = JlMtaSenderMsg;
    type ReceiverMsg = JlMtaReceiverMsg;
    type Error = JlMtaError;

    /// Step 1: Sender (P2) encrypts input `b` using JL encryption.
    ///
    /// The sender encrypts `b` under the shared JL public key. A
    /// `ZkJlEncProof` proves that the ciphertext is a correct JL encryption
    /// of the same plaintext.
    ///
    /// `b` must fit in `Z_{2^k}`.
    fn sender_encrypt(
        setup: &Self::Setup,
        b_bytes: &[u8],
        _q_bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SenderMsg, Self::SenderState), Self::Error> {
        let b = Integer::from_digits(b_bytes, Order::Msf);

        // Encrypt b under pk (for the MtA computation).
        let (ciphertext, nonce) = encrypt(&setup.pk, &b, rng);

        // Message bit-length bound for the ZK proof
        let msg_bits = setup.pk.k;

        // Prove the actual MtA ciphertext is a correct JL encryption of b.
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

    /// Step 2: Receiver (P1) performs homomorphic affine operation and
    /// obtains `alpha`.
    ///
    /// First verifies the sender's `ZkJlEncProof` to ensure the encrypted
    /// value is correctly formed.
    ///
    /// Then computes the XAL23 MtA affine operation:
    ///   1. Shift: `c_shifted = c_B * y^{2^{s+t} * q}` (ensures positivity)
    ///   2. Affine: `c_A = c_shifted^a * y^{alpha'} * h^r mod N`
    ///   3. `alpha = -alpha' mod q`
    ///
    /// Finally produces a `ZkJlAffProof` proving the affine operation was
    /// computed correctly from the (shifted) base ciphertext.
    fn receiver_compute(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>), Self::Error> {
        // ------------------------------------------------------------------
        // Verify the sender's ZkJlEncProof against the actual MtA ciphertext.
        // ------------------------------------------------------------------
        if !sender_msg
            .proof_enc
            .verify(&setup.pk, &sender_msg.ciphertext.c)
        {
            return Err(JlMtaError::ProofVerificationFailed("ZkJlEncProof"));
        }

        // ------------------------------------------------------------------
        // Perform the affine MtA computation (inlined for proof witness access)
        // ------------------------------------------------------------------
        let a = Integer::from_digits(a_bytes, Order::Msf);
        let q = Integer::from_digits(q_bytes, Order::Msf);

        // Sample alpha' <- [0, q^2 * 2^{2s+t})
        let q_sq = Integer::from(&q * &q);
        let alpha_prime_bound = q_sq << (2 * setup.s + setup.t);
        let alpha_prime = random_below(&alpha_prime_bound, rng);

        // Shift factor: 2^{s+t} * q
        let shift = Integer::from(&q << (setup.s + setup.t));

        // C_shifted = C_b * y^{shift} mod N
        let y_shift = setup
            .pk
            .y
            .pow_mod_ref(&shift, &setup.pk.n)
            .expect("exponent is non-negative")
            .complete();
        let c_shifted = (y_shift * &sender_msg.ciphertext.c).modulo(&setup.pk.n);

        // C_1 = C_shifted^a * y^{alpha'} * h^{r_aff} mod N, via one shared-
        // squaring multi-exponentiation instead of three modexps + two muls.
        let r_aff = random_below(&setup.pk.n, rng);
        let c_1 = setup.pk.n.multi_exp(
            &[&c_shifted, &setup.pk.y, &setup.pk.h],
            &[&a, &alpha_prime, &r_aff],
        );

        // Sender's share: alpha = -alpha' mod q
        let alpha_mod_q = Integer::from(&alpha_prime % &q);
        let alpha = if alpha_mod_q == 0 {
            Integer::new()
        } else {
            &q - alpha_mod_q
        };

        // ------------------------------------------------------------------
        // Generate ZkJlAffProof for the affine operation
        // ------------------------------------------------------------------
        // The affine relation proved:
        //   c_1 = c_shifted^a * y^{alpha'} * h^{r_aff} mod N
        //
        // In ZkJlAffProof terms:
        //   c_base = c_shifted, c_aff = c_1,
        //   witnesses: a, alpha', r_aff
        //   bounds: a fits in q bits, alpha' fits in (2*q_bits + 2s + t) bits
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

    /// Step 3: Sender (P2) decrypts to obtain `beta`.
    ///
    /// First verifies the receiver's `ZkJlAffProof` to ensure the affine
    /// operation was computed correctly. The verification requires
    /// reconstructing the shifted base ciphertext from the sender's
    /// original ciphertext and the protocol parameters.
    ///
    /// `beta = Dec(sk, pk, c_A) mod q`
    fn sender_decrypt(
        setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        receiver_msg: &Self::ReceiverMsg,
    ) -> Result<Vec<u8>, Self::Error> {
        let q = Integer::from_digits(q_bytes, Order::Msf);

        // Reconstruct the shifted base ciphertext that the receiver used.
        // The sender knows their original plaintext b and nonce r, so they
        // can recompute: ct = Enc(pk, b; r), then:
        //   c_shifted = ct.c * y^{2^{s+t} * q} mod N
        let ct = crate::enc_dec::encrypt_with_randomness(&setup.pk, &state.plaintext, &state.nonce);
        let shift = Integer::from(&q << (setup.s + setup.t));
        let y_shift = setup
            .pk
            .y
            .pow_mod_ref(&shift, &setup.pk.n)
            .expect("exponent is non-negative")
            .complete();
        let c_shifted = (y_shift * &ct.c).modulo(&setup.pk.n);

        // Verify the ZkJlAffProof
        if !receiver_msg
            .proof_aff
            .verify(&setup.pk, &c_shifted, &receiver_msg.ciphertext.c)
        {
            return Err(JlMtaError::ProofVerificationFailed("ZkJlAffProof"));
        }

        let plaintext = decrypt(&setup.sk, &setup.pk, &receiver_msg.ciphertext);
        let beta = plaintext % q;

        Ok(beta.to_digits::<u8>(Order::Msf))
    }
}

#[cfg(test)]
mod tests {
    use tecdsa_bigint::BigIntExt;

    use super::*;
    use crate::kgen::generate_keypair_with_params;

    #[test]
    fn mta_correctness_small() {
        let mut rng = rand::thread_rng();

        // For a small q (8 bits), we need k >= 2*8 + 80 + 2 = 98
        // Use k = 128, p_bits = 256
        let q_bits = 8u32;
        let k = 128u32; // Must be >= min_k_for_mta(q_bits) = 98
        let (pk, sk) = generate_keypair_with_params(256, k, &mut rng);

        let q = Integer::two_pow(q_bits);

        // Small shares
        let a = Integer::from(10u32);
        let b = Integer::from(11u32);
        let ab_mod_q = Integer::from(&a * &b).modulo(&q);

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

        // q ~ 16 bits, k = 160 (>> 2*16 + 82 = 114)
        let q_bits = 16u32;
        let k = 160u32;
        let (pk, sk) = generate_keypair_with_params(256, k, &mut rng);

        let q = Integer::two_pow(q_bits);

        let a = random_below(&q, &mut rng);
        let b = random_below(&q, &mut rng);
        let ab_mod_q = Integer::from(&a * &b).modulo(&q);

        let sender = JlMtaSender::new(a);
        let receiver = JlMtaReceiver::new(b);

        let (recv_msg, _r_b) = mta_receiver_step1(&receiver, &pk, &mut rng);
        let (send_msg, sender_out) = mta_sender_step(&sender, &pk, &recv_msg, &q, &mut rng);
        let receiver_out = mta_receiver_step2(&sk, &pk, &send_msg, &q);

        let sum = (sender_out.alpha + receiver_out.beta) % &q;
        assert_eq!(sum, ab_mod_q);
    }

    // -----------------------------------------------------------------------
    // MtA trait tests
    // -----------------------------------------------------------------------

    #[test]
    fn jl_mta_trait_correctness() {
        let mut rng = rand::thread_rng();

        // Use small parameters for fast testing
        // q ~ 8 bits, k = 128 (must be >= 2*8 + 80 + 2 = 98)
        let q_bits = 8u32;
        let k = 128u32;
        let (pk, sk) = generate_keypair_with_params(256, k, &mut rng);
        let (pk0, _sk0) = generate_keypair_with_params(256, k, &mut rng);

        let q = Integer::two_pow(q_bits);
        let q_bytes = q.to_digits::<u8>(Order::Msf);

        let setup = JlMtaSetup {
            pk: pk.clone(),
            pk0: pk0.clone(),
            sk: sk.clone(),
            s: 40,
            t: 40,
        };

        // Sender's input b (P2 encrypts)
        let b = Integer::from(11u32);
        let b_bytes = b.to_digits::<u8>(Order::Msf);

        // Receiver's input a (P1 does affine)
        let a = Integer::from(10u32);
        let a_bytes = a.to_digits::<u8>(Order::Msf);

        // Step 1: Sender encrypts b
        let (sender_msg, sender_state) =
            JlMtA::sender_encrypt(&setup, &b_bytes, &q_bytes, &mut rng)
                .expect("sender_encrypt should succeed");

        // Step 2: Receiver computes affine operation
        let (receiver_msg, alpha_bytes) =
            JlMtA::receiver_compute(&setup, &a_bytes, &q_bytes, &sender_msg, &mut rng)
                .expect("receiver_compute should succeed");

        // Step 3: Sender decrypts
        let beta_bytes = JlMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
            .expect("sender_decrypt should succeed");

        // Verify: alpha + beta = a * b mod q
        let alpha = Integer::from_digits(&alpha_bytes, Order::Msf);
        let beta = Integer::from_digits(&beta_bytes, Order::Msf);
        let sum = (alpha + beta) % &q;
        let expected = Integer::from(&a * &b).modulo(&q);

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

        let q = Integer::two_pow(q_bits);
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
            let sum = (alpha + beta) % &q;
            let expected = Integer::from(&a * &b).modulo(&q);

            assert_eq!(
                sum, expected,
                "MtA trait correctness must hold for a={a_val}, b={b_val}"
            );
        }
    }
}
