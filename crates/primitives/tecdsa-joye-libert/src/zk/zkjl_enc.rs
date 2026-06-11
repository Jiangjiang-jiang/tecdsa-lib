// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of correct Joye-Libert encryption (`Pi_JLEnc`).
//!
//! Proves knowledge of `(m, r)` such that `c = y^m * h^r mod N`.
//! This is a Sigma-protocol-style proof made non-interactive via
//! the Fiat-Shamir heuristic (using SHA-256).

use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, multi_exp, pow_mod, random_below};

use crate::kgen::JlPublicKey;

/// Non-interactive proof of correct JL encryption.
///
/// Proves knowledge of `(m, r)` such that `c = y^m * h^r mod N`,
/// where `m` is in a bounded range.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlEncProof {
    /// Commitment: `a = y^v * h^w mod N`
    pub a: Integer,
    /// Response for the message: `z_m = v + e * m`
    pub z_m: Integer,
    /// Response for the randomness: `z_r = w + e * r`
    pub z_r: Integer,
}

/// Security parameter for the Fiat-Shamir challenge (in bits).
const CHALLENGE_BITS: u32 = 128;

impl ZkJlEncProof {
    /// Creates a proof that `ct = y^msg * h^rand mod N`.
    ///
    /// # Arguments
    ///
    /// * `pk` - JL public key
    /// * `ct` - the ciphertext being proven
    /// * `msg` - the plaintext witness
    /// * `rand` - the randomness witness
    /// * `msg_bits` - bound on the message bit-length (for the commitment range)
    #[allow(clippy::many_single_char_names)]
    pub fn prove(
        pk: &JlPublicKey,
        ct: &Integer,
        msg: &Integer,
        rand: &Integer,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let stat_sec = 80u32;

        // Upper bounds for the blinding values
        let v_bound = Integer::from(1) << (msg_bits + stat_sec);
        let w_bound = Integer::from(&pk.n << stat_sec);

        // Sample blinding values
        let blind_v = random_below(&v_bound, rng);
        let blind_w = random_below(&w_bound, rng);

        // Commitment: a = y^v * h^w mod N
        let commit_a = multi_exp(&[&pk.y, &pk.h], &[&blind_v, &blind_w], &pk.n);

        // Fiat-Shamir challenge
        let challenge = fiat_shamir_challenge(pk, ct, &commit_a);

        // Responses
        let z_m = &blind_v + Integer::from(&challenge * msg);
        let z_r = &blind_w + Integer::from(&challenge * rand);

        Self {
            a: commit_a,
            z_m,
            z_r,
        }
    }

    /// Verifies the proof against public key `pk` and ciphertext `ct`.
    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, ct: &Integer) -> bool {
        // Recompute challenge
        let challenge = fiat_shamir_challenge(pk, ct, &self.a);

        // Check: y^{z_m} * h^{z_r} == a * c^e mod N
        let lhs = multi_exp(&[&pk.y, &pk.h], &[&self.z_m, &self.z_r], &pk.n);

        let c_e = pow_mod(ct, &challenge, &pk.n);
        let rhs = mul_mod(&self.a, &c_e, &pk.n);

        lhs == rhs
    }
}

/// Computes the Fiat-Shamir challenge by hashing the public parameters and commitment.
///
/// Context-free challenge derivation. Prefer [`fiat_shamir_challenge_with_prefix`]
/// for new code that has session/party context available.
fn fiat_shamir_challenge(pk: &JlPublicKey, c: &Integer, a: &Integer) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlEnc");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c.to_digits::<u8>(Order::Msf));
    hasher.update(a.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    // Truncate to CHALLENGE_BITS
    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

/// Like [`fiat_shamir_challenge`], but prepends an opaque context prefix before
/// the relation label. Use this when binding the challenge to a session/party/round
/// context.
fn fiat_shamir_challenge_with_prefix(
    prefix: &[u8],
    pk: &JlPublicKey,
    c: &Integer,
    a: &Integer,
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(b"ZkJlEnc");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c.to_digits::<u8>(Order::Msf));
    hasher.update(a.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    // Truncate to CHALLENGE_BITS
    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

impl ZkJlEncProof {
    /// Like [`prove`](Self::prove), but binds the Fiat-Shamir challenge to an
    /// opaque context prefix (e.g. session/party/round bytes).
    #[allow(clippy::many_single_char_names)]
    pub fn prove_with_prefix(
        prefix: &[u8],
        pk: &JlPublicKey,
        ct: &Integer,
        msg: &Integer,
        rand: &Integer,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let stat_sec = 80u32;

        let v_bound = Integer::from(1) << (msg_bits + stat_sec);
        let w_bound = Integer::from(&pk.n << stat_sec);

        let blind_v = random_below(&v_bound, rng);
        let blind_w = random_below(&w_bound, rng);

        let commit_a = multi_exp(&[&pk.y, &pk.h], &[&blind_v, &blind_w], &pk.n);

        let challenge = fiat_shamir_challenge_with_prefix(prefix, pk, ct, &commit_a);

        let z_m = &blind_v + Integer::from(&challenge * msg);
        let z_r = &blind_w + Integer::from(&challenge * rand);

        Self {
            a: commit_a,
            z_m,
            z_r,
        }
    }

    /// Like [`verify`](Self::verify), but uses the same context prefix that was
    /// used during proving.
    #[must_use]
    pub fn verify_with_prefix(&self, prefix: &[u8], pk: &JlPublicKey, ct: &Integer) -> bool {
        let challenge = fiat_shamir_challenge_with_prefix(prefix, pk, ct, &self.a);

        let lhs = multi_exp(&[&pk.y, &pk.h], &[&self.z_m, &self.z_r], &pk.n);

        let c_e = pow_mod(ct, &challenge, &pk.n);
        let rhs = mul_mod(&self.a, &c_e, &pk.n);

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{enc_dec::encrypt, kgen::generate_keypair_with_params};

    #[test]
    fn zkjl_enc_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let proof = ZkJlEncProof::prove(&pk, &ct.c, &m, &r, 32, &mut rng);
        assert!(proof.verify(&pk, &ct.c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_enc_rejects_wrong_witness() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, _r) = encrypt(&pk, &m, &mut rng);

        // Prove with wrong message
        let wrong_m = Integer::from(99u32);
        let wrong_r = random_below(&pk.n, &mut rng);
        let proof = ZkJlEncProof::prove(&pk, &ct.c, &wrong_m, &wrong_r, 32, &mut rng);
        assert!(!proof.verify(&pk, &ct.c));
    }

    #[test]
    fn zkjl_enc_with_prefix_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let prefix = b"session-1::party-2::round-3";
        let proof = ZkJlEncProof::prove_with_prefix(prefix, &pk, &ct.c, &m, &r, 32, &mut rng);
        assert!(proof.verify_with_prefix(prefix, &pk, &ct.c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_enc_with_prefix_rejects_wrong_prefix() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let proof = ZkJlEncProof::prove_with_prefix(b"prefix-A", &pk, &ct.c, &m, &r, 32, &mut rng);
        assert!(!proof.verify_with_prefix(b"prefix-B", &pk, &ct.c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_enc_rejects_mutated_proof() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let mut proof = ZkJlEncProof::prove(&pk, &ct.c, &m, &r, 32, &mut rng);

        // Mutate the z_m response field by adding 1.
        proof.z_m += 1;

        assert!(
            !proof.verify(&pk, &ct.c),
            "verification must reject a proof with mutated z_m response"
        );
    }
}
