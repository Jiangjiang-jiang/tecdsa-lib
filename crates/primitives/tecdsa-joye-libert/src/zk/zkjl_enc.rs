// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of correct Joye-Libert encryption (`Pi_JLEnc`).
//!
//! Proves knowledge of `(m, r)` such that `c = y^m * h^r mod N`.
//! This is a Sigma-protocol-style proof made non-interactive via
//! the Fiat-Shamir heuristic (using SHA-256).

use crate::kgen::JlPublicKey;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Non-interactive proof of correct JL encryption.
///
/// Proves knowledge of `(m, r)` such that `c = y^m * h^r mod N`,
/// where `m` is in a bounded range.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlEncProof {
    /// Commitment: `a = y^v * h^w mod N`
    pub a: BigUint,
    /// Response for the message: `z_m = v + e * m`
    pub z_m: BigUint,
    /// Response for the randomness: `z_r = w + e * r`
    pub z_r: BigUint,
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
        ct: &BigUint,
        msg: &BigUint,
        rand: &BigUint,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let stat_sec = 80u32;

        // Upper bounds for the blinding values
        let v_bound = BigUint::one() << (msg_bits + stat_sec);
        let w_bound = &pk.n << stat_sec;

        // Sample blinding values
        let blind_v = rng.gen_biguint_below(&v_bound);
        let blind_w = rng.gen_biguint_below(&w_bound);

        // Commitment: a = y^v * h^w mod N
        let y_v = pk.y.modpow(&blind_v, &pk.n);
        let h_w = pk.h.modpow(&blind_w, &pk.n);
        let commit_a = (&y_v * &h_w) % &pk.n;

        // Fiat-Shamir challenge
        let challenge = fiat_shamir_challenge(pk, ct, &commit_a);

        // Responses
        let z_m = &blind_v + &challenge * msg;
        let z_r = &blind_w + &challenge * rand;

        Self {
            a: commit_a,
            z_m,
            z_r,
        }
    }

    /// Verifies the proof against public key `pk` and ciphertext `ct`.
    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, ct: &BigUint) -> bool {
        // Recompute challenge
        let challenge = fiat_shamir_challenge(pk, ct, &self.a);

        // Check: y^{z_m} * h^{z_r} == a * c^e mod N
        let lhs_1 = pk.y.modpow(&self.z_m, &pk.n);
        let lhs_2 = pk.h.modpow(&self.z_r, &pk.n);
        let lhs = (&lhs_1 * &lhs_2) % &pk.n;

        let c_e = ct.modpow(&challenge, &pk.n);
        let rhs = (&self.a * &c_e) % &pk.n;

        lhs == rhs
    }
}

/// Computes the Fiat-Shamir challenge by hashing the public parameters and commitment.
///
/// Context-free challenge derivation. Prefer [`fiat_shamir_challenge_with_prefix`]
/// for new code that has session/party context available.
fn fiat_shamir_challenge(pk: &JlPublicKey, c: &BigUint, a: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlEnc");
    hasher.update(pk.n.to_bytes_be());
    hasher.update(pk.y.to_bytes_be());
    hasher.update(pk.h.to_bytes_be());
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c.to_bytes_be());
    hasher.update(a.to_bytes_be());
    let hash = hasher.finalize();

    // Truncate to CHALLENGE_BITS
    let full = BigUint::from_bytes_be(&hash);
    let mask = (BigUint::one() << CHALLENGE_BITS) - BigUint::one();
    full & mask
}

/// Like [`fiat_shamir_challenge`], but prepends an opaque context prefix before
/// the relation label. Use this when binding the challenge to a session/party/round
/// context.
fn fiat_shamir_challenge_with_prefix(
    prefix: &[u8],
    pk: &JlPublicKey,
    c: &BigUint,
    a: &BigUint,
) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(b"ZkJlEnc");
    hasher.update(pk.n.to_bytes_be());
    hasher.update(pk.y.to_bytes_be());
    hasher.update(pk.h.to_bytes_be());
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c.to_bytes_be());
    hasher.update(a.to_bytes_be());
    let hash = hasher.finalize();

    // Truncate to CHALLENGE_BITS
    let full = BigUint::from_bytes_be(&hash);
    let mask = (BigUint::one() << CHALLENGE_BITS) - BigUint::one();
    full & mask
}

impl ZkJlEncProof {
    /// Like [`prove`](Self::prove), but binds the Fiat-Shamir challenge to an
    /// opaque context prefix (e.g. session/party/round bytes).
    #[allow(clippy::many_single_char_names)]
    pub fn prove_with_prefix(
        prefix: &[u8],
        pk: &JlPublicKey,
        ct: &BigUint,
        msg: &BigUint,
        rand: &BigUint,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let stat_sec = 80u32;

        let v_bound = BigUint::one() << (msg_bits + stat_sec);
        let w_bound = &pk.n << stat_sec;

        let blind_v = rng.gen_biguint_below(&v_bound);
        let blind_w = rng.gen_biguint_below(&w_bound);

        let y_v = pk.y.modpow(&blind_v, &pk.n);
        let h_w = pk.h.modpow(&blind_w, &pk.n);
        let commit_a = (&y_v * &h_w) % &pk.n;

        let challenge = fiat_shamir_challenge_with_prefix(prefix, pk, ct, &commit_a);

        let z_m = &blind_v + &challenge * msg;
        let z_r = &blind_w + &challenge * rand;

        Self {
            a: commit_a,
            z_m,
            z_r,
        }
    }

    /// Like [`verify`](Self::verify), but uses the same context prefix that was
    /// used during proving.
    #[must_use]
    pub fn verify_with_prefix(&self, prefix: &[u8], pk: &JlPublicKey, ct: &BigUint) -> bool {
        let challenge = fiat_shamir_challenge_with_prefix(prefix, pk, ct, &self.a);

        let lhs_1 = pk.y.modpow(&self.z_m, &pk.n);
        let lhs_2 = pk.h.modpow(&self.z_r, &pk.n);
        let lhs = (&lhs_1 * &lhs_2) % &pk.n;

        let c_e = ct.modpow(&challenge, &pk.n);
        let rhs = (&self.a * &c_e) % &pk.n;

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enc_dec::encrypt;
    use crate::kgen::generate_keypair_with_params;

    #[test]
    fn zkjl_enc_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = BigUint::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let proof = ZkJlEncProof::prove(&pk, &ct.c, &m, &r, 32, &mut rng);
        assert!(proof.verify(&pk, &ct.c));
    }

    #[test]
    fn zkjl_enc_rejects_wrong_witness() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = BigUint::from(42u32);
        let (ct, _r) = encrypt(&pk, &m, &mut rng);

        // Prove with wrong message
        let wrong_m = BigUint::from(99u32);
        let wrong_r = rng.gen_biguint_below(&pk.n);
        let proof = ZkJlEncProof::prove(&pk, &ct.c, &wrong_m, &wrong_r, 32, &mut rng);
        assert!(!proof.verify(&pk, &ct.c));
    }

    #[test]
    fn zkjl_enc_with_prefix_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = BigUint::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let prefix = b"session-1::party-2::round-3";
        let proof = ZkJlEncProof::prove_with_prefix(prefix, &pk, &ct.c, &m, &r, 32, &mut rng);
        assert!(proof.verify_with_prefix(prefix, &pk, &ct.c));
    }

    #[test]
    fn zkjl_enc_with_prefix_rejects_wrong_prefix() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = BigUint::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let proof = ZkJlEncProof::prove_with_prefix(b"prefix-A", &pk, &ct.c, &m, &r, 32, &mut rng);
        assert!(!proof.verify_with_prefix(b"prefix-B", &pk, &ct.c));
    }

    #[test]
    fn zkjl_enc_rejects_mutated_proof() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = BigUint::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let mut proof = ZkJlEncProof::prove(&pk, &ct.c, &m, &r, 32, &mut rng);

        // Mutate the z_m response field by adding 1.
        proof.z_m += BigUint::from(1u32);

        assert!(
            !proof.verify(&pk, &ct.c),
            "verification must reject a proof with mutated z_m response"
        );
    }
}
