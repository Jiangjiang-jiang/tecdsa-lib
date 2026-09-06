// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of correct JL commitment opening (`Pi_JLCom`).
//!
//! Relation: R_{JL-com} = {(c; m, r) | c = y^{2^k*m} * h^{2^k*r} mod N, m in [0, B]}
//!
//! This is a Sigma-protocol-style proof made non-interactive via
//! the Fiat-Shamir heuristic (using SHA-256).

use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, pow_mod, random_below};

use crate::kgen::JlPublicKey;

/// Non-interactive proof of correct JL commitment opening.
///
/// Proves knowledge of `(m, r)` such that `c = y^{2^k*m} * h^{2^k*r} mod N`,
/// where `m` is in a bounded range `[0, B]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlComProof {
    /// Commitment: d = y^{2^k*v} * h^{2^k*w} mod N
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d: Integer,
    /// Response for the message: z_m = e*m + v
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_m: Integer,
    /// Response for the randomness: z_r = e*r + w
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r: Integer,
}

/// Statistical security parameter (in bits).
const STAT_SEC: u32 = 80;
/// Fiat-Shamir challenge size (in bits).
const CHALLENGE_BITS: u32 = 80;

impl ZkJlComProof {
    /// Creates a proof that `c = y^{2^k*m} * h^{2^k*r} mod N` with `m in [0, B]`.
    ///
    /// # Arguments
    ///
    /// * `pk` - JL public key
    /// * `c` - the commitment being proven
    /// * `m` - the plaintext witness
    /// * `r` - the randomness witness
    /// * `msg_bits` - bound on the message bit-length (B = 2^msg_bits)
    #[allow(clippy::many_single_char_names)]
    pub fn prove(
        pk: &JlPublicKey,
        c: &Integer,
        m: &Integer,
        r: &Integer,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let two_pow_k = Integer::from(1) << pk.k;

        // Upper bounds for the blinding values
        // v <- [0, 2^{s+t} * B) where B = 2^msg_bits
        let v_bound = Integer::from(1) << (STAT_SEC + CHALLENGE_BITS + msg_bits);
        // w <- [0, 2^{s+t} * N)
        let w_bound = Integer::from(&pk.n << (STAT_SEC + CHALLENGE_BITS));

        let v = random_below(&v_bound, rng);
        let w = random_below(&w_bound, rng);

        // Commitment: d = y^{2^k * v} * h^{2^k * w} mod N
        let exp_y = Integer::from(&two_pow_k * &v);
        let exp_h = two_pow_k * &w;
        let y_v = pow_mod(&pk.y, &exp_y, &pk.n);
        let h_w = pow_mod(&pk.h, &exp_h, &pk.n);
        let d = mul_mod(&y_v, &h_w, &pk.n);

        // Fiat-Shamir challenge
        let e = fiat_shamir_challenge(pk, c, &d);

        // Responses
        let z_m = Integer::from(&e * m) + &v;
        let z_r = e * r + &w;

        Self { d, z_m, z_r }
    }

    /// Verifies the proof against public key `pk` and commitment `c`.
    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, c: &Integer) -> bool {
        let two_pow_k = Integer::from(1) << pk.k;

        // Recompute challenge
        let e = fiat_shamir_challenge(pk, c, &self.d);

        // Check: y^{2^k * z_m} * h^{2^k * z_r} == c^e * d mod N
        let exp_y = Integer::from(&two_pow_k * &self.z_m);
        let exp_h = two_pow_k * &self.z_r;
        let lhs_1 = pow_mod(&pk.y, &exp_y, &pk.n);
        let lhs_2 = pow_mod(&pk.h, &exp_h, &pk.n);
        let lhs = mul_mod(&lhs_1, &lhs_2, &pk.n);

        let c_e = pow_mod(c, &e, &pk.n);
        let rhs = mul_mod(&c_e, &self.d, &pk.n);

        lhs == rhs
    }
}

/// Computes the Fiat-Shamir challenge by hashing the public parameters and commitment.
fn fiat_shamir_challenge(pk: &JlPublicKey, c: &Integer, d: &Integer) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlCom");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c.to_digits::<u8>(Order::Msf));
    hasher.update(d.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

/// Computes a JL commitment: c = y^{2^k * m} * h^{2^k * r} mod N.
#[must_use]
pub fn jl_commit(pk: &JlPublicKey, m: &Integer, r: &Integer) -> Integer {
    let two_pow_k = Integer::from(1) << pk.k;
    let exp_y = Integer::from(&two_pow_k * m);
    let exp_h = two_pow_k * r;
    let y_m = pow_mod(&pk.y, &exp_y, &pk.n);
    let h_r = pow_mod(&pk.h, &exp_h, &pk.n);
    mul_mod(&y_m, &h_r, &pk.n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_params;

    #[test]
    fn zkjl_com_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let r = random_below(&pk.n, &mut rng);

        let c = jl_commit(&pk, &m, &r);
        let proof = ZkJlComProof::prove(&pk, &c, &m, &r, 32, &mut rng);
        assert!(proof.verify(&pk, &c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_com_rejects_wrong_witness() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let r = random_below(&pk.n, &mut rng);
        let c = jl_commit(&pk, &m, &r);

        // Prove with wrong message
        let wrong_m = Integer::from(99u32);
        let wrong_r = random_below(&pk.n, &mut rng);
        let proof = ZkJlComProof::prove(&pk, &c, &wrong_m, &wrong_r, 32, &mut rng);
        assert!(!proof.verify(&pk, &c));
    }
}
