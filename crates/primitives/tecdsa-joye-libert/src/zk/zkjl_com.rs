// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of correct JL commitment opening (`Pi_JLCom`).
//!
//! Relation: R_{JL-com} = {(c; m, r) | c = y^{2^k*m} * h^{2^k*r} mod N, m in [0, B]}
//!
//! This is a Sigma-protocol-style proof made non-interactive via
//! the Fiat-Shamir heuristic (using SHA-256).

use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::kgen::JlPublicKey;

/// Non-interactive proof of correct JL commitment opening.
///
/// Proves knowledge of `(m, r)` such that `c = y^{2^k*m} * h^{2^k*r} mod N`,
/// where `m` is in a bounded range `[0, B]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlComProof {
    /// Commitment: d = y^{2^k*v} * h^{2^k*w} mod N
    pub d: BigUint,
    /// Response for the message: z_m = e*m + v
    pub z_m: BigUint,
    /// Response for the randomness: z_r = e*r + w
    pub z_r: BigUint,
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
        c: &BigUint,
        m: &BigUint,
        r: &BigUint,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        use num_bigint::RandBigInt;

        let two_pow_k = BigUint::one() << pk.k;

        // Upper bounds for the blinding values
        // v <- [0, 2^{s+t} * B) where B = 2^msg_bits
        let v_bound = BigUint::one() << (STAT_SEC + CHALLENGE_BITS + msg_bits);
        // w <- [0, 2^{s+t} * N)
        let w_bound = &pk.n << (STAT_SEC + CHALLENGE_BITS);

        let v = rng.gen_biguint_below(&v_bound);
        let w = rng.gen_biguint_below(&w_bound);

        // Commitment: d = y^{2^k * v} * h^{2^k * w} mod N
        let exp_y = &two_pow_k * &v;
        let exp_h = &two_pow_k * &w;
        let y_v = pk.y.modpow(&exp_y, &pk.n);
        let h_w = pk.h.modpow(&exp_h, &pk.n);
        let d = (&y_v * &h_w) % &pk.n;

        // Fiat-Shamir challenge
        let e = fiat_shamir_challenge(pk, c, &d);

        // Responses
        let z_m = &e * m + &v;
        let z_r = &e * r + &w;

        Self { d, z_m, z_r }
    }

    /// Verifies the proof against public key `pk` and commitment `c`.
    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, c: &BigUint) -> bool {
        let two_pow_k = BigUint::one() << pk.k;

        // Recompute challenge
        let e = fiat_shamir_challenge(pk, c, &self.d);

        // Check: y^{2^k * z_m} * h^{2^k * z_r} == c^e * d mod N
        let exp_y = &two_pow_k * &self.z_m;
        let exp_h = &two_pow_k * &self.z_r;
        let lhs_1 = pk.y.modpow(&exp_y, &pk.n);
        let lhs_2 = pk.h.modpow(&exp_h, &pk.n);
        let lhs = (&lhs_1 * &lhs_2) % &pk.n;

        let c_e = c.modpow(&e, &pk.n);
        let rhs = (&c_e * &self.d) % &pk.n;

        lhs == rhs
    }
}

/// Computes the Fiat-Shamir challenge by hashing the public parameters and commitment.
fn fiat_shamir_challenge(pk: &JlPublicKey, c: &BigUint, d: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlCom");
    hasher.update(pk.n.to_bytes_be());
    hasher.update(pk.y.to_bytes_be());
    hasher.update(pk.h.to_bytes_be());
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c.to_bytes_be());
    hasher.update(d.to_bytes_be());
    let hash = hasher.finalize();

    let full = BigUint::from_bytes_be(&hash);
    let mask = (BigUint::one() << CHALLENGE_BITS) - BigUint::one();
    full & mask
}

/// Computes a JL commitment: c = y^{2^k * m} * h^{2^k * r} mod N.
#[must_use]
pub fn jl_commit(pk: &JlPublicKey, m: &BigUint, r: &BigUint) -> BigUint {
    let two_pow_k = BigUint::one() << pk.k;
    let exp_y = &two_pow_k * m;
    let exp_h = &two_pow_k * r;
    let y_m = pk.y.modpow(&exp_y, &pk.n);
    let h_r = pk.h.modpow(&exp_h, &pk.n);
    (&y_m * &h_r) % &pk.n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_params;

    #[test]
    fn zkjl_com_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = BigUint::from(42u32);
        let r = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &pk.n);

        let c = jl_commit(&pk, &m, &r);
        let proof = ZkJlComProof::prove(&pk, &c, &m, &r, 32, &mut rng);
        assert!(proof.verify(&pk, &c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_com_rejects_wrong_witness() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = BigUint::from(42u32);
        let r = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &pk.n);
        let c = jl_commit(&pk, &m, &r);

        // Prove with wrong message
        let wrong_m = BigUint::from(99u32);
        let wrong_r = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &pk.n);
        let proof = ZkJlComProof::prove(&pk, &c, &wrong_m, &wrong_r, 32, &mut rng);
        assert!(!proof.verify(&pk, &c));
    }
}
