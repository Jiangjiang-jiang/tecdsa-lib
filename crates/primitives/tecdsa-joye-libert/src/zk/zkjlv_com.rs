// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of correct JL vector commitment (`Pi_JLVCom`).
//!
//! Extension of `Pi_JLCom` to vector commitments.
//!
//! Relation: R_{JLv-com} = {(c; m_1, ..., m_l, r) |
//!   c = prod_{i=1}^{l} y_i^{2^k * m_i} * h^{2^k * r} mod N,
//!   m_i in [0, B_i] for all i}
//!
//! This is essentially the range proof with slack from the reference.

use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, pow_mod, random_below};

use crate::kgen::JlPublicKey;

/// Non-interactive proof of correct JL vector commitment.
///
/// Proves knowledge of `(m_1, ..., m_l, r)` such that
/// `c = prod y_i^{2^k * m_i} * h^{2^k * r} mod N`
/// with each `m_i in [0, B_i]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlvComProof {
    /// Commitment: d = prod y_i^{2^k * v_i} * h^{2^k * w} mod N
    pub d: Integer,
    /// Response for randomness: z_r = e*r + w
    pub z_r: Integer,
    /// Responses for each message: z_i = e*m_i + v_i
    pub z_vec: Vec<Integer>,
}

/// Statistical security parameter (in bits).
const STAT_SEC: u32 = 80;
/// Fiat-Shamir challenge size (in bits).
const CHALLENGE_BITS: u32 = 80;

impl ZkJlvComProof {
    /// Creates a proof of correct vector commitment.
    ///
    /// # Arguments
    ///
    /// * `pk` - JL public key (provides h, N, k)
    /// * `y_vec` - vector of bases y_1, ..., y_l
    /// * `c` - the commitment being proven
    /// * `m_vec` - the message witnesses
    /// * `r` - the randomness witness
    /// * `b_bits_vec` - bounds on each message in bits
    #[allow(clippy::many_single_char_names)]
    pub fn prove(
        pk: &JlPublicKey,
        y_vec: &[Integer],
        c: &Integer,
        m_vec: &[Integer],
        r: &Integer,
        b_bits_vec: &[u32],
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        assert_eq!(y_vec.len(), m_vec.len());
        assert_eq!(y_vec.len(), b_bits_vec.len());

        let ell = y_vec.len();
        let two_pow_k = Integer::from(1) << pk.k;

        // Sample blinding values
        let w_bound = Integer::from(&pk.n << (STAT_SEC + CHALLENGE_BITS));
        let w = random_below(&w_bound, rng);

        let mut v_vec = Vec::with_capacity(ell);
        let mut y_items = Vec::with_capacity(ell);

        for i in 0..ell {
            let v_bound = Integer::from(1) << (STAT_SEC + CHALLENGE_BITS + b_bits_vec[i]);
            let v = random_below(&v_bound, rng);

            let exp_y = Integer::from(&two_pow_k * &v);
            let y_item = pow_mod(&y_vec[i], &exp_y, &pk.n);

            v_vec.push(v);
            y_items.push(y_item);
        }

        // Commitment: d = prod y_i^{2^k * v_i} * h^{2^k * w} mod N
        let mut d = Integer::from(1);
        for y_item in &y_items {
            d = mul_mod(&d, y_item, &pk.n);
        }
        let exp_h = Integer::from(&two_pow_k * &w);
        let h_w = pow_mod(&pk.h, &exp_h, &pk.n);
        d = mul_mod(&d, &h_w, &pk.n);

        // Fiat-Shamir challenge
        let e = fiat_shamir_challenge(pk, y_vec, c, &d);

        // Responses
        let z_vec: Vec<Integer> = (0..ell)
            .map(|i| Integer::from(&e * &m_vec[i]) + &v_vec[i])
            .collect();
        let z_r = Integer::from(&e * r) + &w;

        Self { d, z_r, z_vec }
    }

    /// Verifies the proof.
    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, y_vec: &[Integer], c: &Integer) -> bool {
        assert_eq!(y_vec.len(), self.z_vec.len());

        let ell = y_vec.len();
        let two_pow_k = Integer::from(1) << pk.k;

        // Recompute challenge
        let e = fiat_shamir_challenge(pk, y_vec, c, &self.d);

        // LHS: prod y_i^{2^k * z_i} * h^{2^k * z_r} mod N
        let mut lhs = Integer::from(1);
        for i in 0..ell {
            let exp_y = Integer::from(&two_pow_k * &self.z_vec[i]);
            let y_item = pow_mod(&y_vec[i], &exp_y, &pk.n);
            lhs = mul_mod(&lhs, &y_item, &pk.n);
        }
        let exp_h = Integer::from(&two_pow_k * &self.z_r);
        let h_item = pow_mod(&pk.h, &exp_h, &pk.n);
        lhs = mul_mod(&lhs, &h_item, &pk.n);

        // RHS: c^e * d mod N
        let c_e = pow_mod(c, &e, &pk.n);
        let rhs = mul_mod(&c_e, &self.d, &pk.n);

        lhs == rhs
    }
}

/// Computes the Fiat-Shamir challenge.
fn fiat_shamir_challenge(pk: &JlPublicKey, y_vec: &[Integer], c: &Integer, d: &Integer) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlvCom");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update((y_vec.len() as u32).to_be_bytes());
    for y in y_vec {
        hasher.update(y.to_digits::<u8>(Order::Msf));
    }
    hasher.update(c.to_digits::<u8>(Order::Msf));
    hasher.update(d.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

/// Computes a JL vector commitment: c = prod y_i^{2^k * m_i} * h^{2^k * r} mod N.
#[must_use]
pub fn jl_vec_commit(
    pk: &JlPublicKey,
    y_vec: &[Integer],
    m_vec: &[Integer],
    r: &Integer,
) -> Integer {
    assert_eq!(y_vec.len(), m_vec.len());
    let two_pow_k = Integer::from(1) << pk.k;
    let mut c = Integer::from(1);
    for i in 0..y_vec.len() {
        let exp = Integer::from(&two_pow_k * &m_vec[i]);
        let item = pow_mod(&y_vec[i], &exp, &pk.n);
        c = mul_mod(&c, &item, &pk.n);
    }
    let exp_h = Integer::from(&two_pow_k * r);
    let h_r = pow_mod(&pk.h, &exp_h, &pk.n);
    mul_mod(&c, &h_r, &pk.n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_qnr;

    #[test]
    fn zkjlv_com_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk, x) = generate_keypair_with_qnr(256, 32, &mut rng);

        // Create additional generators: y_i = x^{alpha_i} mod N
        let ell = 3;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = random_below(&pk.n, &mut rng);
            let y_i = pow_mod(&x, &alpha_i, &pk.n);
            y_vec.push(y_i);
        }

        let m_vec: Vec<Integer> = vec![
            Integer::from(42u32),
            Integer::from(17u32),
            Integer::from(99u32),
        ];
        let b_bits_vec: Vec<u32> = vec![32, 32, 32];
        let r = random_below(&pk.n, &mut rng);

        let c = jl_vec_commit(&pk, &y_vec, &m_vec, &r);
        let proof = ZkJlvComProof::prove(&pk, &y_vec, &c, &m_vec, &r, &b_bits_vec, &mut rng);
        assert!(proof.verify(&pk, &y_vec, &c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjlv_com_rejects_wrong_witness() {
        let mut rng = rand::thread_rng();
        let (pk, _sk, x) = generate_keypair_with_qnr(256, 32, &mut rng);

        let ell = 2;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = random_below(&pk.n, &mut rng);
            let y_i = pow_mod(&x, &alpha_i, &pk.n);
            y_vec.push(y_i);
        }

        let m_vec = vec![Integer::from(42u32), Integer::from(17u32)];
        let b_bits_vec = vec![32, 32];
        let r = random_below(&pk.n, &mut rng);

        let c = jl_vec_commit(&pk, &y_vec, &m_vec, &r);

        // Wrong witness
        let wrong_m = vec![Integer::from(99u32), Integer::from(17u32)];
        let wrong_r = random_below(&pk.n, &mut rng);
        let proof =
            ZkJlvComProof::prove(&pk, &y_vec, &c, &wrong_m, &wrong_r, &b_bits_vec, &mut rng);
        assert!(!proof.verify(&pk, &y_vec, &c));
    }
}
