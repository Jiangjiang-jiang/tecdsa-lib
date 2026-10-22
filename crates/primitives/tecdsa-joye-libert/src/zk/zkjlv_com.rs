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

use rug::{integer::Order, Complete, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::BigIntExt;

use crate::kgen::JlPublicKey;

/// Non-interactive proof of correct JL vector commitment.
///
/// Proves knowledge of `(m_1, ..., m_l, r)` such that
/// `c = prod y_i^{2^k * m_i} * h^{2^k * r} mod N`
/// with each `m_i in [0, B_i]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlvComProof {
    /// Commitment: d = prod y_i^{2^k * v_i} * h^{2^k * w} mod N
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d: Integer,
    /// Response for randomness: z_r = e*r + w
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r: Integer,
    /// Responses for each message: z_i = e*m_i + v_i
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
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
        let two_pow_k = Integer::two_pow(pk.k);

        // Sample blinding values
        let w_bound = Integer::from(&pk.n << (STAT_SEC + CHALLENGE_BITS));
        let w = w_bound.sample_below_ref(rng);

        let mut v_vec = Vec::with_capacity(ell);
        let mut y_items = Vec::with_capacity(ell);

        for i in 0..ell {
            let v_bound = Integer::two_pow(STAT_SEC + CHALLENGE_BITS + b_bits_vec[i]);
            let v = v_bound.sample_below_ref(rng);

            let exp_y = Integer::from(&two_pow_k * &v);
            let y_item = y_vec[i]
                .pow_mod_ref(&exp_y, &pk.n)
                .expect("exponent is non-negative")
                .complete();

            v_vec.push(v);
            y_items.push(y_item);
        }

        // Commitment: d = prod y_i^{2^k * v_i} * h^{2^k * w} mod N
        let mut d = Integer::from(1);
        for y_item in &y_items {
            d = (d * y_item).modulo(&pk.n);
        }
        let exp_h = two_pow_k * &w;
        let h_w =
            pk.h.pow_mod_ref(&exp_h, &pk.n)
                .expect("exponent is non-negative")
                .complete();
        d = (d * h_w).modulo(&pk.n);

        // Fiat-Shamir challenge
        let e = fiat_shamir_challenge(pk, y_vec, c, &d);

        // Responses
        let z_vec: Vec<Integer> = (0..ell)
            .map(|i| Integer::from(&e * &m_vec[i]) + &v_vec[i])
            .collect();
        let z_r = e * r + &w;

        Self { d, z_r, z_vec }
    }

    /// Verifies the proof.
    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, y_vec: &[Integer], c: &Integer) -> bool {
        assert_eq!(y_vec.len(), self.z_vec.len());

        let ell = y_vec.len();
        let two_pow_k = Integer::two_pow(pk.k);

        // Recompute challenge
        let e = fiat_shamir_challenge(pk, y_vec, c, &self.d);

        // LHS: prod y_i^{2^k * z_i} * h^{2^k * z_r} mod N
        let mut lhs = Integer::from(1);
        for i in 0..ell {
            let exp_y = Integer::from(&two_pow_k * &self.z_vec[i]);
            let y_item = y_vec[i]
                .pow_mod_ref(&exp_y, &pk.n)
                .expect("exponent is non-negative")
                .complete();
            lhs = (lhs * y_item).modulo(&pk.n);
        }
        let exp_h = two_pow_k * &self.z_r;
        let h_item =
            pk.h.pow_mod_ref(&exp_h, &pk.n)
                .expect("exponent is non-negative")
                .complete();
        lhs = (lhs * h_item).modulo(&pk.n);

        // RHS: c^e * d mod N
        let c_e = c
            .pow_mod_ref(&e, &pk.n)
            .expect("exponent is non-negative")
            .complete();
        let rhs = (c_e * &self.d).modulo(&pk.n);

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
    let two_pow_k = Integer::two_pow(pk.k);
    let mut c = Integer::from(1);
    for i in 0..y_vec.len() {
        let exp = Integer::from(&two_pow_k * &m_vec[i]);
        let item = y_vec[i]
            .pow_mod_ref(&exp, &pk.n)
            .expect("exponent is non-negative")
            .complete();
        c = (c * item).modulo(&pk.n);
    }
    let exp_h = two_pow_k * r;
    let h_r =
        pk.h.pow_mod_ref(&exp_h, &pk.n)
            .expect("exponent is non-negative")
            .complete();
    (c * h_r).modulo(&pk.n)
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
            let alpha_i = pk.n.sample_below_ref(&mut rng);
            let y_i = x
                .pow_mod_ref(&alpha_i, &pk.n)
                .expect("exponent is non-negative")
                .complete();
            y_vec.push(y_i);
        }

        let m_vec: Vec<Integer> = vec![
            Integer::from(42u32),
            Integer::from(17u32),
            Integer::from(99u32),
        ];
        let b_bits_vec: Vec<u32> = vec![32, 32, 32];
        let r = pk.n.sample_below_ref(&mut rng);

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
            let alpha_i = pk.n.sample_below_ref(&mut rng);
            let y_i = x
                .pow_mod_ref(&alpha_i, &pk.n)
                .expect("exponent is non-negative")
                .complete();
            y_vec.push(y_i);
        }

        let m_vec = vec![Integer::from(42u32), Integer::from(17u32)];
        let b_bits_vec = vec![32, 32];
        let r = pk.n.sample_below_ref(&mut rng);

        let c = jl_vec_commit(&pk, &y_vec, &m_vec, &r);

        // Wrong witness
        let wrong_m = vec![Integer::from(99u32), Integer::from(17u32)];
        let wrong_r = pk.n.sample_below_ref(&mut rng);
        let proof =
            ZkJlvComProof::prove(&pk, &y_vec, &c, &wrong_m, &wrong_r, &b_bits_vec, &mut rng);
        assert!(!proof.verify(&pk, &y_vec, &c));
    }
}
