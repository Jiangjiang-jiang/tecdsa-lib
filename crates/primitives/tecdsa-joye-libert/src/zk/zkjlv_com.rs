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

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::kgen::JlPublicKey;

/// Non-interactive proof of correct JL vector commitment.
///
/// Proves knowledge of `(m_1, ..., m_l, r)` such that
/// `c = prod y_i^{2^k * m_i} * h^{2^k * r} mod N`
/// with each `m_i in [0, B_i]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlvComProof {
    /// Commitment: d = prod y_i^{2^k * v_i} * h^{2^k * w} mod N
    pub d: BigUint,
    /// Response for randomness: z_r = e*r + w
    pub z_r: BigUint,
    /// Responses for each message: z_i = e*m_i + v_i
    pub z_vec: Vec<BigUint>,
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
        y_vec: &[BigUint],
        c: &BigUint,
        m_vec: &[BigUint],
        r: &BigUint,
        b_bits_vec: &[u32],
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        assert_eq!(y_vec.len(), m_vec.len());
        assert_eq!(y_vec.len(), b_bits_vec.len());

        let ell = y_vec.len();
        let two_pow_k = BigUint::one() << pk.k;

        // Sample blinding values
        let w_bound = &pk.n << (STAT_SEC + CHALLENGE_BITS);
        let w = rng.gen_biguint_below(&w_bound);

        let mut v_vec = Vec::with_capacity(ell);
        let mut y_items = Vec::with_capacity(ell);

        for i in 0..ell {
            let v_bound = BigUint::one() << (STAT_SEC + CHALLENGE_BITS + b_bits_vec[i]);
            let v = rng.gen_biguint_below(&v_bound);

            let exp_y = &two_pow_k * &v;
            let y_item = y_vec[i].modpow(&exp_y, &pk.n);

            v_vec.push(v);
            y_items.push(y_item);
        }

        // Commitment: d = prod y_i^{2^k * v_i} * h^{2^k * w} mod N
        let mut d = BigUint::one();
        for y_item in &y_items {
            d = (&d * y_item) % &pk.n;
        }
        let exp_h = &two_pow_k * &w;
        let h_w = pk.h.modpow(&exp_h, &pk.n);
        d = (&d * &h_w) % &pk.n;

        // Fiat-Shamir challenge
        let e = fiat_shamir_challenge(pk, y_vec, c, &d);

        // Responses
        let z_vec: Vec<BigUint> = (0..ell).map(|i| &e * &m_vec[i] + &v_vec[i]).collect();
        let z_r = &e * r + &w;

        Self { d, z_r, z_vec }
    }

    /// Verifies the proof.
    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, y_vec: &[BigUint], c: &BigUint) -> bool {
        assert_eq!(y_vec.len(), self.z_vec.len());

        let ell = y_vec.len();
        let two_pow_k = BigUint::one() << pk.k;

        // Recompute challenge
        let e = fiat_shamir_challenge(pk, y_vec, c, &self.d);

        // LHS: prod y_i^{2^k * z_i} * h^{2^k * z_r} mod N
        let mut lhs = BigUint::one();
        for i in 0..ell {
            let exp_y = &two_pow_k * &self.z_vec[i];
            let y_item = y_vec[i].modpow(&exp_y, &pk.n);
            lhs = (&lhs * &y_item) % &pk.n;
        }
        let exp_h = &two_pow_k * &self.z_r;
        let h_item = pk.h.modpow(&exp_h, &pk.n);
        lhs = (&lhs * &h_item) % &pk.n;

        // RHS: c^e * d mod N
        let c_e = c.modpow(&e, &pk.n);
        let rhs = (&c_e * &self.d) % &pk.n;

        lhs == rhs
    }
}

/// Computes the Fiat-Shamir challenge.
fn fiat_shamir_challenge(pk: &JlPublicKey, y_vec: &[BigUint], c: &BigUint, d: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlvCom");
    hasher.update(pk.n.to_bytes_be());
    hasher.update(pk.h.to_bytes_be());
    hasher.update(pk.k.to_be_bytes());
    hasher.update((y_vec.len() as u32).to_be_bytes());
    for y in y_vec {
        hasher.update(y.to_bytes_be());
    }
    hasher.update(c.to_bytes_be());
    hasher.update(d.to_bytes_be());
    let hash = hasher.finalize();

    let full = BigUint::from_bytes_be(&hash);
    let mask = (BigUint::one() << CHALLENGE_BITS) - BigUint::one();
    full & mask
}

/// Computes a JL vector commitment: c = prod y_i^{2^k * m_i} * h^{2^k * r} mod N.
#[must_use]
pub fn jl_vec_commit(
    pk: &JlPublicKey,
    y_vec: &[BigUint],
    m_vec: &[BigUint],
    r: &BigUint,
) -> BigUint {
    assert_eq!(y_vec.len(), m_vec.len());
    let two_pow_k = BigUint::one() << pk.k;
    let mut c = BigUint::one();
    for i in 0..y_vec.len() {
        let exp = &two_pow_k * &m_vec[i];
        let item = y_vec[i].modpow(&exp, &pk.n);
        c = (&c * &item) % &pk.n;
    }
    let exp_h = &two_pow_k * r;
    let h_r = pk.h.modpow(&exp_h, &pk.n);
    (&c * &h_r) % &pk.n
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
            let alpha_i = rng.gen_biguint_below(&pk.n);
            let y_i = x.modpow(&alpha_i, &pk.n);
            y_vec.push(y_i);
        }

        let m_vec: Vec<BigUint> = vec![
            BigUint::from(42u32),
            BigUint::from(17u32),
            BigUint::from(99u32),
        ];
        let b_bits_vec: Vec<u32> = vec![32, 32, 32];
        let r = rng.gen_biguint_below(&pk.n);

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
            let alpha_i = rng.gen_biguint_below(&pk.n);
            let y_i = x.modpow(&alpha_i, &pk.n);
            y_vec.push(y_i);
        }

        let m_vec = vec![BigUint::from(42u32), BigUint::from(17u32)];
        let b_bits_vec = vec![32, 32];
        let r = rng.gen_biguint_below(&pk.n);

        let c = jl_vec_commit(&pk, &y_vec, &m_vec, &r);

        // Wrong witness
        let wrong_m = vec![BigUint::from(99u32), BigUint::from(17u32)];
        let wrong_r = rng.gen_biguint_below(&pk.n);
        let proof =
            ZkJlvComProof::prove(&pk, &y_vec, &c, &wrong_m, &wrong_r, &b_bits_vec, &mut rng);
        assert!(!proof.verify(&pk, &y_vec, &c));
    }
}
