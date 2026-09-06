// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of JL vector plaintext equality (`Pi_JLVEqu`).
//!
//! Extension of `Pi_JLEqu` to vectors.
//!
//! Proves that the same vector of plaintexts `(m_1, ..., m_l)` appears
//! in both a vector commitment under `pk` (with bases `y_1, ..., y_l`)
//! and individual ciphertexts (raised to `2^k`) under `pk0`.
//!
//! Relation: R_{JLv-equ} = {(c, c'_1, ..., c'_l; m_1, ..., m_l, r, r0_1, ..., r0_l) |
//!   c = prod y_i^{2^k * m_i} * h^{2^k * r} mod N
//!   c'_i = y0^{2^k * m_i} * h0^{2^k * r0_i} mod N0  for all i
//!   m_i in [0, B_i]}

use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, pow_mod, random_below};

use crate::kgen::JlPublicKey;

/// Non-interactive proof of vector plaintext equality.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlvEquProof {
    /// Commitment under pk: d
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d: Integer,
    /// Commitments under pk0: d'_i
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    pub d_prime_vec: Vec<Integer>,
    /// Response for each message: z_m_i = e*m_i + v_i
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    pub z_m_vec: Vec<Integer>,
    /// Response for randomness under pk: z_r = e*r + w
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r: Integer,
    /// Responses for randomness under pk0: z_r0_i = e*r0_i + w0_i
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    pub z_r0_vec: Vec<Integer>,
}

/// Statistical security parameter (in bits).
const STAT_SEC: u32 = 80;
/// Fiat-Shamir challenge size (in bits).
const CHALLENGE_BITS: u32 = 80;

impl ZkJlvEquProof {
    /// Creates a proof of vector plaintext equality.
    ///
    /// # Arguments
    ///
    /// * `pk` - First JL public key (for vector commitment `c` with bases `y_vec`)
    /// * `pk0` - Second JL public key (for individual ciphertexts)
    /// * `y_vec` - Vector of bases for the commitment under `pk`
    /// * `c` - Vector commitment under `pk`
    /// * `c_prime_vec` - Individual commitments (y0^{2^k*m_i} * h0^{2^k*r0_i}) under `pk0`
    /// * `m_vec` - The shared plaintext vector witness
    /// * `r` - Randomness for commitment `c` under `pk`
    /// * `r0_vec` - Randomness for each commitment under `pk0`
    /// * `b_bits_vec` - Bounds on each message in bits
    #[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
    pub fn prove(
        pk: &JlPublicKey,
        pk0: &JlPublicKey,
        y_vec: &[Integer],
        c: &Integer,
        c_prime_vec: &[Integer],
        m_vec: &[Integer],
        r: &Integer,
        r0_vec: &[Integer],
        b_bits_vec: &[u32],
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let ell = m_vec.len();
        assert_eq!(y_vec.len(), ell);
        assert_eq!(c_prime_vec.len(), ell);
        assert_eq!(r0_vec.len(), ell);
        assert_eq!(b_bits_vec.len(), ell);

        let two_pow_k = Integer::from(1) << pk.k;
        let two_pow_k0 = Integer::from(1) << pk0.k;

        // Sample blinding values
        let w_bound = Integer::from(&pk.n << (STAT_SEC + CHALLENGE_BITS));
        let w = random_below(&w_bound, rng);

        let mut v_vec = Vec::with_capacity(ell);
        let mut w0_vec = Vec::with_capacity(ell);
        let mut d_prime_vec = Vec::with_capacity(ell);
        let mut y_items = Vec::with_capacity(ell);

        for i in 0..ell {
            let v_bound = Integer::from(1) << (STAT_SEC + CHALLENGE_BITS + b_bits_vec[i]);
            let w0_bound = Integer::from(&pk0.n << (STAT_SEC + CHALLENGE_BITS));

            let v = random_below(&v_bound, rng);
            let w0 = random_below(&w0_bound, rng);

            // d'_i = y0^{2^k0 * v} * h0^{2^k0 * w0} mod N0
            let exp_y0 = Integer::from(&two_pow_k0 * &v);
            let exp_h0 = Integer::from(&two_pow_k0 * &w0);
            let y0_v = pow_mod(&pk0.y, &exp_y0, &pk0.n);
            let h0_w = pow_mod(&pk0.h, &exp_h0, &pk0.n);
            let d_prime = mul_mod(&y0_v, &h0_w, &pk0.n);

            // y_i item for commitment d
            let exp_y = Integer::from(&two_pow_k * &v);
            let y_item = pow_mod(&y_vec[i], &exp_y, &pk.n);

            v_vec.push(v);
            w0_vec.push(w0);
            d_prime_vec.push(d_prime);
            y_items.push(y_item);
        }

        // d = prod y_i^{2^k * v_i} * h^{2^k * w} mod N
        let mut d = Integer::from(1);
        for y_item in &y_items {
            d = mul_mod(&d, y_item, &pk.n);
        }
        let exp_h = two_pow_k * &w;
        let h_w = pow_mod(&pk.h, &exp_h, &pk.n);
        d = mul_mod(&d, &h_w, &pk.n);

        // Fiat-Shamir challenge
        let e = fiat_shamir_challenge(pk, pk0, y_vec, c, c_prime_vec, &d, &d_prime_vec);

        // Responses
        let z_m_vec: Vec<Integer> = (0..ell)
            .map(|i| Integer::from(&e * &m_vec[i]) + &v_vec[i])
            .collect();
        let z_r = Integer::from(&e * r) + &w;
        let z_r0_vec: Vec<Integer> = (0..ell)
            .map(|i| Integer::from(&e * &r0_vec[i]) + &w0_vec[i])
            .collect();

        Self {
            d,
            d_prime_vec,
            z_m_vec,
            z_r,
            z_r0_vec,
        }
    }

    /// Verifies the proof.
    #[must_use]
    #[allow(clippy::many_single_char_names)]
    pub fn verify(
        &self,
        pk: &JlPublicKey,
        pk0: &JlPublicKey,
        y_vec: &[Integer],
        c: &Integer,
        c_prime_vec: &[Integer],
    ) -> bool {
        let ell = self.z_m_vec.len();
        assert_eq!(y_vec.len(), ell);
        assert_eq!(c_prime_vec.len(), ell);
        assert_eq!(self.d_prime_vec.len(), ell);
        assert_eq!(self.z_r0_vec.len(), ell);

        let two_pow_k = Integer::from(1) << pk.k;
        let two_pow_k0 = Integer::from(1) << pk0.k;

        // Recompute challenge
        let e = fiat_shamir_challenge(pk, pk0, y_vec, c, c_prime_vec, &self.d, &self.d_prime_vec);

        // Check 1: prod y_i^{2^k * z_m_i} * h^{2^k * z_r} == c^e * d mod N
        let mut lhs1 = Integer::from(1);
        for i in 0..ell {
            let exp_y = Integer::from(&two_pow_k * &self.z_m_vec[i]);
            let y_item = pow_mod(&y_vec[i], &exp_y, &pk.n);
            lhs1 = mul_mod(&lhs1, &y_item, &pk.n);
        }
        let exp_h = two_pow_k * &self.z_r;
        let h_item = pow_mod(&pk.h, &exp_h, &pk.n);
        lhs1 = mul_mod(&lhs1, &h_item, &pk.n);

        let c_e = pow_mod(c, &e, &pk.n);
        let rhs1 = mul_mod(&c_e, &self.d, &pk.n);

        if lhs1 != rhs1 {
            return false;
        }

        // Check 2: for each i, y0^{2^k0 * z_m_i} * h0^{2^k0 * z_r0_i} == c'_i^e * d'_i mod N0
        for i in 0..ell {
            let exp_y0 = Integer::from(&two_pow_k0 * &self.z_m_vec[i]);
            let exp_h0 = Integer::from(&two_pow_k0 * &self.z_r0_vec[i]);
            let y0_z = pow_mod(&pk0.y, &exp_y0, &pk0.n);
            let h0_z = pow_mod(&pk0.h, &exp_h0, &pk0.n);
            let lhs2 = mul_mod(&y0_z, &h0_z, &pk0.n);

            let c_prime_e = pow_mod(&c_prime_vec[i], &e, &pk0.n);
            let rhs2 = mul_mod(&c_prime_e, &self.d_prime_vec[i], &pk0.n);

            if lhs2 != rhs2 {
                return false;
            }
        }

        true
    }
}

/// Computes the Fiat-Shamir challenge.
fn fiat_shamir_challenge(
    pk: &JlPublicKey,
    pk0: &JlPublicKey,
    y_vec: &[Integer],
    c: &Integer,
    c_prime_vec: &[Integer],
    d: &Integer,
    d_prime_vec: &[Integer],
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlvEqu");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update(pk0.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk0.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk0.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk0.k.to_be_bytes());
    hasher.update((y_vec.len() as u32).to_be_bytes());
    for y in y_vec {
        hasher.update(y.to_digits::<u8>(Order::Msf));
    }
    hasher.update(c.to_digits::<u8>(Order::Msf));
    for cp in c_prime_vec {
        hasher.update(cp.to_digits::<u8>(Order::Msf));
    }
    hasher.update(d.to_digits::<u8>(Order::Msf));
    // Hash d_prime_vec as a sum (following reference pattern) for simpler hashing
    for dp in d_prime_vec {
        hasher.update(dp.to_digits::<u8>(Order::Msf));
    }
    let hash = hasher.finalize();

    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kgen::generate_keypair_with_qnr,
        zk::{zkjl_com::jl_commit, zkjlv_com::jl_vec_commit},
    };

    #[test]
    fn zkjlv_equ_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk, x) = generate_keypair_with_qnr(256, 32, &mut rng);
        let (pk0, _sk0, _x0) = generate_keypair_with_qnr(256, 32, &mut rng);

        let ell = 2;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = random_below(&pk.n, &mut rng);
            let y_i = pow_mod(&x, &alpha_i, &pk.n);
            y_vec.push(y_i);
        }

        let m_vec = vec![Integer::from(42u32), Integer::from(17u32)];
        let b_bits_vec = vec![32u32, 32];
        let r = random_below(&pk.n, &mut rng);

        // Vector commitment under pk
        let c = jl_vec_commit(&pk, &y_vec, &m_vec, &r);

        // Individual commitments under pk0
        let mut c_prime_vec = Vec::with_capacity(ell);
        let mut r0_vec = Vec::with_capacity(ell);
        for i in 0..ell {
            let r0 = random_below(&pk0.n, &mut rng);
            let cp = jl_commit(&pk0, &m_vec[i], &r0);
            c_prime_vec.push(cp);
            r0_vec.push(r0);
        }

        let proof = ZkJlvEquProof::prove(
            &pk,
            &pk0,
            &y_vec,
            &c,
            &c_prime_vec,
            &m_vec,
            &r,
            &r0_vec,
            &b_bits_vec,
            &mut rng,
        );
        assert!(proof.verify(&pk, &pk0, &y_vec, &c, &c_prime_vec));
    }
}
