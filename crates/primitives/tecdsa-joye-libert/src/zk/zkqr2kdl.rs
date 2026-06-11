// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of 2^k-th power residue discrete-log (`Pi_QR2kDL`).
//!
//! Proves that `h^alpha = y^{2^k} mod N`. Since `h = x^{2^k}` and `y = x^alpha`,
//! this amounts to proving the discrete-log relationship between `y` and `h`.
//!
//! This is a one-time setup proof (Appendix B.2 of XAL23).
//!
//! Protocol (80-repetition Fiat-Shamir):
//! For i = 1..80:
//!   P samples beta_i <- [0, 2^s * N), computes a_i = h^{beta_i} mod N
//! Challenge: e = H(a_1, ..., a_80)
//! For i = 1..80:
//!   z_i = beta_i + e_i * alpha
//! Verify: h^{z_i} == a_i * y^{2^k * e_i} mod N

use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, pow_mod, random_below};

/// Number of repetitions for soundness.
const REPEAT: usize = 80;
/// Statistical security parameter.
const STAT_SEC: u32 = 80;

/// Proof that h^alpha = y^{2^k} mod N (i.e., y and h share the same base x
/// with y = x^alpha and h = x^{2^k}).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkQr2kDlProof {
    /// Public: h (the QR_{2^k} element, h = x^{2^k})
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub h: Integer,
    /// Public: N (RSA modulus)
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub n: Integer,
    /// Public: y = x^alpha mod N
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub y: Integer,
    /// Public: parameter k
    pub k: u32,
    /// Commitment values: a_i = h^{beta_i} mod N
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    a_vec: Vec<Integer>,
    /// Response values: z_i = beta_i + e_i * alpha
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    z_vec: Vec<Integer>,
}

impl ZkQr2kDlProof {
    /// Creates a proof that `h^alpha = y^{2^k} mod N`.
    ///
    /// # Arguments
    ///
    /// * `n` - RSA modulus
    /// * `k` - power parameter
    /// * `alpha` - the discrete log witness
    /// * `h` - the base (a QR_{2^k} element, h = x^{2^k})
    /// * `y` - the public value (y = x^alpha mod N)
    pub fn prove(
        n: &Integer,
        k: u32,
        alpha: &Integer,
        h: &Integer,
        y: &Integer,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        // beta_i sampled from [0, 2^s * N)
        let beta_bound = Integer::from(n << STAT_SEC);

        let mut a_vec = Vec::with_capacity(REPEAT);
        let mut beta_vec = Vec::with_capacity(REPEAT);

        for _ in 0..REPEAT {
            let beta = random_below(&beta_bound, rng);
            let a = pow_mod(h, &beta, n);
            a_vec.push(a);
            beta_vec.push(beta);
        }

        // Fiat-Shamir challenge
        let e = compute_challenge(&a_vec);

        // Compute responses: z_i = beta_i + e_i * alpha
        let mut z_vec = Vec::with_capacity(REPEAT);
        for i in 0..REPEAT {
            let z = if e.get_bit(i as u32) {
                Integer::from(&beta_vec[i] + alpha)
            } else {
                beta_vec[i].clone()
            };
            z_vec.push(z);
        }

        Self {
            h: h.clone(),
            n: n.clone(),
            y: y.clone(),
            k,
            a_vec,
            z_vec,
        }
    }

    /// Verifies the proof.
    ///
    /// Checks: for each i, h^{z_i} == a_i * y^{2^k * e_i} mod N.
    #[must_use]
    pub fn verify(&self) -> bool {
        let two_pow_k = Integer::from(1) << self.k;

        // Recompute challenge
        let e = compute_challenge(&self.a_vec);

        for i in 0..REPEAT {
            // LHS: h^{z_i} mod N
            let lhs = pow_mod(&self.h, &self.z_vec[i], &self.n);

            // RHS: a_i * y^{2^k * e_i} mod N
            let rhs = if e.get_bit(i as u32) {
                let y_exp = pow_mod(&self.y, &two_pow_k, &self.n);
                mul_mod(&self.a_vec[i], &y_exp, &self.n)
            } else {
                self.a_vec[i].clone()
            };

            if lhs != rhs {
                return false;
            }
        }

        true
    }
}

/// Computes the Fiat-Shamir challenge from the commitment vector.
fn compute_challenge(a_vec: &[Integer]) -> Integer {
    let mut fs_vec = Vec::with_capacity(a_vec.len());
    for a in a_vec {
        let mut h = Sha256::new();
        h.update(b"ZkQr2kDl-a");
        h.update(a.to_digits::<u8>(Order::Msf));
        fs_vec.push(h.finalize());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"ZkQr2kDl-e");
    for fs in &fs_vec {
        hasher.update(fs);
    }
    let hash = hasher.finalize();
    Integer::from_digits(&hash, Order::Msf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_qnr;

    #[test]
    fn zkqr2kdl_prove_and_verify() {
        let mut rng = rand::thread_rng();
        // Use generate_keypair_with_qnr so we have proper pk.y = x^alpha, pk.h = x^{2^k}
        let (pk, sk, _x) = generate_keypair_with_qnr(256, 32, &mut rng);

        // The relationship: h^alpha = y^{2^k} mod N
        // because h = x^{2^k}, y = x^alpha, so h^alpha = x^{2^k * alpha} = y^{2^k}
        let proof = ZkQr2kDlProof::prove(&pk.n, pk.k, &sk.alpha, &pk.h, &pk.y, &mut rng);
        assert!(proof.verify());
    }
}
