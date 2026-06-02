// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of 2^k-th power residuosity (`Pi_QR2k`).
//!
//! Proves that `h` is a 2^k-th power residue modulo `N`, i.e. there exists
//! `x` such that `h = x^{2^k} mod N`.
//!
//! This is a one-time setup proof (Appendix B.1 of XAL23).
//!
//! Protocol (80-repetition Fiat-Shamir):
//! For i = 1..80:
//!   P samples r_i <- Z_N, computes a_i = r_i^{2^k} mod N
//! Challenge: e = H(a_1, ..., a_80)
//! For i = 1..80:
//!   if e_i = 0: z_i = r_i
//!   if e_i = 1: z_i = r_i * x  (i.e. z_i^{2^k} = a_i * h mod N)
//! Verify: z_i^{2^k} == a_i * h^{e_i} mod N

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Number of repetitions for soundness.
const REPEAT: usize = 80;

/// Proof that an element `h` is a 2^k-th power residue modulo N.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkQr2kProof {
    /// Public: the element `h` being proven to be a QR_{2^k}
    pub h: BigUint,
    /// Public: modulus N
    pub n: BigUint,
    /// Public: parameter k
    pub k: u32,
    /// Commitment values: a_i = r_i^{2^k} mod N
    a_vec: Vec<BigUint>,
    /// Response values: z_i = r_i * x^{e_i} (plain product, not reduced)
    z_vec: Vec<BigUint>,
}

impl ZkQr2kProof {
    /// Creates a proof that `h = x^{2^k} mod N`.
    ///
    /// # Arguments
    ///
    /// * `n` - RSA modulus
    /// * `k` - power parameter
    /// * `x` - the 2^k-th root witness (h = x^{2^k} mod N)
    /// * `h` - the element to prove is a QR_{2^k}
    pub fn prove(
        n: &BigUint,
        k: u32,
        x: &BigUint,
        h: &BigUint,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let two_pow_k = BigUint::one() << k;

        // Step 1: Generate commitments
        let mut a_vec = Vec::with_capacity(REPEAT);
        let mut r_vec = Vec::with_capacity(REPEAT);

        for _ in 0..REPEAT {
            let r = rng.gen_biguint_below(n);
            let a = r.modpow(&two_pow_k, n);
            a_vec.push(a);
            r_vec.push(r);
        }

        // Step 2: Fiat-Shamir challenge
        let e = compute_challenge(&a_vec);

        // Step 3: Compute responses
        let mut z_vec = Vec::with_capacity(REPEAT);
        for i in 0..REPEAT {
            let e_bit = (&e >> i) & BigUint::one();
            if e_bit.is_one() {
                // z_i = r_i * x mod N
                let z = (&r_vec[i] * x) % n;
                z_vec.push(z);
            } else {
                z_vec.push(r_vec[i].clone());
            }
        }

        Self {
            h: h.clone(),
            n: n.clone(),
            k,
            a_vec,
            z_vec,
        }
    }

    /// Verifies the proof.
    ///
    /// Checks: for each i, z_i^{2^k} == a_i * h^{e_i} mod N.
    #[must_use]
    pub fn verify(&self) -> bool {
        let two_pow_k = BigUint::one() << self.k;

        // Recompute challenge
        let e = compute_challenge(&self.a_vec);

        for i in 0..REPEAT {
            let e_bit = (&e >> i) & BigUint::one();
            let z_pow = self.z_vec[i].modpow(&two_pow_k, &self.n);

            let expected = if e_bit.is_one() {
                (&self.a_vec[i] * &self.h) % &self.n
            } else {
                self.a_vec[i].clone()
            };

            if z_pow != expected {
                return false;
            }
        }

        true
    }
}

/// Computes the Fiat-Shamir challenge from the commitment vector.
fn compute_challenge(a_vec: &[BigUint]) -> BigUint {
    // Hash each a_i individually, then hash the concatenation
    let mut fs_vec = Vec::with_capacity(a_vec.len());
    for a in a_vec {
        let mut h = Sha256::new();
        h.update(b"ZkQr2k-a");
        h.update(a.to_bytes_be());
        fs_vec.push(h.finalize());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"ZkQr2k-e");
    for fs in &fs_vec {
        hasher.update(fs);
    }
    let hash = hasher.finalize();
    BigUint::from_bytes_be(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_params;

    #[test]
    fn zkqr2k_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        // We need the original x to prove h = x^{2^k} mod N.
        // Since generate_keypair_with_params does not expose x, we construct
        // our own test case.
        let x = rng.gen_biguint_below(&pk.n);
        let two_pow_k = BigUint::one() << pk.k;
        let h = x.modpow(&two_pow_k, &pk.n);

        let proof = ZkQr2kProof::prove(&pk.n, pk.k, &x, &h, &mut rng);
        assert!(proof.verify());
    }

    #[test]
    fn zkqr2k_verify_with_pk_h() {
        // pk.h is constructed as x^{2^k} mod N in keygen, so it should verify.
        // We need the witness x though, so we test with a fresh construction.
        let mut rng = rand::thread_rng();
        let n_bits: u64 = 256;
        let k: u32 = 32;

        let x = rng.gen_biguint(n_bits);
        let n = rng.gen_biguint(n_bits * 2);
        // Ensure n is odd (approximate modulus)
        let n = n | BigUint::one();

        let two_pow_k = BigUint::one() << k;
        let h = x.modpow(&two_pow_k, &n);

        let proof = ZkQr2kProof::prove(&n, k, &x, &h, &mut rng);
        assert!(proof.verify());
    }
}
