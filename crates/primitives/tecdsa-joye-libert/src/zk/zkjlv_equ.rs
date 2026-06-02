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

use crate::kgen::JlPublicKey;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Non-interactive proof of vector plaintext equality.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlvEquProof {
    /// Commitment under pk: d
    pub d: BigUint,
    /// Commitments under pk0: d'_i
    pub d_prime_vec: Vec<BigUint>,
    /// Response for each message: z_m_i = e*m_i + v_i
    pub z_m_vec: Vec<BigUint>,
    /// Response for randomness under pk: z_r = e*r + w
    pub z_r: BigUint,
    /// Responses for randomness under pk0: z_r0_i = e*r0_i + w0_i
    pub z_r0_vec: Vec<BigUint>,
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
        y_vec: &[BigUint],
        c: &BigUint,
        c_prime_vec: &[BigUint],
        m_vec: &[BigUint],
        r: &BigUint,
        r0_vec: &[BigUint],
        b_bits_vec: &[u32],
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let ell = m_vec.len();
        assert_eq!(y_vec.len(), ell);
        assert_eq!(c_prime_vec.len(), ell);
        assert_eq!(r0_vec.len(), ell);
        assert_eq!(b_bits_vec.len(), ell);

        let two_pow_k = BigUint::one() << pk.k;
        let two_pow_k0 = BigUint::one() << pk0.k;

        // Sample blinding values
        let w_bound = &pk.n << (STAT_SEC + CHALLENGE_BITS);
        let w = rng.gen_biguint_below(&w_bound);

        let mut v_vec = Vec::with_capacity(ell);
        let mut w0_vec = Vec::with_capacity(ell);
        let mut d_prime_vec = Vec::with_capacity(ell);
        let mut y_items = Vec::with_capacity(ell);

        for i in 0..ell {
            let v_bound = BigUint::one() << (STAT_SEC + CHALLENGE_BITS + b_bits_vec[i]);
            let w0_bound = &pk0.n << (STAT_SEC + CHALLENGE_BITS);

            let v = rng.gen_biguint_below(&v_bound);
            let w0 = rng.gen_biguint_below(&w0_bound);

            // d'_i = y0^{2^k0 * v} * h0^{2^k0 * w0} mod N0
            let exp_y0 = &two_pow_k0 * &v;
            let exp_h0 = &two_pow_k0 * &w0;
            let y0_v = pk0.y.modpow(&exp_y0, &pk0.n);
            let h0_w = pk0.h.modpow(&exp_h0, &pk0.n);
            let d_prime = (&y0_v * &h0_w) % &pk0.n;

            // y_i item for commitment d
            let exp_y = &two_pow_k * &v;
            let y_item = y_vec[i].modpow(&exp_y, &pk.n);

            v_vec.push(v);
            w0_vec.push(w0);
            d_prime_vec.push(d_prime);
            y_items.push(y_item);
        }

        // d = prod y_i^{2^k * v_i} * h^{2^k * w} mod N
        let mut d = BigUint::one();
        for y_item in &y_items {
            d = (&d * y_item) % &pk.n;
        }
        let exp_h = &two_pow_k * &w;
        let h_w = pk.h.modpow(&exp_h, &pk.n);
        d = (&d * &h_w) % &pk.n;

        // Fiat-Shamir challenge
        let e = fiat_shamir_challenge(pk, pk0, y_vec, c, c_prime_vec, &d, &d_prime_vec);

        // Responses
        let z_m_vec: Vec<BigUint> = (0..ell).map(|i| &e * &m_vec[i] + &v_vec[i]).collect();
        let z_r = &e * r + &w;
        let z_r0_vec: Vec<BigUint> = (0..ell).map(|i| &e * &r0_vec[i] + &w0_vec[i]).collect();

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
        y_vec: &[BigUint],
        c: &BigUint,
        c_prime_vec: &[BigUint],
    ) -> bool {
        let ell = self.z_m_vec.len();
        assert_eq!(y_vec.len(), ell);
        assert_eq!(c_prime_vec.len(), ell);
        assert_eq!(self.d_prime_vec.len(), ell);
        assert_eq!(self.z_r0_vec.len(), ell);

        let two_pow_k = BigUint::one() << pk.k;
        let two_pow_k0 = BigUint::one() << pk0.k;

        // Recompute challenge
        let e = fiat_shamir_challenge(pk, pk0, y_vec, c, c_prime_vec, &self.d, &self.d_prime_vec);

        // Check 1: prod y_i^{2^k * z_m_i} * h^{2^k * z_r} == c^e * d mod N
        let mut lhs1 = BigUint::one();
        for i in 0..ell {
            let exp_y = &two_pow_k * &self.z_m_vec[i];
            let y_item = y_vec[i].modpow(&exp_y, &pk.n);
            lhs1 = (&lhs1 * &y_item) % &pk.n;
        }
        let exp_h = &two_pow_k * &self.z_r;
        let h_item = pk.h.modpow(&exp_h, &pk.n);
        lhs1 = (&lhs1 * &h_item) % &pk.n;

        let c_e = c.modpow(&e, &pk.n);
        let rhs1 = (&c_e * &self.d) % &pk.n;

        if lhs1 != rhs1 {
            return false;
        }

        // Check 2: for each i, y0^{2^k0 * z_m_i} * h0^{2^k0 * z_r0_i} == c'_i^e * d'_i mod N0
        for i in 0..ell {
            let exp_y0 = &two_pow_k0 * &self.z_m_vec[i];
            let exp_h0 = &two_pow_k0 * &self.z_r0_vec[i];
            let y0_z = pk0.y.modpow(&exp_y0, &pk0.n);
            let h0_z = pk0.h.modpow(&exp_h0, &pk0.n);
            let lhs2 = (&y0_z * &h0_z) % &pk0.n;

            let c_prime_e = c_prime_vec[i].modpow(&e, &pk0.n);
            let rhs2 = (&c_prime_e * &self.d_prime_vec[i]) % &pk0.n;

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
    y_vec: &[BigUint],
    c: &BigUint,
    c_prime_vec: &[BigUint],
    d: &BigUint,
    d_prime_vec: &[BigUint],
) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlvEqu");
    hasher.update(pk.n.to_bytes_be());
    hasher.update(pk.h.to_bytes_be());
    hasher.update(pk.k.to_be_bytes());
    hasher.update(pk0.n.to_bytes_be());
    hasher.update(pk0.y.to_bytes_be());
    hasher.update(pk0.h.to_bytes_be());
    hasher.update(pk0.k.to_be_bytes());
    hasher.update((y_vec.len() as u32).to_be_bytes());
    for y in y_vec {
        hasher.update(y.to_bytes_be());
    }
    hasher.update(c.to_bytes_be());
    for cp in c_prime_vec {
        hasher.update(cp.to_bytes_be());
    }
    hasher.update(d.to_bytes_be());
    // Hash d_prime_vec as a sum (following reference pattern) for simpler hashing
    for dp in d_prime_vec {
        hasher.update(dp.to_bytes_be());
    }
    let hash = hasher.finalize();

    let full = BigUint::from_bytes_be(&hash);
    let mask = (BigUint::one() << CHALLENGE_BITS) - BigUint::one();
    full & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_qnr;
    use crate::zk::zkjl_com::jl_commit;
    use crate::zk::zkjlv_com::jl_vec_commit;

    #[test]
    fn zkjlv_equ_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk, x) = generate_keypair_with_qnr(256, 32, &mut rng);
        let (pk0, _sk0, _x0) = generate_keypair_with_qnr(256, 32, &mut rng);

        let ell = 2;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = rng.gen_biguint_below(&pk.n);
            let y_i = x.modpow(&alpha_i, &pk.n);
            y_vec.push(y_i);
        }

        let m_vec = vec![BigUint::from(42u32), BigUint::from(17u32)];
        let b_bits_vec = vec![32u32, 32];
        let r = rng.gen_biguint_below(&pk.n);

        // Vector commitment under pk
        let c = jl_vec_commit(&pk, &y_vec, &m_vec, &r);

        // Individual commitments under pk0
        let mut c_prime_vec = Vec::with_capacity(ell);
        let mut r0_vec = Vec::with_capacity(ell);
        for i in 0..ell {
            let r0 = rng.gen_biguint_below(&pk0.n);
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
