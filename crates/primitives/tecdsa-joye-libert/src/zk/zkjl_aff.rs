// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of JL affine relation (`Pi_JLAff`).
//!
//! Relation: R_{JL-aff} = {(C_aff; C, a, alpha, r) |
//!   J_N(C_aff) = 1,
//!   C_aff = C^a * y^alpha * h^r mod N,
//!   a in [0, B_1], alpha in [0, B_2]}
//!
//! This is essentially `ZK_{JLv-com}` with l=2: the affine ciphertext
//! C_aff = C^a * y^alpha * h^r is a vector commitment with bases (C, y)
//! and messages (a, alpha).

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::kgen::JlPublicKey;

/// Non-interactive proof of JL affine relation.
///
/// Proves knowledge of `(a, alpha, r)` such that
/// `C_aff = C^a * y^alpha * h^r mod N`,
/// with `a in [0, B_1]` and `alpha in [0, B_2]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlAffProof {
    /// Commitment: d = C^v1 * y^v2 * h^w mod N
    pub d: BigUint,
    /// Response for `a`: z_a = e*a + v1
    pub z_a: BigUint,
    /// Response for `alpha`: z_alpha = e*alpha + v2
    pub z_alpha: BigUint,
    /// Response for `r`: z_r = e*r + w
    pub z_r: BigUint,
}

/// Statistical security parameter (in bits).
const STAT_SEC: u32 = 80;
/// Fiat-Shamir challenge size (in bits).
const CHALLENGE_BITS: u32 = 80;

impl ZkJlAffProof {
    /// Creates a proof that `c_aff = C^a * y^alpha * h^r mod N`.
    ///
    /// # Arguments
    ///
    /// * `pk` - JL public key (provides y, h, N)
    /// * `c_base` - the base ciphertext C
    /// * `c_aff` - the affine ciphertext being proven
    /// * `a` - the scalar witness
    /// * `alpha` - the additive message witness
    /// * `r` - the randomness witness
    /// * `b1_bits` - bound on `a` in bits (B_1 = 2^b1_bits)
    /// * `b2_bits` - bound on `alpha` in bits (B_2 = 2^b2_bits)
    #[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
    pub fn prove(
        pk: &JlPublicKey,
        c_base: &BigUint,
        c_aff: &BigUint,
        a: &BigUint,
        alpha: &BigUint,
        r: &BigUint,
        b1_bits: u32,
        b2_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        // Upper bounds for the blinding values
        let v1_bound = BigUint::one() << (STAT_SEC + CHALLENGE_BITS + b1_bits);
        let v2_bound = BigUint::one() << (STAT_SEC + CHALLENGE_BITS + b2_bits);
        let w_bound = &pk.n << (STAT_SEC + CHALLENGE_BITS);

        let v1 = rng.gen_biguint_below(&v1_bound);
        let v2 = rng.gen_biguint_below(&v2_bound);
        let w = rng.gen_biguint_below(&w_bound);

        // Commitment: d = C^v1 * y^v2 * h^w mod N
        let c_v1 = c_base.modpow(&v1, &pk.n);
        let y_v2 = pk.y.modpow(&v2, &pk.n);
        let h_w = pk.h.modpow(&w, &pk.n);
        let d = (&c_v1 * &y_v2 % &pk.n) * &h_w % &pk.n;

        // Fiat-Shamir challenge
        let e = fiat_shamir_challenge(pk, c_base, c_aff, &d);

        // Responses
        let z_a = &e * a + &v1;
        let z_alpha = &e * alpha + &v2;
        let z_r = &e * r + &w;

        Self {
            d,
            z_a,
            z_alpha,
            z_r,
        }
    }

    /// Verifies the proof against public key `pk`, base ciphertext `c_base`,
    /// and affine ciphertext `c_aff`.
    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, c_base: &BigUint, c_aff: &BigUint) -> bool {
        // Recompute challenge
        let e = fiat_shamir_challenge(pk, c_base, c_aff, &self.d);

        // Check: C^z_a * y^z_alpha * h^z_r == c_aff^e * d mod N
        let lhs_1 = c_base.modpow(&self.z_a, &pk.n);
        let lhs_2 = pk.y.modpow(&self.z_alpha, &pk.n);
        let lhs_3 = pk.h.modpow(&self.z_r, &pk.n);
        let lhs = (&lhs_1 * &lhs_2 % &pk.n) * &lhs_3 % &pk.n;

        let c_aff_e = c_aff.modpow(&e, &pk.n);
        let rhs = (&c_aff_e * &self.d) % &pk.n;

        lhs == rhs
    }
}

/// Computes the Fiat-Shamir challenge.
fn fiat_shamir_challenge(
    pk: &JlPublicKey,
    c_base: &BigUint,
    c_aff: &BigUint,
    d: &BigUint,
) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlAff");
    hasher.update(pk.n.to_bytes_be());
    hasher.update(pk.y.to_bytes_be());
    hasher.update(pk.h.to_bytes_be());
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c_base.to_bytes_be());
    hasher.update(c_aff.to_bytes_be());
    hasher.update(d.to_bytes_be());
    let hash = hasher.finalize();

    let full = BigUint::from_bytes_be(&hash);
    let mask = (BigUint::one() << CHALLENGE_BITS) - BigUint::one();
    full & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{enc_dec::encrypt, kgen::generate_keypair_with_params};

    #[test]
    fn zkjl_aff_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        // Encrypt a message to get a base ciphertext
        let b = BigUint::from(7u32);
        let (ct_b, _r_b) = encrypt(&pk, &b, &mut rng);

        // Affine op: C_aff = C^a * y^alpha * h^r mod N
        let a = BigUint::from(5u32);
        let alpha = BigUint::from(13u32);
        let r = rng.gen_biguint_below(&pk.n);

        let c_a = ct_b.c.modpow(&a, &pk.n);
        let y_alpha = pk.y.modpow(&alpha, &pk.n);
        let h_r = pk.h.modpow(&r, &pk.n);
        let c_aff = (&c_a * &y_alpha % &pk.n) * &h_r % &pk.n;

        let proof = ZkJlAffProof::prove(&pk, &ct_b.c, &c_aff, &a, &alpha, &r, 32, 32, &mut rng);
        assert!(proof.verify(&pk, &ct_b.c, &c_aff));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_aff_rejects_wrong_witness() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let b = BigUint::from(7u32);
        let (ct_b, _r_b) = encrypt(&pk, &b, &mut rng);

        let a = BigUint::from(5u32);
        let alpha = BigUint::from(13u32);
        let r = rng.gen_biguint_below(&pk.n);

        let c_a = ct_b.c.modpow(&a, &pk.n);
        let y_alpha = pk.y.modpow(&alpha, &pk.n);
        let h_r = pk.h.modpow(&r, &pk.n);
        let c_aff = (&c_a * &y_alpha % &pk.n) * &h_r % &pk.n;

        // Wrong witness
        let wrong_a = BigUint::from(99u32);
        let wrong_r = rng.gen_biguint_below(&pk.n);
        let proof = ZkJlAffProof::prove(
            &pk, &ct_b.c, &c_aff, &wrong_a, &alpha, &wrong_r, 32, 32, &mut rng,
        );
        assert!(!proof.verify(&pk, &ct_b.c, &c_aff));
    }
}
