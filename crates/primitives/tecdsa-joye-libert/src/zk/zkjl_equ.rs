// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of JL plaintext equality (`Pi_JLEqu`).
//!
//! Relation: R_{JL-equ} = {(C, c; m) |
//!   c  = y^{2^k * m} * h^{2^k * r} mod N    (commitment under pk)
//!   C  = y0^{2^k * m} * h0^{2^k * r0} mod N0 (commitment under pk0)
//!   m in [0, B]}
//!
//! Proves that the same plaintext `m` is committed in two different JL instances.

use rug::{integer::Order, Complete, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{random_below, BigIntExt};

use crate::kgen::JlPublicKey;

/// Non-interactive proof of plaintext equality across two JL instances.
///
/// Proves knowledge of `(m, r, r0)` such that
/// `c = y^{2^k*m} * h^{2^k*r} mod N` and
/// `C = y0^{2^k*m} * h0^{2^k*r0} mod N0`
/// with the same `m in [0, B]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlEquProof {
    /// Commitment under pk: d = y^{2^k*v} * h^{2^k*w} mod N
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d: Integer,
    /// Commitment under pk0: d' = y0^{2^k*v} * h0^{2^k*w0} mod N0
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d_prime: Integer,
    /// Response for the message: z_m = e*m + v
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_m: Integer,
    /// Response for randomness under pk: z_r = e*r + w
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r: Integer,
    /// Response for randomness under pk0: z_r0 = e*r0 + w0
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r0: Integer,
}

/// Statistical security parameter (in bits).
const STAT_SEC: u32 = 80;
/// Fiat-Shamir challenge size (in bits).
const CHALLENGE_BITS: u32 = 80;

impl ZkJlEquProof {
    /// Creates a proof of plaintext equality.
    ///
    /// # Arguments
    ///
    /// * `pk` - First JL public key (for commitment `c`)
    /// * `pk0` - Second JL public key (for commitment `C`)
    /// * `c` - Commitment under `pk`
    /// * `c_prime` - Commitment under `pk0`
    /// * `m` - The shared plaintext witness
    /// * `r` - Randomness for commitment `c` under `pk`
    /// * `r0` - Randomness for commitment `C` under `pk0`
    /// * `msg_bits` - Bound on the message bit-length
    #[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
    pub fn prove(
        pk: &JlPublicKey,
        pk0: &JlPublicKey,
        c: &Integer,
        c_prime: &Integer,
        m: &Integer,
        r: &Integer,
        r0: &Integer,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let two_pow_k = Integer::two_pow(pk.k);

        // Upper bounds
        let v_bound = Integer::two_pow(STAT_SEC + CHALLENGE_BITS + msg_bits);
        let w_bound = Integer::from(&pk.n << (STAT_SEC + CHALLENGE_BITS));
        let w0_bound = Integer::from(&pk0.n << (STAT_SEC + CHALLENGE_BITS));

        let v = random_below(&v_bound, rng);
        let w = random_below(&w_bound, rng);
        let w0 = random_below(&w0_bound, rng);

        // Commitment under pk: d = y^{2^k*v} * h^{2^k*w} mod N
        let exp_y = Integer::from(&two_pow_k * &v);
        let exp_h = two_pow_k * &w;
        let y_v =
            pk.y.pow_mod_ref(&exp_y, &pk.n)
                .expect("exponent is non-negative")
                .complete();
        let h_w =
            pk.h.pow_mod_ref(&exp_h, &pk.n)
                .expect("exponent is non-negative")
                .complete();
        let d = (y_v * h_w).modulo(&pk.n);

        // Commitment under pk0: d' = y0^{2^k*v} * h0^{2^k*w0} mod N0
        let two_pow_k0 = Integer::two_pow(pk0.k);
        let exp_y0 = Integer::from(&two_pow_k0 * &v);
        let exp_h0 = two_pow_k0 * &w0;
        let y0_v = pk0
            .y
            .pow_mod_ref(&exp_y0, &pk0.n)
            .expect("exponent is non-negative")
            .complete();
        let h0_w0 = pk0
            .h
            .pow_mod_ref(&exp_h0, &pk0.n)
            .expect("exponent is non-negative")
            .complete();
        let d_prime = (y0_v * h0_w0).modulo(&pk0.n);

        // Fiat-Shamir challenge
        let e = fiat_shamir_challenge(pk, pk0, c, c_prime, &d, &d_prime);

        // Responses
        let z_m = Integer::from(&e * m) + &v;
        let z_r = Integer::from(&e * r) + &w;
        let z_r0 = e * r0 + &w0;

        Self {
            d,
            d_prime,
            z_m,
            z_r,
            z_r0,
        }
    }

    /// Verifies the proof against two public keys and two commitments.
    #[must_use]
    pub fn verify(
        &self,
        pk: &JlPublicKey,
        pk0: &JlPublicKey,
        c: &Integer,
        c_prime: &Integer,
    ) -> bool {
        let two_pow_k = Integer::two_pow(pk.k);
        let two_pow_k0 = Integer::two_pow(pk0.k);

        // Recompute challenge
        let e = fiat_shamir_challenge(pk, pk0, c, c_prime, &self.d, &self.d_prime);

        // Check 1: y^{2^k*z_m} * h^{2^k*z_r} == c^e * d mod N
        let exp_y = Integer::from(&two_pow_k * &self.z_m);
        let exp_h = two_pow_k * &self.z_r;
        let lhs1_y =
            pk.y.pow_mod_ref(&exp_y, &pk.n)
                .expect("exponent is non-negative")
                .complete();
        let lhs1_h =
            pk.h.pow_mod_ref(&exp_h, &pk.n)
                .expect("exponent is non-negative")
                .complete();
        let lhs1 = (lhs1_y * lhs1_h).modulo(&pk.n);

        let c_e = c
            .pow_mod_ref(&e, &pk.n)
            .expect("exponent is non-negative")
            .complete();
        let rhs1 = (c_e * &self.d).modulo(&pk.n);

        if lhs1 != rhs1 {
            return false;
        }

        // Check 2: y0^{2^k0*z_m} * h0^{2^k0*z_r0} == c'^e * d' mod N0
        let exp_y0 = Integer::from(&two_pow_k0 * &self.z_m);
        let exp_h0 = two_pow_k0 * &self.z_r0;
        let lhs2_y = pk0
            .y
            .pow_mod_ref(&exp_y0, &pk0.n)
            .expect("exponent is non-negative")
            .complete();
        let lhs2_h = pk0
            .h
            .pow_mod_ref(&exp_h0, &pk0.n)
            .expect("exponent is non-negative")
            .complete();
        let lhs2 = (lhs2_y * lhs2_h).modulo(&pk0.n);

        let c_prime_e = c_prime
            .pow_mod_ref(&e, &pk0.n)
            .expect("exponent is non-negative")
            .complete();
        let rhs2 = (c_prime_e * &self.d_prime).modulo(&pk0.n);

        lhs2 == rhs2
    }
}

/// Computes the Fiat-Shamir challenge.
fn fiat_shamir_challenge(
    pk: &JlPublicKey,
    pk0: &JlPublicKey,
    c: &Integer,
    c_prime: &Integer,
    d: &Integer,
    d_prime: &Integer,
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlEqu");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update(pk0.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk0.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk0.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk0.k.to_be_bytes());
    hasher.update(c.to_digits::<u8>(Order::Msf));
    hasher.update(c_prime.to_digits::<u8>(Order::Msf));
    hasher.update(d.to_digits::<u8>(Order::Msf));
    hasher.update(d_prime.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kgen::generate_keypair_with_params, zk::zkjl_com::jl_commit};

    #[test]
    fn zkjl_equ_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);
        let (pk0, _sk0) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let r = random_below(&pk.n, &mut rng);
        let r0 = random_below(&pk0.n, &mut rng);

        let c = jl_commit(&pk, &m, &r);
        let c_prime = jl_commit(&pk0, &m, &r0);

        let proof = ZkJlEquProof::prove(&pk, &pk0, &c, &c_prime, &m, &r, &r0, 32, &mut rng);
        assert!(proof.verify(&pk, &pk0, &c, &c_prime));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_equ_rejects_different_messages() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);
        let (pk0, _sk0) = generate_keypair_with_params(256, 32, &mut rng);

        let m1 = Integer::from(42u32);
        let m2 = Integer::from(99u32);
        let r = random_below(&pk.n, &mut rng);
        let r0 = random_below(&pk0.n, &mut rng);

        let c = jl_commit(&pk, &m1, &r);
        let c_prime = jl_commit(&pk0, &m2, &r0);

        // Try to prove equality with wrong message
        let proof = ZkJlEquProof::prove(&pk, &pk0, &c, &c_prime, &m1, &r, &r0, 32, &mut rng);
        assert!(!proof.verify(&pk, &pk0, &c, &c_prime));
    }
}
