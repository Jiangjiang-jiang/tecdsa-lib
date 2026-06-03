// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encryption and decryption for the Joye-Libert scheme.
//!
//! # Encryption
//!
//! `Enc(pk, m, r) = y^m * h^r mod N` where `m` is in `Z_{2^k}` and
//! `r` is random in `Z_N`.
//!
//! # Decryption
//!
//! Decryption recovers the plaintext by computing the 2-adic valuation
//! of a certain power residue symbol, bit by bit.

use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::kgen::{JlPublicKey, JlSecretKey};

/// A ciphertext in the Joye-Libert scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlCiphertext {
    /// The ciphertext value `c` in `Z*_N`.
    pub c: BigUint,
}

/// Encrypts a plaintext `m` in `Z_{2^k}` under the given public key.
///
/// Returns the ciphertext and the randomness used (for proof construction).
///
/// # Panics
///
/// Panics if `m >= 2^k`.
pub fn encrypt(
    pk: &JlPublicKey,
    m: &BigUint,
    rng: &mut impl CryptoRngCore,
) -> (JlCiphertext, BigUint) {
    let two_pow_k = BigUint::one() << pk.k;
    assert!(m < &two_pow_k, "plaintext must be in Z_{{2^k}}");

    let r = rng.gen_biguint_below(&pk.n);
    let ct = encrypt_with_randomness(pk, m, &r);
    (ct, r)
}

/// Encrypts a plaintext `m` with a specific randomness value `r`.
///
/// `Enc(pk, m, r) = y^m * h^r mod N`
///
/// # Panics
///
/// Panics if `m >= 2^k`.
#[must_use]
pub fn encrypt_with_randomness(pk: &JlPublicKey, m: &BigUint, r: &BigUint) -> JlCiphertext {
    let two_pow_k = BigUint::one() << pk.k;
    assert!(m < &two_pow_k, "plaintext must be in Z_{{2^k}}");

    // c = y^m * h^r mod N
    let y_m = pk.y.modpow(m, &pk.n);
    let h_r = pk.h.modpow(r, &pk.n);
    let c = (&y_m * &h_r) % &pk.n;

    JlCiphertext { c }
}

/// Decrypts a ciphertext to recover the plaintext in `Z_{2^k}`.
///
/// Uses the bit-by-bit extraction algorithm based on power residue symbols.
///
/// The algorithm works as follows:
/// For `i = 1, 2, ..., k-1`:
///   1. Compute the `(p-1)/2^i`-th power of the ciphertext modulo `p`
///   2. Compute the `(p-1)/2^i`-th power of `y` modulo `p`, raised to the
///      current partial message
///   3. If they differ, set bit `i-1` of the message to 1
///
/// This is the standard Joye-Libert decryption from the original paper.
#[must_use]
pub fn decrypt(sk: &JlSecretKey, pk: &JlPublicKey, ct: &JlCiphertext) -> BigUint {
    let one = BigUint::one();
    let p = &sk.p;
    let p_minus_1 = p - &one;

    let mut m = BigUint::zero();
    let mut bit_value = BigUint::one(); // Tracks 2^(i-1)

    for i in 1..pk.k {
        // Compute exponent e_i = (p-1) / 2^i
        let exp_i = &p_minus_1 >> i;

        // z = c^{(p-1)/2^i} mod p — the power residue symbol of the ciphertext
        let z = ct.c.modpow(&exp_i, p);

        // t = y^{(p-1)/2^i} mod p — the power residue symbol of the generator
        let t_base = pk.y.modpow(&exp_i, p);

        // t_m = t_base^m mod p — accounts for known bits of m
        let t_m = t_base.modpow(&m, p);

        // If z != t_m, then bit (i-1) of m is 1
        if z != t_m {
            m += &bit_value;
        }

        bit_value <<= 1u32;
    }

    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_params;

    #[test]
    fn encrypt_produces_nonzero_ciphertext() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = BigUint::from(42u32);
        let (ct, _r) = encrypt(&pk, &m, &mut rng);

        assert!(!ct.c.is_zero());
    }
}
