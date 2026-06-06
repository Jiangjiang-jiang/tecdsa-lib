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

use rand_core::CryptoRngCore;
use rug::{Complete, Integer};
use serde::{Deserialize, Serialize};
use tecdsa_bigint::{mul_mod, pow_mod, random_below};

use crate::kgen::{JlPublicKey, JlSecretKey};

/// A ciphertext in the Joye-Libert scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlCiphertext {
    /// The ciphertext value `c` in `Z*_N`.
    pub c: Integer,
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
    m: &Integer,
    rng: &mut impl CryptoRngCore,
) -> (JlCiphertext, Integer) {
    let two_pow_k = Integer::from(1) << pk.k;
    assert!(m < &two_pow_k, "plaintext must be in Z_{{2^k}}");

    let r = random_below(&pk.n, rng);
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
pub fn encrypt_with_randomness(pk: &JlPublicKey, m: &Integer, r: &Integer) -> JlCiphertext {
    let two_pow_k = Integer::from(1) << pk.k;
    assert!(m < &two_pow_k, "plaintext must be in Z_{{2^k}}");

    // c = y^m * h^r mod N
    let y_m = pow_mod(&pk.y, m, &pk.n);
    let h_r = pow_mod(&pk.h, r, &pk.n);
    let c = mul_mod(&y_m, &h_r, &pk.n);

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
pub fn decrypt(sk: &JlSecretKey, pk: &JlPublicKey, ct: &JlCiphertext) -> Integer {
    let mut d =
        ct.c.pow_mod_ref(&Integer::from(&sk.p >> pk.k), &sk.p)
            .unwrap()
            .complete();
    let mut t = sk.y_to_neg_pp.clone();

    let mut m = Integer::new();

    for i in 0..pk.k {
        if d.pow_mod_ref(&(Integer::ONE << (pk.k - i - 1)).complete(), &sk.p)
            .unwrap()
            .complete()
            != *Integer::ONE
        {
            m.set_bit(i, true);
            d *= &t;
            d.modulo_mut(&sk.p);
        }
        t.square_mut();
        t.modulo_mut(&sk.p);
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
        let (pk, sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, _r) = encrypt(&pk, &m, &mut rng);
        let mm = decrypt(&sk, &pk, &ct);

        assert_eq!(m, mm);
    }
}
