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

use std::collections::BTreeMap;

use rand_core::CryptoRngCore;
use rug::{Complete, Integer};
use serde::{Deserialize, Serialize};
use tecdsa_bigint::{mul_mod, multi_exp, random_below};

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

    // c = y^m * h^r mod N, via one shared-squaring multi-exponentiation.
    let c = multi_exp(&[&pk.y, &pk.h], &[m, r], &pk.n);

    JlCiphertext { c }
}

/// Decrypts a ciphertext to recover the plaintext in `Z_{2^k}`.
///
/// This recovers the discrete log `m` of `d = c^{(p-1)/2^k} = g^m` in the cyclic
/// 2-group of order `2^k` (where `g` is the fixed generator with
/// `g^{-1} = sk.y_to_neg_pp`), i.e. the standard Joye-Libert decryption.
///
/// The textbook version peels one bit per step, recomputing `d^{2^{k-i-1}}` from
/// scratch each time, which costs `~k^2/2` modular squarings — at the MtA
/// parameter `k ≈ 712` that is `~250k` squarings per decryption. This is a
/// **windowed (radix-`2^W`) Pohlig-Hellman**: a one-time baby-step table for the
/// order-`2^W` subgroup lets us recover `W` bits per step, cutting the squaring
/// count to `~k^2/(2W)` (≈ `W×` fewer) while producing the identical plaintext.
#[must_use]
pub fn decrypt(sk: &JlSecretKey, pk: &JlPublicKey, ct: &JlCiphertext) -> Integer {
    let p = &sk.p;
    let k = pk.k;
    if k == 0 {
        return Integer::new();
    }

    // d = c^{(p-1)/2^k} lands in the order-2^k subgroup; d = g^m where g is the
    // fixed generator with g^{-1} = sk.y_to_neg_pp.
    let mut d =
        ct.c.pow_mod_ref(&Integer::from(p >> k), p)
            .unwrap()
            .complete();

    // Window width (bits recovered per step). Larger W => fewer squarings but a
    // larger (2^W-entry) baby-step table; 8 is a good single-threaded balance.
    const W: u32 = 8;
    let w = W.min(k);

    // g = inverse of the stored g^{-1}; g_w = g^{2^{k-w}} generates the order-2^w
    // subgroup whose elements index the per-block digit table.
    let g = sk
        .y_to_neg_pp
        .clone()
        .invert(p)
        .expect("generator invertible mod p");
    let g_w = g
        .pow_mod_ref(&(Integer::ONE << (k - w)).complete(), p)
        .unwrap()
        .complete();

    // Baby-step table: g_w^j -> j for j in [0, 2^w).
    let mut table: BTreeMap<Integer, u64> = BTreeMap::new();
    let mut cur = Integer::from(1);
    for j in 0..(1u64 << w) {
        table.insert(cur.clone(), j);
        cur = mul_mod(&cur, &g_w, p);
    }

    let mut m = Integer::new();
    // g_inv_block = g^{-2^{processed}} (starts at g^{-1} for processed = 0).
    let mut g_inv_block = sk.y_to_neg_pp.clone();
    let mut processed: u32 = 0;
    while processed < k {
        let width = w.min(k - processed);
        // val = d^{2^{k-processed-width}} = g_w^{x_block * 2^{w-width}} lies in the
        // order-2^w subgroup; recover the next `width` bits as `x_block`.
        let e = k - processed - width;
        let mut val = d.clone();
        for _ in 0..e {
            val.square_mut();
            val.modulo_mut(p);
        }
        let raw = *table
            .get(&val)
            .expect("decrypt: digit must be in baby-step table (well-formed ciphertext)");
        let x_block = raw >> (w - width);
        if x_block != 0 {
            m += Integer::from(x_block) << processed;
            // d *= g^{-x_block * 2^{processed}} = g_inv_block^{x_block}.
            let factor = g_inv_block
                .pow_mod_ref(&Integer::from(x_block), p)
                .unwrap()
                .complete();
            d = mul_mod(&d, &factor, p);
        }
        // Advance g_inv_block by `width` squarings for the next block.
        for _ in 0..width {
            g_inv_block.square_mut();
            g_inv_block.modulo_mut(p);
        }
        processed += width;
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

    /// Round-trip a range of plaintexts, including the boundaries `0` and
    /// `2^k - 1`, for both a window-aligned `k` and a non-aligned `k` (which
    /// exercises the windowed decryption's partial final block).
    #[test]
    fn decrypt_roundtrip_edges_and_partial_block() {
        let mut rng = rand::thread_rng();
        for k in [32u32, 13u32] {
            let (pk, sk) = generate_keypair_with_params(256, k, &mut rng);
            let max = (Integer::from(1) << k) - Integer::from(1);
            let mut cases = vec![
                Integer::new(),
                Integer::from(1u32),
                max.clone(),
                &max - Integer::from(1),
            ];
            for _ in 0..8 {
                cases.push(random_below(&(Integer::from(1) << k), &mut rng));
            }
            for m in cases {
                let (ct, _r) = encrypt(&pk, &m, &mut rng);
                assert_eq!(decrypt(&sk, &pk, &ct), m, "round-trip failed at k={k}");
            }
        }
    }
}
