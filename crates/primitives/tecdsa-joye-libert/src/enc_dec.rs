use std::collections::BTreeMap;

use rand_core::CryptoRngCore;
use rug::{Complete, Integer};
use serde::{Deserialize, Serialize};
use tecdsa_bigint::{mul_mod, multi_exp, random_below};

use crate::kgen::{JlPublicKey, JlSecretKey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlCiphertext {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub c: Integer,
}

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

#[must_use]
pub fn encrypt_with_randomness(pk: &JlPublicKey, m: &Integer, r: &Integer) -> JlCiphertext {
    let two_pow_k = Integer::from(1) << pk.k;
    assert!(m < &two_pow_k, "plaintext must be in Z_{{2^k}}");

    let c = multi_exp(&[&pk.y, &pk.h], &[m, r], &pk.n);

    JlCiphertext { c }
}

#[must_use]
pub fn decrypt(sk: &JlSecretKey, pk: &JlPublicKey, ct: &JlCiphertext) -> Integer {
    let p = &sk.p;
    let k = pk.k;
    if k == 0 {
        return Integer::new();
    }

    let mut d =
        ct.c.pow_mod_ref(&Integer::from(p >> k), p)
            .unwrap()
            .complete();

    const W: u32 = 8;
    let w = W.min(k);

    let g = sk
        .y_to_neg_pp
        .clone()
        .invert(p)
        .expect("generator invertible mod p");
    let g_w = g
        .pow_mod_ref(&(Integer::ONE << (k - w)).complete(), p)
        .unwrap()
        .complete();

    let mut table: BTreeMap<Integer, u64> = BTreeMap::new();
    let mut cur = Integer::from(1);
    for j in 0..(1u64 << w) {
        table.insert(cur.clone(), j);
        cur = mul_mod(&cur, &g_w, p);
    }

    let mut m = Integer::new();
    let mut g_inv_block = sk.y_to_neg_pp.clone();
    let mut processed: u32 = 0;
    while processed < k {
        let width = w.min(k - processed);
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
            let factor = g_inv_block
                .pow_mod_ref(&Integer::from(x_block), p)
                .unwrap()
                .complete();
            d = mul_mod(&d, &factor, p);
        }
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
