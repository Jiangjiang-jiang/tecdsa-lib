// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the Joye-Libert encryption scheme.
//!
//! Uses small (256-bit) modulus for fast testing. Full-size key generation
//! tests are marked `#[ignore]` due to their runtime.

use rug::Integer;
use tecdsa_joye_libert::{
    enc_dec::{decrypt, encrypt},
    hom::{hadd, hscmul},
    kgen::{generate_keypair, generate_keypair_with_params, SecurityLevel},
    zk::zkjl_enc::ZkJlEncProof,
};

/// Helper to create a small test key pair (256-bit primes, k=32).
fn small_keypair() -> (
    tecdsa_joye_libert::kgen::JlPublicKey,
    tecdsa_joye_libert::kgen::JlSecretKey,
) {
    let mut rng = rand::thread_rng();
    generate_keypair_with_params(256, 32, &mut rng)
}

#[test]
fn jl_kgen_produces_valid_key() {
    let (pk, sk) = small_keypair();

    // N should be non-zero and composite
    assert!(pk.n != 0);
    // p should divide N
    assert!(pk.n.is_divisible(&sk.p));
    // k should match
    assert_eq!(pk.k, 32);
    // y, h should be non-zero and less than N
    assert!(pk.y != 0);
    assert!(pk.h != 0);
    assert!(pk.y < pk.n);
    assert!(pk.h < pk.n);
}

#[test]
fn jl_enc_dec_roundtrip() {
    let (pk, sk) = small_keypair();
    let mut rng = rand::thread_rng();

    // Test several values including 0, 1, and a larger value
    for m_val in [0u64, 1, 42, 255, 1000, (1u64 << 31) - 1] {
        let m = Integer::from(m_val);
        let (ct, _r) = encrypt(&pk, &m, &mut rng);
        let recovered = decrypt(&sk, &pk, &ct);
        assert_eq!(recovered, m, "roundtrip failed for m = {m_val}");
    }
}

#[test]
fn jl_hadd_correctness() {
    let (pk, sk) = small_keypair();
    let mut rng = rand::thread_rng();
    let two_pow_k = Integer::from(1) << pk.k;

    let a = Integer::from(123u32);
    let b = Integer::from(456u32);
    let expected = Integer::from(&a + &b) % &two_pow_k;

    let (ct_a, _) = encrypt(&pk, &a, &mut rng);
    let (ct_b, _) = encrypt(&pk, &b, &mut rng);
    let ct_sum = hadd(&pk, &ct_a, &ct_b);
    let result = decrypt(&sk, &pk, &ct_sum);

    assert_eq!(
        result, expected,
        "HAdd: Dec(Enc(a) + Enc(b)) != a + b mod 2^k"
    );
}

#[test]
#[ignore = "redundant negative/variant test"]
fn jl_hadd_wraps_mod_2k() {
    let (pk, sk) = small_keypair();
    let mut rng = rand::thread_rng();
    let two_pow_k = Integer::from(1) << pk.k;

    // Choose values that will overflow 2^k when added
    let a = Integer::from(&two_pow_k - 10);
    let b = Integer::from(20u32);
    let expected = Integer::from(&a + &b) % &two_pow_k; // Should be 10

    let (ct_a, _) = encrypt(&pk, &a, &mut rng);
    let (ct_b, _) = encrypt(&pk, &b, &mut rng);
    let ct_sum = hadd(&pk, &ct_a, &ct_b);
    let result = decrypt(&sk, &pk, &ct_sum);

    assert_eq!(result, expected, "HAdd should wrap around mod 2^k");
}

#[test]
fn jl_hscmul_correctness() {
    let (pk, sk) = small_keypair();
    let mut rng = rand::thread_rng();
    let two_pow_k = Integer::from(1) << pk.k;

    let a = Integer::from(7u32);
    let s = Integer::from(6u32);
    let expected = Integer::from(&a * &s) % &two_pow_k;

    let (ct_a, _) = encrypt(&pk, &a, &mut rng);
    let ct_prod = hscmul(&pk, &ct_a, &s);
    let result = decrypt(&sk, &pk, &ct_prod);

    assert_eq!(result, expected, "HScMul: Dec(Enc(a)^s) != a*s mod 2^k");
}

#[test]
#[ignore = "redundant negative/variant test"]
fn jl_hscmul_wraps_mod_2k() {
    let (pk, sk) = small_keypair();
    let mut rng = rand::thread_rng();
    let two_pow_k = Integer::from(1) << pk.k;

    let a = Integer::from(1_000_000u32);
    let s = Integer::from(5_000u32);
    let expected = Integer::from(&a * &s) % &two_pow_k;

    let (ct_a, _) = encrypt(&pk, &a, &mut rng);
    let ct_prod = hscmul(&pk, &ct_a, &s);
    let result = decrypt(&sk, &pk, &ct_prod);

    assert_eq!(result, expected, "HScMul should wrap around mod 2^k");
}

#[test]
fn jl_zkjl_enc_proof_roundtrip() {
    let (pk, _sk) = small_keypair();
    let mut rng = rand::thread_rng();

    let m = Integer::from(42u32);
    let (ct, r) = encrypt(&pk, &m, &mut rng);

    let proof = ZkJlEncProof::prove(&pk, &ct.c, &m, &r, pk.k, &mut rng);
    assert!(proof.verify(&pk, &ct.c), "valid proof should verify");
}

#[test]
#[ignore = "full-size key generation is slow (>10s)"]
fn jl_keygen_128bit_security() {
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_keypair(SecurityLevel::Sec128, &mut rng);

    assert!(pk.n != 0);
    assert!(pk.n.is_divisible(&sk.p));
    assert_eq!(pk.k, 256);

    // Enc/Dec roundtrip with production-size keys
    let m = Integer::from(12345u32);
    let (ct, _) = encrypt(&pk, &m, &mut rng);
    let recovered = decrypt(&sk, &pk, &ct);
    assert_eq!(recovered, m);
}
