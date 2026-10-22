// SPDX-License-Identifier: MIT OR Apache-2.0
use rug::Integer;
use tecdsa_paillier::BigIntExt;

fn test_dk() -> tecdsa_paillier::DecryptionKey {
    // Use small primes for fast tests.
    let p = Integer::generate_safe_prime(&mut rand::thread_rng(), 256);
    let q = Integer::generate_safe_prime(&mut rand::thread_rng(), 256);
    tecdsa_paillier::DecryptionKey::from_primes(p, q).expect("valid primes")
}

#[test]
fn paillier_enc_dec_roundtrip() {
    let dk = test_dk();
    let ek = dk.encryption_key();
    let mut rng = rand::thread_rng();

    let plaintext = Integer::from(42);
    let (ciphertext, _nonce) = ek
        .encrypt_with_random(&mut rng, &plaintext)
        .expect("encrypt");
    let recovered = dk.decrypt(&ciphertext).expect("decrypt");
    assert_eq!(recovered, plaintext);
}

#[test]
fn paillier_homomorphic_add() {
    let dk = test_dk();
    let ek = dk.encryption_key();
    let mut rng = rand::thread_rng();

    let a = Integer::from(17);
    let b = Integer::from(25);
    let (ca, _) = ek.encrypt_with_random(&mut rng, &a).expect("encrypt a");
    let (cb, _) = ek.encrypt_with_random(&mut rng, &b).expect("encrypt b");

    let c_sum = ek.oadd(&ca, &cb).expect("add");
    let result = dk.decrypt(&c_sum).expect("decrypt sum");
    assert_eq!(result, Integer::from(42));
}

#[test]
fn paillier_homomorphic_scalar_mul() {
    let dk = test_dk();
    let ek = dk.encryption_key();
    let mut rng = rand::thread_rng();

    let plaintext = Integer::from(7);
    let scalar = Integer::from(6);
    let (ciphertext, _) = ek
        .encrypt_with_random(&mut rng, &plaintext)
        .expect("encrypt");

    let c_product = ek.omul(&scalar, &ciphertext).expect("scalar mul");
    let result = dk.decrypt(&c_product).expect("decrypt product");
    assert_eq!(result, Integer::from(42));
}
