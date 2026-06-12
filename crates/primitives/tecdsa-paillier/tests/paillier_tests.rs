use tecdsa_paillier::{add_ciphertexts, backend::Integer, decrypt, encrypt, scalar_mul_ciphertext};

fn test_dk() -> tecdsa_paillier::DecryptionKey {
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
    let (ciphertext, _nonce) = encrypt(ek, &mut rng, &plaintext).expect("encrypt");
    let recovered = decrypt(&dk, &ciphertext).expect("decrypt");
    assert_eq!(recovered, plaintext);
}

#[test]
fn paillier_homomorphic_add() {
    let dk = test_dk();
    let ek = dk.encryption_key();
    let mut rng = rand::thread_rng();

    let a = Integer::from(17);
    let b = Integer::from(25);
    let (ca, _) = encrypt(ek, &mut rng, &a).expect("encrypt a");
    let (cb, _) = encrypt(ek, &mut rng, &b).expect("encrypt b");

    let c_sum = add_ciphertexts(ek, &ca, &cb).expect("add");
    let result = decrypt(&dk, &c_sum).expect("decrypt sum");
    assert_eq!(result, Integer::from(42));
}

#[test]
fn paillier_homomorphic_scalar_mul() {
    let dk = test_dk();
    let ek = dk.encryption_key();
    let mut rng = rand::thread_rng();

    let plaintext = Integer::from(7);
    let scalar = Integer::from(6);
    let (ciphertext, _) = encrypt(ek, &mut rng, &plaintext).expect("encrypt");

    let c_product = scalar_mul_ciphertext(ek, &scalar, &ciphertext).expect("scalar mul");
    let result = decrypt(&dk, &c_product).expect("decrypt product");
    assert_eq!(result, Integer::from(42));
}
