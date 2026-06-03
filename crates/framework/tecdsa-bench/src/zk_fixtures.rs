// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared fixture builders for ZK proof benchmarks.
//!
//! **Profile B** (lambda=128, secp256k1):
//! - Paillier N = 3072 bit (two 1536-bit safe primes, fast-paillier default)
//! - CL |DeltaK| ~ 1827 bit (new_secp256k1_128bit)
//! - JL N = 3072 bit (p_bits=1536, k=256)
//! - NTilde = 3072 bit (two 1536-bit safe primes)
//! - Pedersen-mod = 1536-bit primes (3072-bit N)

use k256::Secp256k1;
use rand_core::OsRng;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::backend::Integer;

pub type C = Secp256k1;

pub fn random_scalar() -> k256::Scalar {
    C::random_scalar(&mut OsRng)
}

pub fn scalar_to_bytes(s: &k256::Scalar) -> Vec<u8> {
    tecdsa_curve::conv::scalar_to_bytes::<C>(s)
}

pub fn paillier_keys() -> (
    tecdsa_paillier::DecryptionKey,
    tecdsa_paillier::EncryptionKey,
) {
    let dk = tecdsa_paillier::DecryptionKey::generate(&mut OsRng).expect("paillier keygen");
    let ek = dk.encryption_key().clone();
    (dk, ek)
}

pub fn paillier_encrypt(
    ek: &tecdsa_paillier::EncryptionKey,
    plaintext: &Integer,
) -> (tecdsa_paillier::Ciphertext, tecdsa_paillier::Nonce) {
    ek.encrypt_with_random(&mut OsRng, plaintext)
        .expect("encrypt")
}

/// CL setup with 128-bit security (|DeltaK| ~ 1827 bit).
pub fn cl_setup() -> tecdsa_class_group::bicycl_glue::ClSetup {
    tecdsa_class_group::bicycl_glue::ClSetup::new_secp256k1_128bit("42042").expect("cl setup")
}

pub fn cl_setup_with_keys() -> (
    tecdsa_class_group::bicycl_glue::ClSetup,
    tecdsa_class_group::bicycl_glue::BicyclSecretKey,
    tecdsa_class_group::bicycl_glue::BicyclPublicKey,
) {
    let mut setup = cl_setup();
    let (sk, pk) = setup.keygen().expect("cl keygen");
    (setup, sk, pk)
}

pub fn sample_below(bound: &Integer) -> Integer {
    bound.random_below_ref(&mut OsRng)
}

pub fn group_order() -> Integer {
    tecdsa_paillier::conv::group_order_integer::<C>()
}

/// Ring-Pedersen auxiliary parameters (N_tilde, h1, h2).
/// Profile B: N_tilde = 3072 bit (two 1536-bit safe primes).
pub fn ntilde_params() -> (Integer, Integer, Integer) {
    let p = Integer::generate_safe_prime(&mut OsRng, 1536);
    let q = Integer::generate_safe_prime(&mut OsRng, 1536);
    let n_tilde = &p * &q;
    let h1 = Integer::sample_in_mult_group_of(&mut OsRng, &n_tilde);
    let lambda = (&p - Integer::one()) * (&q - Integer::one());
    let h2 = h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod for h2");
    (n_tilde, h1, h2)
}

pub fn pow_mod_signed(base: &Integer, exp: &Integer, modulus: &Integer) -> Integer {
    if exp.cmp0().is_lt() {
        let base_inv = base.invert_ref(modulus).expect("base must be invertible");
        let pos_exp = -exp.clone();
        base_inv.pow_mod_ref(&pos_exp, modulus).expect("pow_mod")
    } else {
        base.pow_mod_ref(exp, modulus).expect("pow_mod")
    }
}

/// JL keys: Profile B = N=3072 bit (p_bits=1536), k=256.
pub fn jl_keys() -> (
    tecdsa_joye_libert::kgen::JlPublicKey,
    tecdsa_joye_libert::kgen::JlSecretKey,
    num_bigint::BigUint,
) {
    tecdsa_joye_libert::kgen::generate_keypair_with_qnr(1536, 256, &mut OsRng)
}
