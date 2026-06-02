// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared fixture builders for ZK proof benchmarks.

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

pub fn cl_setup() -> tecdsa_class_group::bicycl_glue::ClSetup {
    tecdsa_class_group::bicycl_glue::ClSetup::new_secp256k1("42042").expect("cl setup")
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

pub fn jl_keys() -> (
    tecdsa_joye_libert::kgen::JlPublicKey,
    tecdsa_joye_libert::kgen::JlSecretKey,
    num_bigint::BigUint,
) {
    tecdsa_joye_libert::kgen::generate_keypair_with_qnr(256, 32, &mut OsRng)
}
