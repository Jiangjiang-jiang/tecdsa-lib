// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests for `tecdsa-class-group`.

use num_bigint::BigUint;
use num_traits::Num;

use tecdsa_class_group::bicycl_glue::ClSetup;
use tecdsa_class_group::cl_enc;
use tecdsa_class_group::nim::Nim;

/// The secp256k1 curve order.
fn q() -> BigUint {
    BigUint::from_str_radix(
        "115792089237316195423570985008687907852837564279074904382605163141518161494337",
        10,
    )
    .unwrap()
}

#[test]
fn cl_enc_dec_roundtrip() {
    let mut setup = ClSetup::new_secp256k1("100").expect("setup failed");
    let (pk, sk) = cl_enc::keygen(&mut setup).expect("keygen failed");

    // Encrypt and decrypt a small value.
    let plaintext = BigUint::from(42u32);
    let ct = cl_enc::encrypt(&mut setup, &pk, &plaintext).expect("encrypt failed");
    let decrypted = cl_enc::decrypt(&setup, &sk, &ct).expect("decrypt failed");
    assert_eq!(decrypted, plaintext, "roundtrip failed for plaintext=42");

    // Encrypt and decrypt zero.
    let zero = BigUint::from(0u32);
    let ct_zero = cl_enc::encrypt(&mut setup, &pk, &zero).expect("encrypt zero failed");
    let dec_zero = cl_enc::decrypt(&setup, &sk, &ct_zero).expect("decrypt zero failed");
    assert_eq!(dec_zero, zero, "roundtrip failed for plaintext=0");

    // Encrypt and decrypt a larger value.
    let large = BigUint::from(123_456_789u64);
    let ct_large = cl_enc::encrypt(&mut setup, &pk, &large).expect("encrypt large failed");
    let dec_large = cl_enc::decrypt(&setup, &sk, &ct_large).expect("decrypt large failed");
    assert_eq!(dec_large, large, "roundtrip failed for large plaintext");
}

#[test]
fn cl_homomorphic_add() {
    let mut setup = ClSetup::new_secp256k1("200").expect("setup failed");
    let (pk, sk) = cl_enc::keygen(&mut setup).expect("keygen failed");

    let a = BigUint::from(100u32);
    let b = BigUint::from(200u32);

    let ct_a = cl_enc::encrypt(&mut setup, &pk, &a).expect("encrypt a");
    let ct_b = cl_enc::encrypt(&mut setup, &pk, &b).expect("encrypt b");

    let ct_sum = cl_enc::hadd(&mut setup, &pk, &ct_a, &ct_b).expect("hadd");
    let sum = cl_enc::decrypt(&setup, &sk, &ct_sum).expect("decrypt sum");

    let expected = (&a + &b) % q();
    assert_eq!(sum, expected, "homomorphic add failed: {sum} != {expected}");
}

#[test]
fn cl_homomorphic_scalar_mul() {
    let mut setup = ClSetup::new_secp256k1("300").expect("setup failed");
    let (pk, sk) = cl_enc::keygen(&mut setup).expect("keygen failed");

    let m = BigUint::from(7u32);
    let s = BigUint::from(6u32);

    let ct_m = cl_enc::encrypt(&mut setup, &pk, &m).expect("encrypt m");
    let ct_scaled = cl_enc::hscmul(&mut setup, &pk, &s, &ct_m).expect("hscmul");
    let result = cl_enc::decrypt(&setup, &sk, &ct_scaled).expect("decrypt scaled");

    let expected = (&m * &s) % q();
    assert_eq!(
        result, expected,
        "homomorphic scalar mul failed: {result} != {expected}"
    );
}

#[test]
#[allow(clippy::similar_names)]
fn nim_correctness() {
    let mut setup = ClSetup::new_secp256k1("500").expect("setup failed");
    // Single CRS key pair shared by both parties.
    let (_sk, pk) = setup.keygen().expect("keygen");

    let x_val = BigUint::from(1234u32);
    let y_val = BigUint::from(5678u32);
    let x_bytes = x_val.to_bytes_be();
    let y_bytes = y_val.to_bytes_be();

    let mut nim = Nim::new(&mut setup);

    // Party A encodes
    let encode_a_out = nim.encode_a(&x_bytes, &pk).expect("encode_a");

    // Party B encodes
    let encode_b_out = nim.encode_b(&y_bytes, &pk).expect("encode_b");

    // Party A decodes using pe_B
    let share_a = nim
        .decode_a(&encode_b_out.pe_b, &encode_a_out.state)
        .expect("decode_a");

    // Party B decodes using pe_A
    let share_b = nim
        .decode_b(&encode_a_out.pe_a, &encode_b_out.state)
        .expect("decode_b");

    // Verify correctness: z_A + z_B = x * y mod q
    let q = q();
    let z_a = BigUint::from_bytes_be(&share_a);
    let z_b = BigUint::from_bytes_be(&share_b);
    let xy = (&x_val * &y_val) % &q;
    let sum = (&z_a + &z_b) % &q;

    assert_eq!(
        sum, xy,
        "NIM correctness failed: z_A({z_a}) + z_B({z_b}) = {sum} != x*y = {xy}"
    );
}
