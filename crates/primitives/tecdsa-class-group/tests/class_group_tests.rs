use rug::{integer::Order, Integer};
use tecdsa_bigint::mul_mod;
use tecdsa_class_group::{cl::ClSetup, nim::Nim};

fn q() -> Integer {
    Integer::from_str_radix(
        "115792089237316195423570985008687907852837564279074904382605163141518161494337",
        10,
    )
    .unwrap()
}

#[test]
fn cl_enc_dec_roundtrip() {
    let mut setup = ClSetup::new_secp256k1("100").expect("setup failed");
    let (sk, pk) = setup.keygen().expect("keygen failed");

    let plaintext = Integer::from(42u32);
    let ct = setup
        .encrypt_bytes(&pk, &plaintext.to_digits::<u8>(Order::Msf))
        .expect("encrypt failed");
    let decrypted = Integer::from_digits(
        &setup.decrypt_bytes(&sk, &ct).expect("decrypt failed"),
        Order::Msf,
    );
    assert_eq!(decrypted, plaintext, "roundtrip failed for plaintext=42");

    let zero = Integer::from(0u32);
    let ct_zero = setup
        .encrypt_bytes(&pk, &zero.to_digits::<u8>(Order::Msf))
        .expect("encrypt zero failed");
    let dec_zero = Integer::from_digits(
        &setup
            .decrypt_bytes(&sk, &ct_zero)
            .expect("decrypt zero failed"),
        Order::Msf,
    );
    assert_eq!(dec_zero, zero, "roundtrip failed for plaintext=0");

    let large = Integer::from(123_456_789u64);
    let ct_large = setup
        .encrypt_bytes(&pk, &large.to_digits::<u8>(Order::Msf))
        .expect("encrypt large failed");
    let dec_large = Integer::from_digits(
        &setup
            .decrypt_bytes(&sk, &ct_large)
            .expect("decrypt large failed"),
        Order::Msf,
    );
    assert_eq!(dec_large, large, "roundtrip failed for large plaintext");
}

#[test]
fn cl_homomorphic_add() {
    let mut setup = ClSetup::new_secp256k1("200").expect("setup failed");
    let (sk, pk) = setup.keygen().expect("keygen failed");

    let a = Integer::from(100u32);
    let b = Integer::from(200u32);

    let ct_a = setup
        .encrypt_bytes(&pk, &a.to_digits::<u8>(Order::Msf))
        .expect("encrypt a");
    let ct_b = setup
        .encrypt_bytes(&pk, &b.to_digits::<u8>(Order::Msf))
        .expect("encrypt b");

    let ct_sum = setup.add_ciphertexts(&pk, &ct_a, &ct_b).expect("hadd");
    let sum = Integer::from_digits(
        &setup.decrypt_bytes(&sk, &ct_sum).expect("decrypt sum"),
        Order::Msf,
    );

    let expected = Integer::from(&a + &b) % q();
    assert_eq!(sum, expected, "homomorphic add failed: {sum} != {expected}");
}

#[test]
fn cl_homomorphic_scalar_mul() {
    let mut setup = ClSetup::new_secp256k1("300").expect("setup failed");
    let (sk, pk) = setup.keygen().expect("keygen failed");

    let m = Integer::from(7u32);
    let s = Integer::from(6u32);

    let ct_m = setup
        .encrypt_bytes(&pk, &m.to_digits::<u8>(Order::Msf))
        .expect("encrypt m");
    let ct_scaled = setup
        .scal_ciphertext_bytes(&pk, &ct_m, &s.to_digits::<u8>(Order::Msf))
        .expect("hscmul");
    let result = Integer::from_digits(
        &setup
            .decrypt_bytes(&sk, &ct_scaled)
            .expect("decrypt scaled"),
        Order::Msf,
    );

    let expected = mul_mod(&m, &s, &q());
    assert_eq!(
        result, expected,
        "homomorphic scalar mul failed: {result} != {expected}"
    );
}

#[test]
#[allow(clippy::similar_names)]
fn nim_correctness() {
    let mut setup = ClSetup::new_secp256k1("500").expect("setup failed");
    let (_sk, pk) = setup.keygen().expect("keygen");

    let x_val = Integer::from(1234u32);
    let y_val = Integer::from(5678u32);
    let x_bytes = x_val.to_digits::<u8>(Order::Msf);
    let y_bytes = y_val.to_digits::<u8>(Order::Msf);

    let mut nim = Nim::new(&mut setup);

    let encode_a_out = nim.encode_a(&x_bytes, &pk).expect("encode_a");

    let encode_b_out = nim.encode_b(&y_bytes, &pk).expect("encode_b");

    let share_a = nim
        .decode_a(&encode_b_out.pe_b, &encode_a_out.state)
        .expect("decode_a");

    let share_b = nim
        .decode_b(&encode_a_out.pe_a, &encode_b_out.state)
        .expect("decode_b");

    let q = q();
    let z_a = Integer::from_digits(&share_a, Order::Msf);
    let z_b = Integer::from_digits(&share_b, Order::Msf);
    let xy = mul_mod(&x_val, &y_val, &q);
    let sum = Integer::from(&z_a + &z_b) % &q;

    assert_eq!(
        sum, xy,
        "NIM correctness failed: z_A({z_a}) + z_B({z_b}) = {sum} != x*y = {xy}"
    );
}
