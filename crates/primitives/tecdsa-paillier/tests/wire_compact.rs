// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wire-size regression tests for the compact big-integer serde format.
//!
//! `rug`'s default serde encodes integers as radix-16 strings, costing two
//! bytes of wire per byte of integer. The vendored `fast-paillier` backend and
//! `tecdsa_bigint::int_wire` instead encode `(sign, magnitude-bytes)`, so a
//! b-bit integer must serialize under bincode to about `b/8` bytes plus a few
//! bytes of framing. These tests pin that property so a serde regression
//! cannot silently double every ciphertext on the wire again.

use fast_paillier::backend::Integer;

fn wire_size<T: serde::Serialize>(value: &T) -> usize {
    bincode::serde::encode_to_vec(value, bincode::config::standard())
        .expect("serializable")
        .len()
}

/// Allowed framing overhead (sign byte + length varint + container framing).
const SLACK: usize = 16;

#[test]
fn paillier_ciphertext_is_compact() {
    // A Paillier ciphertext for a 3072-bit modulus lives in Z_{N^2}: 6144 bits.
    let ct: fast_paillier::Ciphertext = (Integer::one() << 6144_u32) - Integer::one();
    let size = wire_size(&ct);
    assert!(size >= 768, "6144-bit ciphertext cannot fit in {size} B");
    assert!(
        size <= 768 + SLACK,
        "6144-bit ciphertext serializes to {size} B; compact format lost"
    );
}

#[test]
fn paillier_encryption_key_is_compact() {
    let n: Integer = (Integer::one() << 3072_u32) - Integer::one();
    let ek = fast_paillier::EncryptionKey::from_n(n);
    let size = wire_size(&ek);
    assert!(
        (384..=384 + SLACK).contains(&size),
        "3072-bit encryption key serializes to {size} B"
    );
}

#[test]
fn negative_integer_roundtrips() {
    let x = -((Integer::one() << 2047_u32) + Integer::one());
    let bytes = bincode::serde::encode_to_vec(&x, bincode::config::standard()).unwrap();
    let (x2, _): (Integer, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(x, x2);
}

#[test]
fn rug_int_wire_is_compact() {
    #[derive(serde::Serialize)]
    struct Wire {
        #[serde(with = "tecdsa_bigint::int_wire")]
        n: rug::Integer,
    }
    let w = Wire {
        n: (rug::Integer::from(1) << 3072_u32) - 1u8,
    };
    let size = wire_size(&w);
    assert!(
        (384..=384 + SLACK).contains(&size),
        "3072-bit rug integer serializes to {size} B"
    );
}
