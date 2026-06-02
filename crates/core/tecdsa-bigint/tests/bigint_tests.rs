// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_bigint::{gcd, generate_safe_prime, is_safe_prime, jacobi, tonelli_shanks, DynInt};

#[test]
fn jacobi_known_values() {
    // 2 is a QR mod 7 (squares mod 7 = {1,2,4}) → Jacobi(2/7) = 1
    assert_eq!(jacobi(&DynInt::from(2u64), &DynInt::from(7u64)), 1);
    assert_eq!(jacobi(&DynInt::from(1u64), &DynInt::from(7u64)), 1);
    assert_eq!(jacobi(&DynInt::from(0u64), &DynInt::from(7u64)), 0);
    // 2 is a NQR mod 5 (squares mod 5 = {1,4}) → Jacobi(2/5) = -1
    assert_eq!(jacobi(&DynInt::from(2u64), &DynInt::from(5u64)), -1);
    assert_eq!(jacobi(&DynInt::from(3u64), &DynInt::from(5u64)), -1);
    assert_eq!(jacobi(&DynInt::from(4u64), &DynInt::from(5u64)), 1);
}

#[test]
fn gcd_basic() {
    assert_eq!(
        gcd(&DynInt::from(12u64), &DynInt::from(8u64)),
        DynInt::from(4u64)
    );
    assert_eq!(
        gcd(&DynInt::from(17u64), &DynInt::from(13u64)),
        DynInt::from(1u64)
    );
}

#[test]
fn tonelli_shanks_known_square_root() {
    let r = tonelli_shanks(&DynInt::from(4u64), &DynInt::from(7u64)).unwrap();
    let r_sq = &r * &r % DynInt::from(7u64);
    assert_eq!(r_sq, DynInt::from(4u64));
}

#[test]
fn tonelli_shanks_non_residue_returns_none() {
    assert!(tonelli_shanks(&DynInt::from(3u64), &DynInt::from(7u64)).is_none());
}

#[test]
fn safe_prime_check() {
    assert!(is_safe_prime(&DynInt::from(11u64)));
    assert!(!is_safe_prime(&DynInt::from(13u64)));
}

#[test]
fn generate_safe_prime_produces_valid() {
    let mut rng = rand::thread_rng();
    let p = generate_safe_prime(64, &mut rng);
    assert!(is_safe_prime(&p));
}

#[test]
fn dyn_int_from_to_bytes_roundtrip() {
    let val = DynInt::from(0xDEAD_BEEFu64);
    let bytes = val.to_bytes_be();
    let recovered = DynInt::from_bytes_be(&bytes);
    assert_eq!(val, recovered);
}
