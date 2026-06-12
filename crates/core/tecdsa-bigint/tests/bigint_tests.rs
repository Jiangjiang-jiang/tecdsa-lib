use rug::{integer::Order, Integer};
use tecdsa_bigint::{gcd, generate_safe_prime, is_safe_prime, jacobi, tonelli_shanks};

#[test]
fn jacobi_known_values() {
    assert_eq!(jacobi(&Integer::from(2u64), &Integer::from(7u64)), 1);
    assert_eq!(jacobi(&Integer::from(1u64), &Integer::from(7u64)), 1);
    assert_eq!(jacobi(&Integer::from(0u64), &Integer::from(7u64)), 0);
    assert_eq!(jacobi(&Integer::from(2u64), &Integer::from(5u64)), -1);
    assert_eq!(jacobi(&Integer::from(3u64), &Integer::from(5u64)), -1);
    assert_eq!(jacobi(&Integer::from(4u64), &Integer::from(5u64)), 1);
}

#[test]
fn gcd_basic() {
    assert_eq!(
        gcd(&Integer::from(12u64), &Integer::from(8u64)),
        Integer::from(4u64)
    );
    assert_eq!(
        gcd(&Integer::from(17u64), &Integer::from(13u64)),
        Integer::from(1u64)
    );
}

#[test]
fn tonelli_shanks_known_square_root() {
    let r = tonelli_shanks(&Integer::from(4u64), &Integer::from(7u64)).unwrap();
    let r_sq = Integer::from(&r * &r) % Integer::from(7u64);
    assert_eq!(r_sq, Integer::from(4u64));
}

#[test]
fn tonelli_shanks_non_residue_returns_none() {
    assert!(tonelli_shanks(&Integer::from(3u64), &Integer::from(7u64)).is_none());
}

#[test]
fn safe_prime_check() {
    assert!(is_safe_prime(&Integer::from(11u64)));
    assert!(!is_safe_prime(&Integer::from(13u64)));
}

#[test]
fn generate_safe_prime_produces_valid() {
    let mut rng = rand::thread_rng();
    let p = generate_safe_prime(64, &mut rng);
    assert!(is_safe_prime(&p));
}

#[test]
fn integer_from_to_bytes_roundtrip() {
    let val = Integer::from(0xDEAD_BEEFu64);
    let n = val.significant_digits::<u8>();
    let mut bytes = vec![0u8; n];
    val.write_digits(&mut bytes, Order::Msf);
    let recovered = Integer::from_digits(&bytes, Order::Msf);
    assert_eq!(val, recovered);
}
