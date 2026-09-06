// SPDX-License-Identifier: MIT OR Apache-2.0
use rug::{integer::Order, Complete, Integer};
use tecdsa_bigint::{generate_safe_prime, is_safe_prime, BigIntExt};

#[test]
fn jacobi_known_values() {
    // 2 is a QR mod 7 (squares mod 7 = {1,2,4}) -> Jacobi(2/7) = 1
    assert_eq!(Integer::from(2u64).jacobi(&Integer::from(7u64)), 1);
    assert_eq!(Integer::from(1u64).jacobi(&Integer::from(7u64)), 1);
    assert_eq!(Integer::from(0u64).jacobi(&Integer::from(7u64)), 0);
    // 2 is a NQR mod 5 (squares mod 5 = {1,4}) -> Jacobi(2/5) = -1
    assert_eq!(Integer::from(2u64).jacobi(&Integer::from(5u64)), -1);
    assert_eq!(Integer::from(3u64).jacobi(&Integer::from(5u64)), -1);
    assert_eq!(Integer::from(4u64).jacobi(&Integer::from(5u64)), 1);
}

#[test]
fn gcd_basic() {
    assert_eq!(
        Integer::from(12u64)
            .gcd_ref(&Integer::from(8u64))
            .complete(),
        Integer::from(4u64)
    );
    assert_eq!(
        Integer::from(17u64)
            .gcd_ref(&Integer::from(13u64))
            .complete(),
        Integer::from(1u64)
    );
}

#[test]
fn sqrt_mod_known_square_root() {
    // p = 7: p-1 = 2*3, so s = 1 and the early-return path is taken.
    let p = Integer::from(7u64);
    let r = Integer::from(4u64).sqrt_mod(&p).unwrap();
    assert_eq!(r.square().modulo(&p), Integer::from(4u64));
}

#[test]
fn sqrt_mod_non_residue_returns_none() {
    assert!(Integer::from(3u64).sqrt_mod(&Integer::from(7u64)).is_none());
}

/// Covers the main Tonelli-Shanks loop, which the `p = 7` cases above never
/// reach: they have `p - 1 = 2 * odd`, i.e. `s = 1`, which returns early via
/// the `p = 3 (mod 4)` shortcut. Each prime here has `s > 1`.
#[test]
fn sqrt_mod_covers_general_loop() {
    // (prime, s) where p - 1 = 2^s * odd
    for p in [13u64, 17, 29, 41, 97, 113, 193, 257, 12289] {
        let p = Integer::from(p);
        let s = (p.clone() - 1u32).find_one(0).unwrap();
        assert!(s > 1, "prime {p} does not exercise the general loop");

        let mut residues = 0;
        for n in 1u64..50 {
            let n = Integer::from(n).modulo(&p);
            if n.cmp0().is_eq() {
                continue;
            }
            match n.sqrt_mod(&p) {
                Some(r) => {
                    assert_eq!(
                        r.square().modulo(&p),
                        n,
                        "sqrt_mod returned a non-root for n={n} p={p}"
                    );
                    residues += 1;
                }
                // Must genuinely be a non-residue.
                None => assert_eq!(
                    n.jacobi(&p),
                    -1,
                    "sqrt_mod returned None for the residue n={n} p={p}"
                ),
            }
        }
        assert!(residues > 0, "no residues exercised for p={p}");
    }
}

#[test]
fn multi_exp_matches_naive() {
    let modulus = Integer::from_str_radix(
        "115792089237316195423570985008687907853269984665640564039457584007913129640233",
        10,
    )
    .unwrap();
    let bases = [
        Integer::from(3u32),
        Integer::from(5u32),
        Integer::from(7u32),
        Integer::from(11u32),
    ];
    let exps = [
        Integer::from(123_456_789u64),
        Integer::from(1u32),
        Integer::from_str_radix("9abcdef0123456789", 16).unwrap(),
        Integer::from(0u32),
    ];
    for n in 1..=4 {
        let b: Vec<&Integer> = bases[..n].iter().collect();
        let e: Vec<&Integer> = exps[..n].iter().collect();
        let got = modulus.multi_exp(&b, &e);
        let mut naive = Integer::from(1);
        for (bi, ei) in b.iter().zip(&e) {
            let term = bi.pow_mod_ref(ei, &modulus).unwrap().complete();
            naive = (naive * term).modulo(&modulus);
        }
        assert_eq!(got, naive, "multi_exp mismatch at n={n}");
    }
}

#[test]
fn multi_exp_empty_exponents_is_one() {
    let modulus = Integer::from(97u32);
    let base = Integer::from(5u32);
    let zero = Integer::ZERO;
    assert_eq!(modulus.multi_exp(&[&base], &[&zero]), Integer::from(1u32));
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
