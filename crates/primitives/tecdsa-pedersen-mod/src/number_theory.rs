// SPDX-License-Identifier: MIT OR Apache-2.0
//! Number-theoretic helpers for `PiMod` (Paillier-Blum modulus proof).

use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed};
use rand_core::CryptoRngCore;
use tecdsa_bigint::DynInt;

use crate::params::RandAdapter;

#[allow(clippy::many_single_char_names)]
fn blum_sqrt(y: &DynInt, p: &DynInt, q: &DynInt, n: &DynInt) -> DynInt {
    let p1 = p.inner() - BigUint::one();
    let q1 = q.inner() - BigUint::one();
    let e = (&p1 * &q1 + BigUint::from(4u32)) / BigUint::from(8u32);
    DynInt::from(y.inner().modpow(&e, n.inner()))
}

/// Compute Blum fourth root: x such that x^4 = y mod N.
///
/// Applies `blum_sqrt` twice: sqrt(sqrt(y)).
#[allow(clippy::many_single_char_names)]
pub fn blum_fourth_root(y: &DynInt, p: &DynInt, q: &DynInt, n: &DynInt) -> DynInt {
    let sqrt = blum_sqrt(y, p, q, n);
    blum_sqrt(&sqrt, p, q, n)
}

/// Find (a, b) in {0,1}^2 such that (-1)^a * w^b * y is a QR mod N.
///
/// Returns (a, b, y') where y' = (-1)^a * w^b * y mod N.
/// Requires: w has Jacobi symbol -1 mod N, and p,q are Blum primes.
#[allow(clippy::many_single_char_names)]
pub fn find_residue(
    y: &DynInt,
    w: &DynInt,
    p: &DynInt,
    q: &DynInt,
    n: &DynInt,
) -> Option<(bool, bool, DynInt)> {
    let y_mod_p = DynInt::from(y.inner() % p.inner());
    let y_mod_q = DynInt::from(y.inner() % q.inner());
    let jp = tecdsa_bigint::jacobi(&y_mod_p, p);
    let jq = tecdsa_bigint::jacobi(&y_mod_q, q);

    match (jp, jq) {
        (1, 1) => return Some((false, false, y.clone())),
        (-1, -1) => {
            let neg_y = DynInt::from(n.inner() - y.inner());
            return Some((true, false, neg_y));
        }
        _ => {}
    }

    let wy = DynInt::from((w.inner() * y.inner()) % n.inner());
    let wy_mod_p = DynInt::from(wy.inner() % p.inner());
    let wy_mod_q = DynInt::from(wy.inner() % q.inner());
    let jp = tecdsa_bigint::jacobi(&wy_mod_p, p);
    let jq = tecdsa_bigint::jacobi(&wy_mod_q, q);

    match (jp, jq) {
        (1, 1) => Some((false, true, wy)),
        (-1, -1) => {
            let neg_wy = DynInt::from(n.inner() - wy.inner());
            Some((true, true, neg_wy))
        }
        _ => None,
    }
}

/// Sample w in Z*_N with Jacobi symbol (w/N) = -1.
pub fn sample_neg_jacobi(n: &DynInt, rng: &mut impl CryptoRngCore) -> DynInt {
    let mut adapter = RandAdapter(rng);
    loop {
        let w = adapter.gen_biguint_below(n.inner());
        if w <= BigUint::one() {
            continue;
        }
        let w = DynInt::from(w);
        if tecdsa_bigint::gcd(&w, n) != DynInt::one() {
            continue;
        }
        if tecdsa_bigint::jacobi(&w, n) == -1 {
            return w;
        }
    }
}

/// Compute modular inverse: a^{-1} mod m, using extended GCD.
///
/// Returns `None` if gcd(a, m) != 1.
pub fn mod_inverse(a: &DynInt, m: &DynInt) -> Option<DynInt> {
    let a_big = BigInt::from(a.inner().clone());
    let m_big = BigInt::from(m.inner().clone());
    let result = a_big.extended_gcd(&m_big);
    if !result.gcd.is_one() {
        return None;
    }
    let mut inv = result.x % &m_big;
    if inv.is_negative() {
        inv += &m_big;
    }
    let (sign, digits) = inv.to_u32_digits();
    debug_assert!(sign != Sign::Minus);
    Some(DynInt::from(BigUint::new(digits)))
}

/// Check if N is probably composite using Miller-Rabin.
///
/// Returns true if N is composite (not prime).
#[allow(clippy::many_single_char_names)]
pub fn is_probably_composite(n: &DynInt, iterations: u32, rng: &mut impl CryptoRngCore) -> bool {
    let n_inner = n.inner();
    if n_inner <= &BigUint::one() {
        return true;
    }
    if n_inner.is_even() {
        return *n_inner != BigUint::from(2u32);
    }

    let n_minus_1 = n_inner - BigUint::one();
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while d.is_even() {
        d >>= 1u32;
        r += 1;
    }

    let mut adapter = RandAdapter(rng);
    for _ in 0..iterations {
        let a = loop {
            let candidate = adapter.gen_biguint_below(n_inner);
            if candidate >= BigUint::from(2u32) {
                break candidate;
            }
        };
        let mut x = a.modpow(&d, n_inner);
        if x == BigUint::one() || x == n_minus_1 {
            continue;
        }
        let mut composite_witness = true;
        for _ in 0..r - 1 {
            x = x.modpow(&BigUint::from(2u32), n_inner);
            if x == n_minus_1 {
                composite_witness = false;
                break;
            }
        }
        if composite_witness {
            return true;
        }
    }
    false
}
