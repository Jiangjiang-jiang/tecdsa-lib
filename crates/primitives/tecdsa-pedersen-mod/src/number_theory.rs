// SPDX-License-Identifier: MIT OR Apache-2.0
//! Number-theoretic helpers for `PiMod` (Paillier-Blum modulus proof).

use rand_core::CryptoRngCore;
use rug::Integer;

#[allow(clippy::many_single_char_names)]
fn blum_sqrt(y: &Integer, p: &Integer, q: &Integer, n: &Integer) -> Integer {
    let p1 = Integer::from(p - 1);
    let q1 = Integer::from(q - 1);
    let e = (p1 * q1 + 4) / 8;
    y.clone().pow_mod(&e, n).unwrap()
}

/// Compute Blum fourth root: x such that x^4 = y mod N.
///
/// Applies `blum_sqrt` twice: sqrt(sqrt(y)).
#[allow(clippy::many_single_char_names)]
pub fn blum_fourth_root(y: &Integer, p: &Integer, q: &Integer, n: &Integer) -> Integer {
    let sqrt = blum_sqrt(y, p, q, n);
    blum_sqrt(&sqrt, p, q, n)
}

/// Find (a, b) in {0,1}^2 such that (-1)^a * w^b * y is a QR mod N.
///
/// Returns (a, b, y') where y' = (-1)^a * w^b * y mod N.
/// Requires: w has Jacobi symbol -1 mod N, and p,q are Blum primes.
#[allow(clippy::many_single_char_names)]
pub fn find_residue(
    y: &Integer,
    w: &Integer,
    p: &Integer,
    q: &Integer,
    n: &Integer,
) -> Option<(bool, bool, Integer)> {
    let y_mod_p = Integer::from(y % p);
    let y_mod_q = Integer::from(y % q);
    let jp = tecdsa_bigint::jacobi(&y_mod_p, p);
    let jq = tecdsa_bigint::jacobi(&y_mod_q, q);

    match (jp, jq) {
        (1, 1) => return Some((false, false, y.clone())),
        (-1, -1) => {
            let neg_y = Integer::from(n - y);
            return Some((true, false, neg_y));
        }
        _ => {}
    }

    let wy = Integer::from(w * y) % n;
    let wy_mod_p = Integer::from(&wy % p);
    let wy_mod_q = Integer::from(&wy % q);
    let jp = tecdsa_bigint::jacobi(&wy_mod_p, p);
    let jq = tecdsa_bigint::jacobi(&wy_mod_q, q);

    match (jp, jq) {
        (1, 1) => Some((false, true, wy)),
        (-1, -1) => {
            let neg_wy = Integer::from(n - &wy);
            Some((true, true, neg_wy))
        }
        _ => None,
    }
}

/// Sample w in Z*_N with Jacobi symbol (w/N) = -1.
pub fn sample_neg_jacobi(n: &Integer, rng: &mut impl CryptoRngCore) -> Integer {
    use tecdsa_bigint::SyncRng;
    let mut sync_rng = SyncRng(rng);
    let rug_rng = &mut rug::rand::ThreadRandState::new_custom(&mut sync_rng);
    loop {
        let w = n.clone().random_below(rug_rng);
        if w <= 1 {
            continue;
        }
        if w.clone().gcd(n) != 1 {
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
pub fn mod_inverse(a: &Integer, m: &Integer) -> Option<Integer> {
    a.clone().invert(m).ok()
}

/// Check if N is probably composite using Miller-Rabin.
///
/// Returns true if N is composite (not prime).
#[allow(clippy::many_single_char_names)]
pub fn is_probably_composite(n: &Integer, iterations: u32, _rng: &mut impl CryptoRngCore) -> bool {
    n.is_probably_prime(iterations) == rug::integer::IsPrime::No
}
