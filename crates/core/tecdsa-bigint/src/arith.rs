// SPDX-License-Identifier: MIT OR Apache-2.0
use rug::Integer;

/// Computes the greatest common divisor of `a` and `b`.
#[must_use]
pub fn gcd(a: &Integer, b: &Integer) -> Integer {
    a.clone().gcd(b)
}

/// Computes the Jacobi symbol `(a/n)`.
///
/// Returns `1`, `-1`, or `0`.  `n` must be a positive odd integer.
#[must_use]
pub fn jacobi(a: &Integer, n: &Integer) -> i8 {
    a.jacobi(n) as i8
}

/// Tonelli-Shanks square root: returns `r` such that `r² ≡ n (mod p)`,
/// or `None` if `n` is a quadratic non-residue mod `p`.
///
/// `p` must be an odd prime.
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn tonelli_shanks(n: &Integer, p: &Integer) -> Option<Integer> {
    if jacobi(n, p) != 1 {
        return None;
    }
    let one = Integer::from(1);
    let two = Integer::from(2);

    let p_minus_1 = Integer::from(p - &one);
    let mut q = p_minus_1.clone();
    let mut s: u32 = 0;
    while q.is_even() {
        q >>= 1u32;
        s += 1;
    }

    if s == 1 {
        let exp = Integer::from(p + &one) >> 2u32;
        return n.clone().pow_mod(&exp, p).ok();
    }

    let mut z = Integer::from(2);
    while jacobi(&z, p) != -1 {
        z += &one;
    }

    let mut m_val = s;
    let mut c = z.pow_mod(&q, p).unwrap();
    let mut t = n.clone().pow_mod(&q, p).unwrap();
    let mut r = n
        .clone()
        .pow_mod(&(Integer::from(&q + &one) >> 1u32), p)
        .unwrap();

    loop {
        if t == 1 {
            return Some(r);
        }
        let mut i: u32 = 1;
        let mut tmp = Integer::from(&t * &t) % p;
        while tmp != 1 {
            tmp = Integer::from(&tmp * &tmp) % p;
            i += 1;
        }
        let b = c
            .pow_mod(
                &two.clone()
                    .pow_mod(&Integer::from(m_val - i - 1), &p_minus_1)
                    .unwrap(),
                p,
            )
            .unwrap();
        m_val = i;
        c = Integer::from(&b * &b) % p;
        t = Integer::from(&t * &c) % p;
        r = Integer::from(&r * &b) % p;
    }
}
