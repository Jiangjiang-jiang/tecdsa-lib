// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::DynInt;
use num_integer::Integer;
use num_traits::{One, Zero};

/// Computes the greatest common divisor of `a` and `b`.
#[must_use]
pub fn gcd(a: &DynInt, b: &DynInt) -> DynInt {
    DynInt::from(a.inner().gcd(b.inner()))
}

/// Computes the Jacobi symbol `(a/n)`.
///
/// Returns `1`, `-1`, or `0`.  `n` must be a positive odd integer.
#[allow(clippy::many_single_char_names)]
#[must_use]
pub fn jacobi(a: &DynInt, n: &DynInt) -> i8 {
    let mut a = a.inner().clone();
    let n_inner = n.inner();
    let mut n = n_inner.clone();
    let mut result: i8 = 1;

    a %= &n;
    while !a.is_zero() {
        while a.is_even() {
            a >>= 1u32;
            let n_mod8 = (&n % num_bigint::BigUint::from(8u32))
                .to_u64_digits()
                .first()
                .copied()
                .unwrap_or(0);
            if n_mod8 == 3 || n_mod8 == 5 {
                result = -result;
            }
        }
        std::mem::swap(&mut a, &mut n);
        let a_mod4 = (&a % num_bigint::BigUint::from(4u32))
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(0);
        let n_mod4 = (&n % num_bigint::BigUint::from(4u32))
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(0);
        if a_mod4 == 3 && n_mod4 == 3 {
            result = -result;
        }
        a %= &n;
    }
    if n.is_one() {
        result
    } else {
        0
    }
}

/// Tonelli-Shanks square root: returns `r` such that `r² ≡ n (mod p)`,
/// or `None` if `n` is a quadratic non-residue mod `p`.
///
/// `p` must be an odd prime.
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn tonelli_shanks(n: &DynInt, p: &DynInt) -> Option<DynInt> {
    if jacobi(n, p) != 1 {
        return None;
    }
    let p_inner = p.inner();
    let n_inner = n.inner();
    let one = num_bigint::BigUint::one();
    let two = num_bigint::BigUint::from(2u32);

    let p_minus_1 = p_inner - &one;
    let mut q = p_minus_1.clone();
    let mut s: u32 = 0;
    while q.is_even() {
        q >>= 1u32;
        s += 1;
    }

    if s == 1 {
        let exp = (p_inner + &one) >> 2u32;
        return Some(DynInt::from(n_inner.modpow(&exp, p_inner)));
    }

    let mut z = num_bigint::BigUint::from(2u32);
    while jacobi(&DynInt::from(z.clone()), p) != -1 {
        z += &one;
    }

    let mut m_val = s;
    let mut c = z.modpow(&q, p_inner);
    let mut t = n_inner.modpow(&q, p_inner);
    let mut r = n_inner.modpow(&((&q + &one) >> 1u32), p_inner);

    loop {
        if t.is_one() {
            return Some(DynInt::from(r));
        }
        let mut i: u32 = 1;
        let mut tmp = (&t * &t) % p_inner;
        while !tmp.is_one() {
            tmp = (&tmp * &tmp) % p_inner;
            i += 1;
        }
        let b = c.modpow(
            &two.modpow(&num_bigint::BigUint::from(m_val - i - 1), &p_minus_1),
            p_inner,
        );
        m_val = i;
        c = (&b * &b) % p_inner;
        t = (&t * &c) % p_inner;
        r = (&r * &b) % p_inner;
    }
}
