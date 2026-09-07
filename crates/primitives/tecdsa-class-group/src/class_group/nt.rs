//! Number-theoretic algorithms layered on top of [`rug::Integer`].

use rug::{Complete, Integer};

/// Extended gcd: returns `(g, u, v)` with `g = u*a + v*b`, `g >= 0`.
///
/// Thin wrapper over [`Integer::extended_gcd`] (which consumes its operands)
/// so callers can pass borrowed values.
pub(crate) fn gcdext(a: &Integer, b: &Integer) -> (Integer, Integer, Integer) {
    a.clone().extended_gcd(b.clone(), Integer::new())
}

/// Exact division, or `None` if `d` is zero or does not divide `x`.
pub(crate) fn div_exact_checked(x: &Integer, d: &Integer) -> Option<Integer> {
    (!d.is_zero() && x.is_divisible(d)).then(|| x.clone().div_exact(d))
}

/// Tonelli–Shanks square root modulo an odd prime `p`.
///
/// Returns some `x` with `x^2 ≡ a (mod p)`, or `None` if `a` is a non-residue.
/// (When several roots exist, the canonical one returned is in `[0, p)`.)
pub fn sqrt_mod_prime(a: &Integer, p: &Integer) -> Option<Integer> {
    let one = Integer::from(1u64);
    let am = a.modulo_ref(p).complete();
    if am.is_zero() {
        return Some(Integer::new());
    }
    if am.kronecker(p) != 1 {
        return None;
    }

    // Fast path: p ≡ 3 (mod 4) ⇒ x = a^((p+1)/4).
    if p.modulo_ref(&Integer::from(4u64)).complete() == 3u64 {
        let e = (p + 1u64).complete() >> 2u32; // (p+1)/4
        return Some(
            am.pow_mod(&e, p)
                .expect("non-negative exponent always succeeds"),
        );
    }

    // General Tonelli–Shanks. Write p-1 = Q * 2^S with Q odd.
    let pm1 = (p - &one).complete();
    let mut s: u32 = 0;
    let mut q = pm1.clone();
    while q.is_even() {
        q >>= 1u32;
        s += 1;
    }

    // A quadratic non-residue z.
    let mut z = Integer::from(2u64);
    while z.kronecker(p) != -1 {
        z += 1u64;
    }

    const NONNEG_EXP: &str = "non-negative exponent always succeeds";
    let mut m = s;
    let mut c = z.clone().pow_mod(&q, p).expect(NONNEG_EXP);
    let mut t = am.clone().pow_mod(&q, p).expect(NONNEG_EXP);
    let mut r = am
        .clone()
        .pow_mod(&((&q + 1u64).complete() >> 1u32), p)
        .expect(NONNEG_EXP); // a^((Q+1)/2)

    loop {
        if t == one {
            return Some(r);
        }
        // Least i in (0, m) with t^(2^i) == 1.
        let mut i: u32 = 0;
        let mut t2 = t.clone();
        while t2 != one {
            t2 = t2.pow_mod(&Integer::from(2u64), p).expect(NONNEG_EXP);
            i += 1;
            if i == m {
                return None; // a was not actually a residue
            }
        }
        // b = c^(2^(m-i-1)).
        let mut b = c.clone();
        for _ in 0..(m - i - 1) {
            b = b.pow_mod(&Integer::from(2u64), p).expect(NONNEG_EXP);
        }
        m = i;
        c = b
            .clone()
            .pow_mod(&Integer::from(2u64), p)
            .expect(NONNEG_EXP);
        t = (&t * &c).complete().modulo(p);
        r = (&r * &b).complete().modulo(p);
    }
}

#[cfg(test)]
mod tests {
    use rug::Complete;

    use super::*;
    use crate::class_group::error::parse_int_auto;

    #[test]
    fn sqrt_mod_small_primes() {
        // p ≡ 1 mod 4 case (uses full Tonelli–Shanks): p = 13
        let p = Integer::from(13u64);
        for a in 1u64..13 {
            let am = Integer::from(a);
            match sqrt_mod_prime(&am, &p) {
                Some(x) => assert_eq!((&x * &x).complete().modulo(&p), am),
                None => assert_eq!(am.kronecker(&p), -1),
            }
        }
    }

    #[test]
    fn sqrt_mod_p3mod4() {
        let p = Integer::from(103u64); // 103 ≡ 3 mod 4
        let a = Integer::from(7u64);
        if let Some(x) = sqrt_mod_prime(&a, &p) {
            assert_eq!((&x * &x).complete().modulo(&p), a);
        } else {
            assert_eq!(a.kronecker(&p), -1);
        }
    }

    #[test]
    fn sqrt_mod_large_prime() {
        let p = parse_int_auto("0xfffffffffffffffffffffffffffffffeffffffffffffffff").unwrap();
        // p256-ish? just ensure roundtrip for residues
        let a = Integer::from(123456789u64);
        if let Some(x) = sqrt_mod_prime(&a, &p) {
            assert_eq!((&x * &x).complete().modulo(&p), a.modulo_ref(&p).complete());
        }
    }
}
