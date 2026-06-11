// SPDX-License-Identifier: MIT OR Apache-2.0
use rug::{Complete, Integer};

/// Computes the greatest common divisor of `a` and `b`.
#[must_use]
pub fn gcd(a: &Integer, b: &Integer) -> Integer {
    a.clone().gcd(b)
}

/// Modular exponentiation: returns `base^exp mod modulus` as the unique
/// representative in `[0, modulus)`.
///
/// `modulus` must be non-zero.
///
/// # Panics
///
/// Panics if `exp` is negative and `base` is not invertible modulo `modulus`.
#[must_use]
pub fn pow_mod(base: &Integer, exp: &Integer, modulus: &Integer) -> Integer {
    base.pow_mod_ref(exp, modulus)
        .expect("base not invertible modulo modulus")
        .complete()
}

/// Computes `(a * b) mod modulus` as the unique representative in
/// `[0, modulus)`.
///
/// `modulus` must be non-zero.
#[must_use]
pub fn mul_mod(a: &Integer, b: &Integer, modulus: &Integer) -> Integer {
    (a * b).complete().modulo(modulus)
}

/// Simultaneous multi-exponentiation `∏ bases[i]^exps[i] mod modulus` via an
/// interleaved fixed-window (Straus/Shamir) algorithm: a single squaring chain
/// is shared across all bases (`max_bits` squarings instead of one full chain
/// per base), which is the dominant cost. Each base contributes one
/// multiplication per nonzero `W`-bit window.
///
/// Modular inversion is *not* free here (unlike class groups), so this uses
/// plain unsigned windows rather than signed-digit (NAF/JSF) recoding. All
/// exponents must be non-negative.
///
/// # Panics
/// Panics if `bases.len() != exps.len()`.
#[must_use]
pub fn multi_exp(bases: &[&Integer], exps: &[&Integer], modulus: &Integer) -> Integer {
    assert_eq!(
        bases.len(),
        exps.len(),
        "multi_exp: bases and exps must have equal length"
    );
    const W: u32 = 4;
    const TABLE: usize = 1 << W;

    let mut maxbits = 0u32;
    for e in exps {
        maxbits = maxbits.max(e.significant_bits());
    }
    if maxbits == 0 {
        return Integer::from(1);
    }

    // Per-base window table: base^d mod modulus for d in 0..2^W.
    let mut tables: Vec<Vec<Integer>> = Vec::with_capacity(bases.len());
    for b in bases {
        let mut tab = Vec::with_capacity(TABLE);
        tab.push(Integer::from(1));
        tab.push((*b).clone());
        for d in 2..TABLE {
            tab.push(mul_mod(&tab[d - 1], b, modulus));
        }
        tables.push(tab);
    }

    let nblocks = maxbits.div_ceil(W);
    let mut result = Integer::from(1);
    for blk in (0..nblocks).rev() {
        for _ in 0..W {
            result = mul_mod(&result, &result, modulus);
        }
        let shift = blk * W;
        for (tab, e) in tables.iter().zip(exps.iter()) {
            let mut d = 0usize;
            for bit in 0..W {
                if e.get_bit(shift + bit) {
                    d |= 1 << bit;
                }
            }
            if d != 0 {
                result = mul_mod(&result, &tab[d], modulus);
            }
        }
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;

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
            Integer::from(123456789u64),
            Integer::from(1u32),
            Integer::from_str_radix("9abcdef0123456789", 16).unwrap(),
            Integer::from(0u32),
        ];
        for n in 1..=4 {
            let b: Vec<&Integer> = bases[..n].iter().collect();
            let e: Vec<&Integer> = exps[..n].iter().collect();
            let got = multi_exp(&b, &e, &modulus);
            let mut naive = Integer::from(1);
            for (bi, ei) in b.iter().zip(&e) {
                naive = mul_mod(&naive, &pow_mod(bi, ei, &modulus), &modulus);
            }
            assert_eq!(got, naive, "multi_exp mismatch at n={n}");
        }
    }
}
