//! Recursive, sub-quadratic **half-GCD** (HGCD) for the partial reduction inside
//! NUCOMP, plus a Lehmer-windowed base case.
//!
//! `hgcd(u, v)` (with `u > v ≥ 0`) returns the 2×2 *reduction matrix* `M` such
//! that `[u_out; v_out] = M·[u_in; v_in]`, reducing `v` to roughly half the bit
//! length of `u`. `M` is the product of elementary Euclidean step matrices
//! `[[0,1],[1,-q]]`, so `det M = ±1` and `M`'s entries are the continued-fraction
//! cofactors. The recursion does the work on the high halves and applies the
//! resulting matrix to the full operands — the divide-and-conquer that gives
//! `O(M(n)·log n)` (the matrix products use GMP's Karatsuba/Toom multiplication).
//!
//! Correctness is unconditional: every application of a matrix obtained from the
//! high halves is *validated* (must yield a legal Euclidean state `u' > v' ≥ 0`),
//! and on the rare boundary miss we fall back to the schoolbook reduction. The
//! returned `M` therefore always satisfies the invariant `[u0;v0] = M·[u;v]` with
//! `det M = ±1` (checked in the tests, and against the plain reduction).

// With `gmp-hgcd` the hgcd2 loop replaces this Lehmer/recursive-HGCD machinery
// on the hot path; it stays live for the default build, the fallback tail, and
// the benches, so silence dead-code only in that feature build.
#![cfg_attr(feature = "gmp-hgcd", allow(dead_code))]

use core::{cell::RefCell, cmp::Ordering};

use gmp_mpfr_sys::gmp;
use rug::{Assign, Integer};

thread_local! {
    /// Reused scratch for the partial-reduction inner loop (one per thread):
    /// the three `apply_mat2` temporaries plus the head-extraction register.
    /// Reusing these across calls eliminates the per-call allocation churn that
    /// otherwise dominates `square`/`compose` in a tight exponentiation loop.
    static PR_SCRATCH: RefCell<(Integer, Integer, Integer)> =
        const { RefCell::new((Integer::new(), Integer::new(), Integer::new())) };
}

/// 2×2 integer matrix `[[m0,m1],[m2,m3]]` acting on a column `[u; v]`.
type Mat = [Integer; 4];

/// Operand size (in bits) below which the recursion stops and the
/// Lehmer-windowed schoolbook reduction is used as the HGCD base case.
const HGCD_THRESHOLD_BITS: u32 = 1500;

/// Operand size (in bits) at or above which NUCOMP would dispatch to the
/// recursive HGCD. Benchmarks (`bench_reductions`) show this from-scratch HGCD
/// is *slower* than the word-batched schoolbook Lehmer at every measured size
/// (up to 131072-bit operands, where it is still ~2× slower — see README), so
/// the threshold is set beyond any competitive range: NUCOMP always uses
/// Lehmer in practice. HGCD is retained as the requested, verified
/// implementation and remains reachable for very large operands where its
/// better asymptotic scaling might eventually pay off.
pub(crate) const NUCOMP_HGCD_DISPATCH_BITS: u32 = 1_000_000;

fn mat_id() -> Mat {
    [
        Integer::from(1),
        Integer::new(),
        Integer::new(),
        Integer::from(1),
    ]
}

fn is_id(m: &Mat) -> bool {
    m[0] == 1 && m[1] == 0 && m[2] == 0 && m[3] == 1
}

/// `a · b` for 2×2 matrices.
fn mat_mul(a: &Mat, b: &Mat) -> Mat {
    [
        Integer::from(&a[0] * &b[0]) + Integer::from(&a[1] * &b[2]),
        Integer::from(&a[0] * &b[1]) + Integer::from(&a[1] * &b[3]),
        Integer::from(&a[2] * &b[0]) + Integer::from(&a[3] * &b[2]),
        Integer::from(&a[2] * &b[1]) + Integer::from(&a[3] * &b[3]),
    ]
}

/// `det M < 0` (i.e. an odd number of Euclidean steps).
fn det_is_neg(m: &Mat) -> bool {
    (Integer::from(&m[0] * &m[3]) - Integer::from(&m[1] * &m[2])).cmp0() == Ordering::Less
}

/// `[u; v] ← [[a,b],[c,d]]·[u; v]` for a machine-word matrix.
fn vec_apply_i64(u: &mut Integer, v: &mut Integer, m: [i64; 4]) {
    let nu = Integer::from(&*u * m[0]) + Integer::from(&*v * m[1]);
    let nv = Integer::from(&*u * m[2]) + Integer::from(&*v * m[3]);
    *u = nu;
    *v = nv;
}

/// `M ← [[a,b],[c,d]]·M` for a machine-word left factor.
fn premul_i64(s: [i64; 4], m: &mut Mat) {
    let m0 = Integer::from(&m[0] * s[0]) + Integer::from(&m[2] * s[1]);
    let m1 = Integer::from(&m[1] * s[0]) + Integer::from(&m[3] * s[1]);
    let m2 = Integer::from(&m[0] * s[2]) + Integer::from(&m[2] * s[3]);
    let m3 = Integer::from(&m[1] * s[2]) + Integer::from(&m[3] * s[3]);
    *m = [m0, m1, m2, m3];
}

/// Apply the 2×2 integer matrix `[[m0,m1],[m2,m3]]` to the column `[p; q]`
/// in place: `p ← m0·p + m1·q`, `q ← m2·p + m3·q`. Uses two scratch integers
/// and no allocation (the matrix entries fit `i64`).
fn apply_mat2(
    p: &mut Integer,
    q: &mut Integer,
    m: [i64; 4],
    t0: &mut Integer,
    t1: &mut Integer,
    t2: &mut Integer,
) {
    // Raw `mpz_*` (the matrix entries fit `c_long`): new p = m0·p + m1·q,
    // new q = m2·p + m3·q, no allocation.
    unsafe {
        let pp = p.as_raw_mut();
        let qq = q.as_raw_mut();
        let s0 = t0.as_raw_mut();
        let s1 = t1.as_raw_mut();
        let s2 = t2.as_raw_mut();
        gmp::mpz_mul_si(s0, pp, m[0]);
        gmp::mpz_mul_si(s1, qq, m[1]);
        gmp::mpz_add(s0, s0, s1); // new p
        gmp::mpz_mul_si(s1, pp, m[2]);
        gmp::mpz_mul_si(s2, qq, m[3]);
        gmp::mpz_add(s1, s1, s2); // new q
        gmp::mpz_swap(pp, s0);
        gmp::mpz_swap(qq, s1);
    }
}

/// Schoolbook **Lehmer** partial extended Euclidean reduction (Knuth Algorithm
/// L): continued-fraction steps batched in `i128` machine words, touching the
/// big integers once per batch. `O(n²)`. Reduces `(u, v) = (by, bx)` until
/// `bx ≤ l`; returns the cofactors `(y, x)` (the column `M·[0;1]`) and the
/// parity of the step count.
pub(crate) fn partial_reduce_lehmer(
    bx: &mut Integer,
    by: &mut Integer,
    l: &Integer,
) -> (Integer, Integer, bool) {
    partial_reduce_lehmer_cont(bx, by, l, Integer::from(0), Integer::from(1), false)
}

/// Like [`partial_reduce_lehmer`], but *continues* an in-progress reduction:
/// the caller supplies the cofactor column `(cof0, cof1) = M·(0;1)` and parity
/// already accumulated by an earlier stage (e.g. a GMP `mpn_hgcd` call), and
/// this finishes the reduction down to `bx ≤ l`, composing the matrices. With
/// the identity seed `(0, 1, false)` it is the plain partial reduction.
pub(crate) fn partial_reduce_lehmer_cont(
    bx: &mut Integer,
    by: &mut Integer,
    l: &Integer,
    mut cof0: Integer,
    mut cof1: Integer,
    mut parity: bool,
) -> (Integer, Integer, bool) {
    #[cfg(test)]
    {
        PR_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    PR_SCRATCH.with(|scr| {
        let mut scr = scr.borrow_mut();
        let scr = &mut *scr;
        let (t0, t1, t2) = (&mut scr.0, &mut scr.1, &mut scr.2);

        while &*bx > l && bx.cmp0() != Ordering::Equal {
            let nb = by.significant_bits();
            if nb <= 62 {
                let mut u = by.to_i64().unwrap() as i128;
                let mut v = bx.to_i64().unwrap() as i128;
                let ll = l.to_i64().unwrap_or(-1) as i128;
                let mut m = [1i128, 0, 0, 1];
                while v > ll && v != 0 {
                    let qq = u / v;
                    let r = u - qq * v;
                    u = v;
                    v = r;
                    m = [m[2], m[3], m[0] - qq * m[2], m[1] - qq * m[3]];
                    parity = !parity;
                }
                let mi = [m[0] as i64, m[1] as i64, m[2] as i64, m[3] as i64];
                apply_mat2(by, bx, mi, t0, t1, t2);
                apply_mat2(&mut cof0, &mut cof1, mi, t0, t1, t2);
                break;
            }
            let shift = nb - 62;
            t0.assign(&*by >> shift);
            let mut uh = t0.to_i64().unwrap() as i128;
            t0.assign(&*bx >> shift);
            let mut vh = t0.to_i64().unwrap() as i128;
            let mut m = [1i128, 0, 0, 1];
            let mut steps = 0u32;
            loop {
                let vc = vh + m[2];
                let vd = vh + m[3];
                if vc <= 0 || vd <= 0 {
                    break;
                }
                // Lehmer's invariant keeps the convergent cofactors ≤ the head
                // (< 2^63) throughout a valid window, so the *division* operands
                // fit i64 — use the native 64-bit divide (the i128 path emits a
                // compiler-rt call). The matrix products `q·m` still need i128.
                let nc = uh + m[0];
                let nd = uh + m[1];
                debug_assert!(
                    nc <= i64::MAX as i128
                        && nd <= i64::MAX as i128
                        && vc <= i64::MAX as i128
                        && vd <= i64::MAX as i128,
                    "Lehmer head exceeded i64 — invariant violated"
                );
                let q = (nc as i64 / vc as i64) as i128;
                if q != (nd as i64 / vd as i64) as i128 {
                    break;
                }
                m = [m[2], m[3], m[0] - q * m[2], m[1] - q * m[3]];
                let nuh = vh;
                vh = uh - q * vh;
                uh = nuh;
                steps += 1;
            }
            if steps == 0 {
                #[cfg(test)]
                {
                    PR_STEPS0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let (qf, r) = by.clone().div_rem_floor(bx.clone());
                let ncof1 = &cof0 - Integer::from(&qf * &cof1);
                cof0 = core::mem::replace(&mut cof1, ncof1);
                core::mem::swap(by, bx);
                *bx = r;
                parity = !parity;
            } else {
                #[cfg(test)]
                {
                    PR_BATCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let mi = [m[0] as i64, m[1] as i64, m[2] as i64, m[3] as i64];
                apply_mat2(by, bx, mi, t0, t1, t2);
                apply_mat2(&mut cof0, &mut cof1, mi, t0, t1, t2);
                if steps & 1 == 1 {
                    parity = !parity;
                }
            }
        }
    });
    (cof0, cof1, parity)
}

/// Lehmer-windowed schoolbook reduction of `(u, v)` (`u > v ≥ 0`) until
/// `bits(v) ≤ target`, returning the reduction matrix. This is the HGCD base
/// case (and boundary fallback).
fn lehmer_reduce_bits(u: &mut Integer, v: &mut Integer, target: u32) -> Mat {
    let mut m = mat_id();
    while v.cmp0() != Ordering::Equal && v.significant_bits() > target {
        let nb = u.significant_bits();
        if nb <= 62 {
            let mut uu = u.to_i64().unwrap() as i128;
            let mut vv = v.to_i64().unwrap() as i128;
            let stop = if target >= 62 { 1i128 } else { 1i128 << target };
            let mut s = [1i128, 0, 0, 1];
            while vv != 0 && vv >= stop {
                let q = uu / vv;
                let r = uu - q * vv;
                uu = vv;
                vv = r;
                s = [s[2], s[3], s[0] - q * s[2], s[1] - q * s[3]];
            }
            let si = [s[0] as i64, s[1] as i64, s[2] as i64, s[3] as i64];
            vec_apply_i64(u, v, si);
            premul_i64(si, &mut m);
            break;
        }
        let shift = nb - 62;
        let mut a = Integer::from(&*u >> shift).to_i64().unwrap() as i128;
        let mut b = Integer::from(&*v >> shift).to_i64().unwrap() as i128;
        let mut s = [1i128, 0, 0, 1];
        loop {
            let vc = b + s[2];
            let vd = b + s[3];
            if vc <= 0 || vd <= 0 {
                break;
            }
            let q = (a + s[0]) / vc;
            if q != (a + s[1]) / vd {
                break;
            }
            s = [s[2], s[3], s[0] - q * s[2], s[1] - q * s[3]];
            let na = b;
            b = a - q * b;
            a = na;
        }
        if s[1] == 0 {
            // Leading bits gave no quotient: one full-precision Euclidean step.
            let (q, r) = u.clone().div_rem_floor(v.clone());
            let step = [
                Integer::new(),
                Integer::from(1),
                Integer::from(1),
                Integer::from(-&q),
            ];
            m = mat_mul(&step, &m);
            core::mem::swap(u, v); // u ← old v
            *v = r;
        } else {
            let si = [s[0] as i64, s[1] as i64, s[2] as i64, s[3] as i64];
            vec_apply_i64(u, v, si);
            premul_i64(si, &mut m);
        }
    }
    m
}

#[cfg(test)]
pub(crate) static PR_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
pub(crate) static PR_BATCHES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
pub(crate) static PR_STEPS0: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
pub(crate) static HGCD_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
pub(crate) static HGCD_FALLBACKS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
fn bump(c: &std::sync::atomic::AtomicU64) {
    c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Recursive half-GCD: reduce `(u, v)` (`u > v ≥ 0`) until `bits(v) ≤ ⌈n/2⌉`
/// (`n = bits(u)`), returning the reduction matrix `M` with `[u0;v0] = M·[u;v]`.
fn hgcd(u: &mut Integer, v: &mut Integer) -> Mat {
    #[cfg(test)]
    bump(&HGCD_CALLS);
    let n = u.significant_bits();
    let target = n.div_ceil(2);
    if v.cmp0() == Ordering::Equal || v.significant_bits() <= target {
        return mat_id();
    }
    if n <= HGCD_THRESHOLD_BITS {
        return lehmer_reduce_bits(u, v, target);
    }

    // --- first recursion on the high halves ---
    let s = n / 2;
    let mut uh = Integer::from(&*u >> s);
    let mut vh = Integer::from(&*v >> s);
    let r = hgcd(&mut uh, &mut vh);

    let nu = Integer::from(&r[0] * &*u) + Integer::from(&r[1] * &*v);
    let nv = Integer::from(&r[2] * &*u) + Integer::from(&r[3] * &*v);
    let mut m = if nu > nv && nv.cmp0() != Ordering::Less {
        *u = nu;
        *v = nv;
        r
    } else {
        // Boundary miss: the high-half matrix is not valid for the full
        // operands — fall back to schoolbook (u, v untouched).
        #[cfg(test)]
        bump(&HGCD_FALLBACKS);
        return lehmer_reduce_bits(u, v, target);
    };
    if v.cmp0() == Ordering::Equal || v.significant_bits() <= target {
        return m;
    }

    // --- one Euclidean step across the midpoint ---
    let (q, rr) = u.clone().div_rem_floor(v.clone());
    let step = [
        Integer::new(),
        Integer::from(1),
        Integer::from(1),
        Integer::from(-&q),
    ];
    m = mat_mul(&step, &m);
    core::mem::swap(u, v);
    *v = rr;
    if v.cmp0() == Ordering::Equal || v.significant_bits() <= target {
        return m;
    }

    // --- second recursion on the new high halves ---
    let n2 = u.significant_bits();
    let s2 = (2 * target).saturating_sub(n2);
    let mut uh2 = Integer::from(&*u >> s2);
    let mut vh2 = Integer::from(&*v >> s2);
    let ss = hgcd(&mut uh2, &mut vh2);

    let nu2 = Integer::from(&ss[0] * &*u) + Integer::from(&ss[1] * &*v);
    let nv2 = Integer::from(&ss[2] * &*u) + Integer::from(&ss[3] * &*v);
    if nu2 > nv2 && nv2.cmp0() != Ordering::Less {
        *u = nu2;
        *v = nv2;
        mat_mul(&ss, &m)
    } else {
        #[cfg(test)]
        bump(&HGCD_FALLBACKS);
        let m2 = lehmer_reduce_bits(u, v, target);
        mat_mul(&m2, &m)
    }
}

/// Partial reduction of `(bx, by)` (`by > bx ≥ 0`) until `bits(bx) ≤ bits(l)`,
/// via recursive HGCD. Matches the contract of `qfi::partial_reduce_lehmer`:
/// returns the cofactors `(y, x)` = second column of the total reduction matrix
/// and the parity of the step count.
pub(crate) fn partial_reduce_hgcd(
    bx: &mut Integer,
    by: &mut Integer,
    l: &Integer,
) -> (Integer, Integer, bool) {
    let lbits = l.significant_bits();
    let mut m = mat_id();
    while bx.cmp0() != Ordering::Equal && bx.significant_bits() > lbits {
        let n = by.significant_bits();
        if n <= HGCD_THRESHOLD_BITS || n.saturating_sub(lbits) < 64 {
            let mm = lehmer_reduce_bits(by, bx, lbits);
            m = mat_mul(&mm, &m);
            break;
        }
        let mm = hgcd(by, bx);
        if is_id(&mm) {
            let mm2 = lehmer_reduce_bits(by, bx, lbits);
            m = mat_mul(&mm2, &m);
            break;
        }
        m = mat_mul(&mm, &m);
    }
    // cofactor column M·[0;1] = (m1, m3); parity = (det M < 0)
    (m[1].clone(), m[3].clone(), det_is_neg(&m))
}

#[cfg(test)]
mod tests {
    use rug::rand::RandState;
    use tecdsa_bigint::BigIntExt;

    use super::*;

    fn rand_pair(rng: &mut RandState, bits: u32) -> (Integer, Integer) {
        // Balanced: a has exactly `bits` bits, b exactly `bits-1` (so a > b and
        // both have the same limb count with nonzero high limbs — required by
        // GMP's mpn_hgcd). Both odd.
        let mut a = Integer::from(Integer::random_bits(bits, rng));
        a.set_bit(bits - 1, true);
        a.set_bit(0, true);
        let mut b = Integer::from(Integer::random_bits(bits, rng));
        b.set_bit(bits - 1, false);
        b.set_bit(bits - 2, true);
        b.set_bit(0, true);
        (a, b)
    }

    /// Head-to-head: schoolbook Lehmer vs recursive HGCD partial reduction,
    /// reducing `bits`-bit operands down to `bits/2` (the NUCOMP target).
    /// Run with: `cargo test --release -- --ignored --nocapture bench_reductions`
    #[test]
    #[ignore]
    fn bench_reductions() {
        use std::time::Instant;
        let mut rng = RandState::new();
        rng.seed(&Integer::from(42));
        println!("\n   bits |   lehmer µs |    hgcd µs |  speedup");
        for &bits in &[1024u32, 2048, 4096, 8192, 16384, 32768, 65536, 131072] {
            let reps = (8_000_000 / bits).clamp(5, 400) as usize;
            let pairs: Vec<(Integer, Integer)> =
                (0..reps).map(|_| rand_pair(&mut rng, bits)).collect();
            let l = Integer::two_pow(bits / 2);

            let t = Instant::now();
            for (a, b) in &pairs {
                let (mut bx, mut by) = (b.clone(), a.clone());
                let _ = partial_reduce_lehmer(&mut bx, &mut by, &l);
            }
            let leh = t.elapsed().as_secs_f64() * 1e6 / reps as f64;

            use std::sync::atomic::Ordering as AOrd;
            HGCD_CALLS.store(0, AOrd::Relaxed);
            HGCD_FALLBACKS.store(0, AOrd::Relaxed);
            let t = Instant::now();
            for (a, b) in &pairs {
                let (mut bx, mut by) = (b.clone(), a.clone());
                let _ = partial_reduce_hgcd(&mut bx, &mut by, &l);
            }
            let hg = t.elapsed().as_secs_f64() * 1e6 / reps as f64;
            let calls = HGCD_CALLS.load(AOrd::Relaxed);
            let fb = HGCD_FALLBACKS.load(AOrd::Relaxed);
            let fb_pct = if calls > 0 {
                100.0 * fb as f64 / calls as f64
            } else {
                0.0
            };

            // GMP's internal recursive HGCD (the genuine sub-quadratic one).
            #[cfg(feature = "gmp-hgcd")]
            let gmp_str = {
                let t = Instant::now();
                for (a, b) in &pairs {
                    let _ = super::super::hgcd_gmp::hgcd_reduce_gmp(a, b);
                }
                let gmp = t.elapsed().as_secs_f64() * 1e6 / reps as f64;
                format!(" | gmp {gmp:10.2} ({:.2}x vs Lehmer)", leh / gmp)
            };
            #[cfg(not(feature = "gmp-hgcd"))]
            let gmp_str = String::new();

            println!(
                "  {bits:6} | {leh:11.2} | {hg:10.2} | {:6.2}x | fb {fb_pct:5.1}%{gmp_str}",
                leh / hg
            );
        }
    }

    /// The cofactors returned by `partial_reduce_lehmer` must satisfy the
    /// continued-fraction invariants (this guards the i64-division inner loop):
    /// with reduced `(bx, byr)` and `(y, x, parity)`,
    ///   `|x·byr − y·bx| == by0`   and   `bx ≡ x·bx0 (mod by0)`,
    /// and `bx ≤ l < byr`.
    #[test]
    fn partial_reduce_lehmer_cofactor_invariant() {
        let mut rng = RandState::new();
        rng.seed(&Integer::from(54321));
        for &bits in &[256u32, 900, 1796, 4096] {
            let l = Integer::two_pow(bits / 2);
            for _ in 0..40 {
                let (by0, bx0) = rand_pair(&mut rng, bits); // by0 > bx0 > 0
                let (mut bx, mut by) = (bx0.clone(), by0.clone());
                let (y, x, parity) = partial_reduce_lehmer(&mut bx, &mut by, &l);
                // det relation: |x·byr − y·bx| == by0
                let det_rel = Integer::from(&x * &by) - y * &bx;
                assert_eq!(det_rel.clone().abs(), by0, "det invariant ({bits} bits)");
                assert_eq!(
                    (det_rel.cmp0() == Ordering::Less),
                    parity,
                    "parity sign ({bits} bits)"
                );
                // bx ≡ x·bx0 (mod by0)
                let r = (Integer::from(&bx) - x * bx0) % &by0;
                assert_eq!(r, 0, "bx ≡ x·bx0 (mod by0) ({bits} bits)");
                // reduced: bx ≤ l (unless it bottomed out)
                assert!(
                    bx <= l || bx.cmp0() == Ordering::Equal,
                    "bx ≤ l ({bits} bits)"
                );
            }
        }
    }

    #[test]
    fn hgcd_matches_lehmer_full_reduction() {
        // At l = 0 both reduce to the gcd; cofactors and parity must agree.
        let mut rng = RandState::new();
        rng.seed(&Integer::from(987));
        let l = Integer::from(0);
        for &bits in &[200u32, 1000, 3000, 6000] {
            for _ in 0..15 {
                let (a0, b0) = rand_pair(&mut rng, bits); // a0 > b0
                let (mut bx1, mut by1) = (b0.clone(), a0.clone());
                let r1 = partial_reduce_lehmer(&mut bx1, &mut by1, &l);
                let (mut bx2, mut by2) = (b0.clone(), a0.clone());
                let r2 = partial_reduce_hgcd(&mut bx2, &mut by2, &l);
                assert_eq!(r1, r2, "(cof0,cof1,parity) mismatch at {bits} bits");
                assert_eq!(
                    (bx1, by1),
                    (bx2, by2),
                    "reduced pair mismatch at {bits} bits"
                );
            }
        }
    }

    #[test]
    fn hgcd_matrix_invariant_and_progress() {
        let mut rng = RandState::new();
        rng.seed(&Integer::from(12345));
        for &bits in &[256u32, 1024, 2048, 5000, 12000] {
            for _ in 0..20 {
                let (a0, b0) = rand_pair(&mut rng, bits);
                let (mut u, mut v) = (a0.clone(), b0.clone());
                let m = hgcd(&mut u, &mut v);
                // M is the reduction matrix: [u; v] = M·[a0; b0].
                let ru = Integer::from(&m[0] * &a0) + Integer::from(&m[1] * &b0);
                let rv = Integer::from(&m[2] * &a0) + Integer::from(&m[3] * &b0);
                assert_eq!(ru, u, "row0 invariant ({bits} bits)");
                assert_eq!(rv, v, "row1 invariant ({bits} bits)");
                // det ±1
                let det = Integer::from(&m[0] * &m[3]) - Integer::from(&m[1] * &m[2]);
                assert!(det == 1 || det == -1, "det must be ±1");
                // progress: v reduced to about half the bits (or already small)
                assert!(v.significant_bits() <= a0.significant_bits().div_ceil(2));
                assert!(u > v && v.cmp0() != Ordering::Less);
            }
        }
    }
}
