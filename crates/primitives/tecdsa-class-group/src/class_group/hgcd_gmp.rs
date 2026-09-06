//! FFI to GMP's *internal* half-GCD primitives, used to accelerate the
//! NUCOMP/NUDUPL partial reduction behind the `gmp-hgcd` feature.
//!
//! `__gmpn_hgcd`/`__gmpn_hgcd2` are declared in GMP's `gmp-impl.h` (not the
//! public `gmp.h`) and are **not** bound by `gmp-mpfr-sys`. They are present in
//! the linked libgmp on this platform (verified via `nm -D`), so we declare them
//! ourselves. This is `unsafe` and depends on an undocumented, version-fragile
//! internal API (the `hgcd_matrix`/`hgcd_matrix1` layouts and the contracts could
//! change across GMP releases), hence the opt-in feature; without it the
//! word-batched i64 Lehmer ([`super::hgcd::partial_reduce_lehmer`]) is used.
//!
//! Contracts (from `gmp-impl.h` / `mpn/generic/hgcd*.c`):
//! * `hgcd_matrix { mp_size_t alloc; mp_size_t n; mp_ptr p[2][2]; }`.
//! * `mpn_hgcd(ap, bp, n, M, tp)`: reduces the `n`-limb pair in place to its
//!   return value `nn` limbs and fills `M` so that `(a;b) = M·(a';b')`.
//! * `hgcd_matrix1 { mp_limb_t u[2][2]; }` (four single-limb cofactors).
//! * `mpn_hgcd2(ah, al, bh, bl, M)`: reduces the 2-limb pair `(ah:al, bh:bl)`
//!   (`ah` normalised, high bit set) and fills `M` so that `(a;b) = M·(a';b')`,
//!   `M` non-negative, `det = ±1`; returns 0 if the heads don't determine a step.
//!
//! ## Driving the partial reduction with `mpn_hgcd2` (the win)
//! [`partial_reduce_hgcd2`] runs a Lehmer-style loop whose window engine is
//! `mpn_hgcd2`: each window feeds the top 128 bits of `(by, bx)` to it, applies
//! the reducing matrix `M⁻¹` to the full operands and the cofactor column, and
//! stops at `bx ≤ L`. 128-bit heads advance ~2× more per window than the 62-bit
//! machine-word Lehmer. Two subtleties had to be handled:
//! * **Unordered result.** `mpn_hgcd2` performs a number of CF steps whose parity
//!   decides which of `(a',b')` ends up larger, so after a window `by` may be
//!   `< bx`. We restore `by ≥ bx` by swapping the operands, the cofactor column,
//!   and the parity (a row swap flips det).
//! * **Overshoot.** Its coarse ~64-bit window can jump `bx` *past* `L`, leaving
//!   the assembled form non-reduced. We hand off to the precise word-Lehmer tail
//!   once within one window of `L`, so the final stop lands exactly at `bx ≤ L`.
//!
//! Both verified by the `square == compose_dirichlet` fuzz and a cofactor
//! invariant test; measured faster than the i64 Lehmer at the CL size (see the
//! `bench_partial_cl` test and the README).
//!
//! [`partial_reduce_mpn`] is a fully `mpn`-level, allocation-free variant: each
//! window reduces the operands in place with `mpn_matrix22_mul1_inverse_vector`
//! (a fused `mpn` pass, no `mpz`/`rug` per-op overhead) and accumulates the
//! reduction matrix with `mpn_hgcd_matrix_mul_1`, extracting the cofactors at the
//! end. It is correct (same invariants/fuzz) and marginally faster at the
//! *primitive* level (~4.4 vs ~4.5 us in `bench_partial_cl`), but **end-to-end a
//! wash** (decrypt ~14.0 ms either way): the fused apply is offset by the matrix
//! accumulation + final cofactor extraction. The hot path keeps the simpler
//! [`partial_reduce_hgcd2`]; `partial_reduce_mpn` is the benchmarked answer to
//! "does allocation-free in-place mpn NUDUPL help?" -- it does not, because the
//! arithmetic (gcdext + the reduction muls), not allocation/dispatch, dominates.
//!
//! `mpn_hgcd` (the *recursive* HGCD, via [`hgcd_reduce_gmp`]) is retained for the
//! `bench_reductions` comparison only: driving the partial reduction with it is a
//! net loss here because its fixed ~n/2 target overshoots `L` (and a Lehmer
//! cleanup tail only reaches break-even).

// The recursive `mpn_hgcd` machinery (`hgcd_reduce_gmp` etc.) is used only by
// the benches; the hgcd2 hot-path items are used in non-test builds. Silence the
// bench-only dead-code in non-test feature builds.
#![cfg_attr(not(test), allow(dead_code))]

use core::{
    cell::RefCell,
    cmp::Ordering,
    ffi::{c_int, c_long},
    ptr,
};

use gmp_mpfr_sys::{gmp, gmp::limb_t};
use rug::{integer::Order, Integer};

thread_local! {
    /// Reused `apply_u64` temporaries for the [`partial_reduce_hgcd2`] loop, so a
    /// tight exponentiation loop does not reallocate them per call.
    static PR2_SCRATCH: RefCell<(Integer, Integer, Integer)> =
        const { RefCell::new((Integer::new(), Integer::new(), Integer::new())) };
}

#[repr(C)]
struct HgcdMatrix {
    alloc: c_long,
    n: c_long,
    p: [[*mut limb_t; 2]; 2],
}

/// GMP's 2-limb half-GCD base-case matrix (`struct hgcd_matrix1`): four
/// single-limb cofactors, non-negative, with `(a;b) = M·(a';b')`, det ±1.
#[repr(C)]
struct HgcdMatrix1 {
    u: [[limb_t; 2]; 2],
}

extern "C" {
    #[link_name = "__gmpn_hgcd_itch"]
    fn mpn_hgcd_itch(n: c_long) -> c_long;
    #[link_name = "__gmpn_hgcd_matrix_init"]
    fn mpn_hgcd_matrix_init(m: *mut HgcdMatrix, n: c_long, p: *mut limb_t);
    #[link_name = "__gmpn_hgcd"]
    fn mpn_hgcd(
        ap: *mut limb_t,
        bp: *mut limb_t,
        n: c_long,
        m: *mut HgcdMatrix,
        tp: *mut limb_t,
    ) -> c_long;
    #[link_name = "__gmpn_hgcd2"]
    fn mpn_hgcd2(ah: limb_t, al: limb_t, bh: limb_t, bl: limb_t, m: *mut HgcdMatrix1) -> c_int;
    // Reduce a 2-vector: (r;b) = M1^{-1}(a;b) = (u11 a - u01 b; -u10 a + u00 b).
    // new-a → rp, new-b → bp (in place), old-a read from ap (three distinct
    // buffers). No carry limb (it is a reduction); returns the new limb size.
    #[link_name = "__gmpn_matrix22_mul1_inverse_vector"]
    fn mpn_matrix22_mul1_inverse_vector(
        m: *const HgcdMatrix1,
        rp: *mut limb_t,
        ap: *const limb_t,
        bp: *mut limb_t,
        n: c_long,
    ) -> c_long;
    // Accumulate: M ← M · M1.  `tp` is scratch of ≥ M.n + 1 limbs.
    #[link_name = "__gmpn_hgcd_matrix_mul_1"]
    fn mpn_hgcd_matrix_mul_1(m: *mut HgcdMatrix, m1: *const HgcdMatrix1, tp: *mut limb_t);
}

/// Read the limb slice of a (non-negative) `Integer`.
unsafe fn limbs(x: &Integer) -> &[limb_t] {
    let raw = x.as_raw();
    let n = (*raw).size.unsigned_abs() as usize;
    if n == 0 {
        &[]
    } else {
        core::slice::from_raw_parts((*raw).d.as_ptr(), n)
    }
}

/// Top 128 bits of a non-negative `Integer` shifted down by `shift`, returned as
/// `(hi, lo)` limbs. With `shift = nbits − 128` this yields the two leading limbs
/// with the high bit of `hi` set (the normalisation `mpn_hgcd2` wants).
#[inline]
unsafe fn top128(x: *const gmp::mpz_t, shift: u64) -> (limb_t, limb_t) {
    let size = (*x).size.unsigned_abs() as u64;
    let d = (*x).d.as_ptr();
    let g = |i: u64| -> limb_t {
        if i < size {
            *d.add(i as usize)
        } else {
            0
        }
    };
    let k = shift / 64;
    let off = (shift % 64) as u32;
    if off == 0 {
        (g(k + 1), g(k))
    } else {
        let lo = (g(k) >> off) | (g(k + 1) << (64 - off));
        let hi = (g(k + 1) >> off) | (g(k + 2) << (64 - off));
        (hi, lo)
    }
}

/// Apply the 2×2 matrix `[[m0,m1],[m2,m3]]` (entries given as magnitude + sign) to
/// the column `(p; q)` in place: `p ← s0·m0·p + s1·m1·q`, `q ← s2·m2·p + s3·m3·q`,
/// using `mpz_mul_ui` (the entries are single limbs, up to `2^64−1`) and reused
/// scratch. Sign is applied by flipping the result's `mpz` size field.
#[allow(clippy::too_many_arguments)]
#[inline]
unsafe fn apply_u64(
    p: *mut gmp::mpz_t,
    q: *mut gmp::mpz_t,
    mag: [limb_t; 4],
    neg: [bool; 4],
    t0: *mut gmp::mpz_t,
    t1: *mut gmp::mpz_t,
    t2: *mut gmp::mpz_t,
) {
    gmp::mpz_mul_ui(t0, p, mag[0]);
    if neg[0] {
        (*t0).size = -(*t0).size;
    }
    gmp::mpz_mul_ui(t1, q, mag[1]);
    if neg[1] {
        (*t1).size = -(*t1).size;
    }
    gmp::mpz_add(t0, t0, t1); // new p
    gmp::mpz_mul_ui(t1, p, mag[2]);
    if neg[2] {
        (*t1).size = -(*t1).size;
    }
    gmp::mpz_mul_ui(t2, q, mag[3]);
    if neg[3] {
        (*t2).size = -(*t2).size;
    }
    gmp::mpz_add(t1, t1, t2); // new q
    gmp::mpz_swap(p, t0);
    gmp::mpz_swap(q, t1);
}

/// Partial reduction of `(bx, by)` (`by > bx ≥ 0`) via a **Lehmer-style loop
/// driven by GMP's 2-limb half-GCD `mpn_hgcd2`** — the hot-path partial reduction
/// under the `gmp-hgcd` feature. Matches the contract of
/// [`super::hgcd::partial_reduce_lehmer`]: reduces in place to `bx ≤ l` and
/// returns the cofactor column `(y, x)` and the reduction parity. See the module
/// docs for the unordered-result and overshoot handling.
pub(crate) fn partial_reduce_hgcd2(
    bx: &mut Integer,
    by: &mut Integer,
    l: &Integer,
) -> (Integer, Integer, bool) {
    let mut cof0 = Integer::from(0);
    let mut cof1 = Integer::from(1);
    let mut parity = false;
    let mut handoff = false;
    let lbits = l.significant_bits();
    PR2_SCRATCH.with(|scr| {
        let s = &mut *scr.borrow_mut();
        unsafe {
            let (t0, t1, t2) = (s.0.as_raw_mut(), s.1.as_raw_mut(), s.2.as_raw_mut());
            loop {
                if &*bx <= l || bx.cmp0() == Ordering::Equal {
                    break;
                }
                let nb = by.significant_bits();
                // Hand off to the precise word-Lehmer tail once within one 128-bit
                // window of L (so the final stop lands exactly at `bx ≤ l` instead
                // of overshooting), or when too small for a 128-bit head.
                if nb < lbits + 128 || nb < 130 {
                    handoff = true;
                    break;
                }
                let shift = (nb - 128) as u64;
                let (ah, al) = top128(by.as_raw(), shift);
                let (bh, bl) = top128(bx.as_raw(), shift);
                let mut m1 = HgcdMatrix1 { u: [[0; 2]; 2] };
                if mpn_hgcd2(ah, al, bh, bl, &mut m1) == 0 {
                    handoff = true; // heads don't determine a step
                    break;
                }
                let (u00, u01, u10, u11) = (m1.u[0][0], m1.u[0][1], m1.u[1][0], m1.u[1][1]);
                // (a;b) = M·(a';b') ⇒ reduce by M⁻¹ = det·[[u11,−u01],[−u10,u00]].
                // For det = +1 the signs are [+,−,−,+]; det = −1 flips them all.
                let det_pos = (u00 as u128) * (u11 as u128) > (u01 as u128) * (u10 as u128);
                let mag = [u11, u01, u10, u00];
                let neg = if det_pos {
                    [false, true, true, false]
                } else {
                    [true, false, false, true]
                };
                apply_u64(by.as_raw_mut(), bx.as_raw_mut(), mag, neg, t0, t1, t2);
                apply_u64(cof0.as_raw_mut(), cof1.as_raw_mut(), mag, neg, t0, t1, t2);
                if !det_pos {
                    parity = !parity;
                }
                // `mpn_hgcd2`'s reduced pair comes out unordered: restore `by ≥ bx`
                // by swapping operands, the cofactor column, and the parity (a row
                // swap flips det) — preserving `(by;bx) = M·(by0;bx0)`.
                if *by < *bx {
                    core::mem::swap(by, bx);
                    core::mem::swap(&mut cof0, &mut cof1);
                    parity = !parity;
                }
                // Termination guard: a correct window strictly shrinks `by`. If not
                // (degenerate matrix / negative operand), bail to the Lehmer tail
                // rather than spin forever.
                if by.significant_bits() >= nb || bx.cmp0() == Ordering::Less {
                    handoff = true;
                    break;
                }
            }
        }
    });
    if handoff {
        super::hgcd::partial_reduce_lehmer_cont(bx, by, l, cof0, cof1, parity)
    } else {
        (cof0, cof1, parity)
    }
}

/// One recursive-HGCD "half" reduction of `(a, b)` (`a > b > 0`, `a` ≥ 3 limbs)
/// via GMP's internal `mpn_hgcd`. Returns the reduced pair `(a', b')` and the
/// matrix `[m00, m01, m10, m11]` with `(a; b) = M·(a'; b')`. Used only by the
/// `bench_reductions` comparison (its fixed n/2 target makes it unsuitable for
/// driving the NUCOMP partial reduction — see the module docs).
pub(crate) fn hgcd_reduce_gmp(a: &Integer, b: &Integer) -> (Integer, Integer, [Integer; 4]) {
    unsafe {
        let n = (*a.as_raw()).size.unsigned_abs() as usize;
        assert!(n >= 3, "mpn_hgcd requires n >= 3 limbs");

        // Operand buffers of length n (b zero-padded), reduced in place.
        let mut ap = vec![0 as limb_t; n];
        let mut bp = vec![0 as limb_t; n];
        let al = limbs(a);
        ap[..al.len()].copy_from_slice(al);
        let bl = limbs(b);
        bp[..bl.len()].copy_from_slice(bl);

        // Matrix storage (4 entries × ((n+1)/2 + 1) limbs) and scratch.
        let s = n.div_ceil(2) + 1;
        let mut mstore = vec![0 as limb_t; 4 * s];
        let mut m = HgcdMatrix {
            alloc: 0,
            n: 0,
            p: [[ptr::null_mut(); 2]; 2],
        };
        mpn_hgcd_matrix_init(&mut m, n as c_long, mstore.as_mut_ptr());
        let itch = mpn_hgcd_itch(n as c_long) as usize;
        let mut tp = vec![0 as limb_t; itch];

        let nn = mpn_hgcd(
            ap.as_mut_ptr(),
            bp.as_mut_ptr(),
            n as c_long,
            &mut m,
            tp.as_mut_ptr(),
        ) as usize;

        if nn == 0 {
            // No reduction possible (inputs too small/close): identity.
            let id = [
                Integer::from(1),
                Integer::new(),
                Integer::new(),
                Integer::from(1),
            ];
            return (a.clone(), b.clone(), id);
        }
        let ared = Integer::from_digits(&ap[..nn], Order::Lsf);
        let bred = Integer::from_digits(&bp[..nn], Order::Lsf);
        let mn = m.n as usize;
        let ent =
            |pp: *mut limb_t| Integer::from_digits(core::slice::from_raw_parts(pp, mn), Order::Lsf);
        let mat = [
            ent(m.p[0][0]),
            ent(m.p[0][1]),
            ent(m.p[1][0]),
            ent(m.p[1][1]),
        ];
        (ared, bred, mat)
    }
}

thread_local! {
    /// Reused buffers for `partial_reduce_mpn`: the accumulating `hgcd_matrix`
    /// storage, the `mpn_hgcd_matrix_mul_1` scratch, and the new-`a` result mpz.
    static MPN_BUF: RefCell<(Vec<limb_t>, Vec<limb_t>, Integer)> =
        const { RefCell::new((Vec::new(), Vec::new(), Integer::new())) };
}

/// Partial reduction of `(bx, by)` (`by > bx >= 0`) via a GMP-native `mpn`-level
/// loop: each window reduces the full operands in place with
/// `mpn_hgcd_mul_matrix1_vector` (a fused `mpn` pass — no `rug::Integer` bridging,
/// no per-op `mpz` overhead) and accumulates the reduction into an `hgcd_matrix`
/// with `mpn_hgcd_matrix_mul_1`. The cofactors `(y, x)` and parity are extracted
/// from the matrix (`(by0;bx0) = M*(byr;bx)`, `det = +-1`: `x = det*m00`,
/// `y = -det*m01`), then the precise word-Lehmer tail finishes to `bx <= l`
/// (avoiding the coarse-window overshoot). All operands stay in their own mpz
/// limb storage via `mpz_limbs_modify`/`_finish`; the loop allocates nothing.
pub(crate) fn partial_reduce_mpn(
    bx: &mut Integer,
    by: &mut Integer,
    l: &Integer,
) -> (Integer, Integer, bool) {
    let lbits = l.significant_bits();
    let (y, x, parity) = MPN_BUF.with(|buf| {
        let buf = &mut *buf.borrow_mut();
        let (mstore, tp, rsc) = (&mut buf.0, &mut buf.1, &mut buf.2);
        unsafe {
            let n0 = (*by.as_raw()).size as c_long; // by limb count (> 0)
            if n0 < 3 {
                // Too small for mpn_hgcd2: identity matrix => pure Lehmer below.
                return (Integer::from(0), Integer::from(1), false);
            }
            mstore.clear();
            mstore.resize((4 * ((n0 + 1) / 2 + 1)) as usize, 0);
            tp.clear();
            tp.resize(n0 as usize + 2, 0);
            let mut m = HgcdMatrix {
                alloc: 0,
                n: 0,
                p: [[ptr::null_mut(); 2]; 2],
            };
            mpn_hgcd_matrix_init(&mut m, n0, mstore.as_mut_ptr());

            loop {
                if &*bx <= l || bx.cmp0() == Ordering::Equal {
                    break;
                }
                let nb = by.significant_bits();
                // Stop within one 128-bit window of L (Lehmer finishes precisely),
                // or when too small for a normalised 128-bit head.
                if nb < lbits + 128 || nb < 130 {
                    break;
                }
                let shift = (nb - 128) as u64;
                let (ah, al) = top128(by.as_raw(), shift);
                let (bh, bl) = top128(bx.as_raw(), shift);
                let mut m1 = HgcdMatrix1 { u: [[0; 2]; 2] };
                if mpn_hgcd2(ah, al, bh, bl, &mut m1) == 0 {
                    break; // heads don't determine a step
                }
                // Apply M1 to (by, bx) on the limb arrays in place.
                let ncur = (*by.as_raw()).size as c_long;
                let bx_n = (*bx.as_raw()).size.unsigned_abs() as usize;
                let ap = gmp::mpz_limbs_read(by.as_raw());
                let bp = gmp::mpz_limbs_modify(bx.as_raw_mut(), ncur + 1); // +1 for the mpn carry limb
                for i in bx_n..(ncur as usize) {
                    *bp.add(i) = 0; // zero-pad bx to ncur limbs
                }
                let rp = gmp::mpz_limbs_modify(rsc.as_raw_mut(), ncur + 1);
                let ret = mpn_matrix22_mul1_inverse_vector(&m1, rp, ap, bp, ncur);
                gmp::mpz_limbs_finish(rsc.as_raw_mut(), ret); // rsc = new-a
                gmp::mpz_limbs_finish(bx.as_raw_mut(), ret); // bx = new-b
                gmp::mpz_swap(by.as_raw_mut(), rsc.as_raw_mut()); // by = new-a
                mpn_hgcd_matrix_mul_1(&mut m, &m1, tp.as_mut_ptr()); // M <- M * M1
                                                                     // Normalized heads can leave the reduced pair unordered (by < bx).
                                                                     // Restore by > bx by swapping operands and M's columns: from
                                                                     // (by0;bx0) = M*(by;bx) and swapping (by;bx) -> (bx;by) we get
                                                                     // (by0;bx0) = (M*P)*(bx;by), i.e. swap p[i][0] <-> p[i][1].
                if *by < *bx {
                    core::mem::swap(by, bx);
                    m.p[0].swap(0, 1);
                    m.p[1].swap(0, 1);
                }
            }

            // Cofactors from M: (by0;bx0) = M*(byr;bx), det=+-1 =>
            //   x = det*m00, y = -det*m01, parity = (det < 0).
            let mn = m.n as usize;
            let ent = |pp: *mut limb_t| {
                Integer::from_digits(core::slice::from_raw_parts(pp, mn), Order::Lsf)
            };
            let m00 = ent(m.p[0][0]);
            let m01 = ent(m.p[0][1]);
            let m10 = ent(m.p[1][0]);
            let m11 = ent(m.p[1][1]);
            let det = Integer::from(&m00 * &m11) - Integer::from(&m01 * &m10);
            if det.cmp0() == Ordering::Less {
                (m01, Integer::from(-&m00), true) // (y, x) = (m01, -m00)
            } else {
                (Integer::from(-&m01), m00, false) // (y, x) = (-m01, m00)
            }
        }
    });
    // Finish precisely to bx <= l, composing the cofactors.
    super::hgcd::partial_reduce_lehmer_cont(bx, by, l, y, x, parity)
}

#[cfg(test)]
mod tests {
    use rug::rand::RandState;

    use super::*;

    fn balanced_pair(rng: &mut RandState, bits: u32) -> (Integer, Integer) {
        let mut a = Integer::from(Integer::random_bits(bits, rng));
        a.set_bit(bits - 1, true); // exactly `bits` bits
        a.set_bit(0, true);
        let mut b = Integer::from(Integer::random_bits(bits, rng));
        b.set_bit(bits - 1, false);
        b.set_bit(bits - 2, true); // exactly `bits-1` bits => b < a, same limb count
        b.set_bit(0, true);
        (a, b)
    }

    #[test]
    fn gmp_hgcd_matrix_invariant() {
        let mut rng = RandState::new();
        rng.seed(&Integer::from(2024));
        for &bits in &[1024u32, 4096, 16384, 65536] {
            for _ in 0..10 {
                let (a, b) = balanced_pair(&mut rng, bits);
                let (ar, br, m) = hgcd_reduce_gmp(&a, &b);
                // GMP convention (verified): (a; b) = M*(a'; b').
                let ra = Integer::from(&m[0] * &ar) + Integer::from(&m[1] * &br);
                let rb = Integer::from(&m[2] * &ar) + Integer::from(&m[3] * &br);
                assert_eq!(ra, a, "row0 ({bits} bits)");
                assert_eq!(rb, b, "row1 ({bits} bits)");
                let det = Integer::from(&m[0] * &m[3]) - Integer::from(&m[1] * &m[2]);
                assert!(det == 1 || det == -1, "det +-1 ({bits} bits)");
                assert!(br.significant_bits() <= a.significant_bits() / 2 + 80);
                assert!(br.significant_bits() < a.significant_bits());
            }
        }
    }

    /// `partial_reduce_hgcd2` must satisfy the same continued-fraction cofactor
    /// invariants as the Lehmer reference: with reduced `(bx, byr)` and `(y, x,
    /// parity)`,  `|x·byr − y·bx| == by0`  and  `bx ≡ x·bx0 (mod by0)`, and
    /// `bx ≤ l < byr`. This pins the matrix convention/sign handling.
    #[test]
    fn hgcd2_cofactor_invariant() {
        let mut rng = RandState::new();
        rng.seed(&Integer::from(13));
        for &bits in &[300u32, 896, 1796, 4096] {
            let l = Integer::from(1) << (bits / 2);
            for _ in 0..40 {
                let (by0, bx0) = balanced_pair(&mut rng, bits); // by0 > bx0
                let (mut bx, mut by) = (bx0.clone(), by0.clone());
                let (y, x, parity) = partial_reduce_hgcd2(&mut bx, &mut by, &l);
                let det_rel = Integer::from(&x * &by) - y * &bx;
                assert_eq!(det_rel.clone().abs(), by0, "det invariant ({bits} bits)");
                assert_eq!(
                    det_rel.cmp0() == Ordering::Less,
                    parity,
                    "parity ({bits} bits)"
                );
                let r = (Integer::from(&bx) - x * bx0) % &by0;
                assert_eq!(r, 0, "bx ≡ x·bx0 (mod by0) ({bits} bits)");
                assert!(
                    bx <= l || bx.cmp0() == Ordering::Equal,
                    "bx ≤ l ({bits} bits)"
                );
                assert!(by >= bx, "by ≥ bx ({bits} bits)");
            }
        }
    }

    /// Same invariant check for the mpn-native `partial_reduce_mpn`.
    #[test]
    fn mpn_cofactor_invariant() {
        let mut rng = RandState::new();
        rng.seed(&Integer::from(13));
        for &bits in &[300u32, 896, 1796, 4096] {
            let l = Integer::from(1) << (bits / 2);
            for _ in 0..40 {
                let (by0, bx0) = balanced_pair(&mut rng, bits);
                let (mut bx, mut by) = (bx0.clone(), by0.clone());
                let (y, x, parity) = partial_reduce_mpn(&mut bx, &mut by, &l);
                let det_rel = Integer::from(&x * &by) - y * &bx;
                assert_eq!(det_rel.clone().abs(), by0, "det invariant ({bits} bits)");
                assert_eq!(
                    det_rel.cmp0() == Ordering::Less,
                    parity,
                    "parity ({bits} bits)"
                );
                let r = (Integer::from(&bx) - x * bx0) % &by0;
                assert_eq!(r, 0, "bx == x*bx0 mod by0 ({bits} bits)");
                assert!(
                    bx <= l || bx.cmp0() == Ordering::Equal,
                    "bx <= l ({bits} bits)"
                );
                assert!(by >= bx, "by >= bx ({bits} bits)");
            }
        }
    }

    /// Same-run head-to-head of the partial reduction at the CL operand size
    /// (`By₀ ≈ 895` bits → `L ≈ 448` bits): word-Lehmer vs the `mpn_hgcd2`
    /// 128-bit-window loop. A clone-only baseline is subtracted so only the
    /// reduction is timed.
    /// `cargo test --release --features gmp-hgcd --lib -- --ignored --nocapture bench_partial_cl`
    #[test]
    #[ignore]
    fn bench_partial_cl() {
        use std::time::Instant;
        let mut rng = RandState::new();
        rng.seed(&Integer::from(99));
        let l = Integer::from(1) << 448u32;
        let pairs: Vec<(Integer, Integer)> = (0..200)
            .map(|_| {
                let mut by = Integer::from(Integer::random_bits(895, &mut rng));
                by.set_bit(894, true);
                let bx = Integer::from(Integer::random_bits(880, &mut rng));
                (bx, by) // bx < by
            })
            .collect();
        let bench = |label: &str, f: &dyn Fn(&mut Integer, &mut Integer)| -> f64 {
            for (bx, by) in &pairs {
                let (mut a, mut b) = (bx.clone(), by.clone());
                f(&mut a, &mut b);
            }
            let mut best = f64::MAX;
            for _ in 0..15 {
                let t = Instant::now();
                for (bx, by) in &pairs {
                    let (mut a, mut b) = (bx.clone(), by.clone());
                    f(&mut a, &mut b);
                }
                best = best.min(t.elapsed().as_secs_f64() * 1e6 / pairs.len() as f64);
            }
            println!("  {label:24} {best:7.3} µs/op");
            best
        };
        let base = bench("clone-only baseline", &|_bx, _by| {});
        let leh = bench("lehmer (i64)", &|bx, by| {
            super::super::hgcd::partial_reduce_lehmer(bx, by, &l);
        });
        let h2 = bench("hgcd2 apply_u64", &|bx, by| {
            let _ = partial_reduce_hgcd2(bx, by, &l);
        });
        let mp = bench("hgcd2 mpn-native", &|bx, by| {
            let _ = partial_reduce_mpn(bx, by, &l);
        });
        println!(
            "  net (minus clone): lehmer {:.2} | apply_u64 {:.2} | mpn {:.2} (us)",
            leh - base,
            h2 - base,
            mp - base
        );
    }
}
