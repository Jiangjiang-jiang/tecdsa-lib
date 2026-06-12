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
    static PR2_SCRATCH: RefCell<(Integer, Integer, Integer)> =
        const { RefCell::new((Integer::new(), Integer::new(), Integer::new())) };
}

#[repr(C)]
struct HgcdMatrix {
    alloc: c_long,
    n: c_long,
    p: [[*mut limb_t; 2]; 2],
}

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
    #[link_name = "__gmpn_matrix22_mul1_inverse_vector"]
    fn mpn_matrix22_mul1_inverse_vector(
        m: *const HgcdMatrix1,
        rp: *mut limb_t,
        ap: *const limb_t,
        bp: *mut limb_t,
        n: c_long,
    ) -> c_long;
    #[link_name = "__gmpn_hgcd_matrix_mul_1"]
    fn mpn_hgcd_matrix_mul_1(m: *mut HgcdMatrix, m1: *const HgcdMatrix1, tp: *mut limb_t);
}

unsafe fn limbs(x: &Integer) -> &[limb_t] {
    let raw = x.as_raw();
    let n = (*raw).size.unsigned_abs() as usize;
    if n == 0 {
        &[]
    } else {
        core::slice::from_raw_parts((*raw).d.as_ptr(), n)
    }
}

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
    gmp::mpz_add(t0, t0, t1);
    gmp::mpz_mul_ui(t1, p, mag[2]);
    if neg[2] {
        (*t1).size = -(*t1).size;
    }
    gmp::mpz_mul_ui(t2, q, mag[3]);
    if neg[3] {
        (*t2).size = -(*t2).size;
    }
    gmp::mpz_add(t1, t1, t2);
    gmp::mpz_swap(p, t0);
    gmp::mpz_swap(q, t1);
}

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
                if nb < lbits + 128 || nb < 130 {
                    handoff = true;
                    break;
                }
                let shift = (nb - 128) as u64;
                let (ah, al) = top128(by.as_raw(), shift);
                let (bh, bl) = top128(bx.as_raw(), shift);
                let mut m1 = HgcdMatrix1 { u: [[0; 2]; 2] };
                if mpn_hgcd2(ah, al, bh, bl, &mut m1) == 0 {
                    handoff = true;
                    break;
                }
                let (u00, u01, u10, u11) = (m1.u[0][0], m1.u[0][1], m1.u[1][0], m1.u[1][1]);
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
                if *by < *bx {
                    core::mem::swap(by, bx);
                    core::mem::swap(&mut cof0, &mut cof1);
                    parity = !parity;
                }
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

pub(crate) fn hgcd_reduce_gmp(a: &Integer, b: &Integer) -> (Integer, Integer, [Integer; 4]) {
    unsafe {
        let n = (*a.as_raw()).size.unsigned_abs() as usize;
        assert!(n >= 3, "mpn_hgcd requires n >= 3 limbs");

        let mut ap = vec![0 as limb_t; n];
        let mut bp = vec![0 as limb_t; n];
        let al = limbs(a);
        ap[..al.len()].copy_from_slice(al);
        let bl = limbs(b);
        bp[..bl.len()].copy_from_slice(bl);

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
    static MPN_BUF: RefCell<(Vec<limb_t>, Vec<limb_t>, Integer)> =
        const { RefCell::new((Vec::new(), Vec::new(), Integer::new())) };
}

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
            let n0 = (*by.as_raw()).size as c_long;
            if n0 < 3 {
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
                if nb < lbits + 128 || nb < 130 {
                    break;
                }
                let shift = (nb - 128) as u64;
                let (ah, al) = top128(by.as_raw(), shift);
                let (bh, bl) = top128(bx.as_raw(), shift);
                let mut m1 = HgcdMatrix1 { u: [[0; 2]; 2] };
                if mpn_hgcd2(ah, al, bh, bl, &mut m1) == 0 {
                    break;
                }
                let ncur = (*by.as_raw()).size as c_long;
                let bx_n = (*bx.as_raw()).size.unsigned_abs() as usize;
                let ap = gmp::mpz_limbs_read(by.as_raw());
                let bp = gmp::mpz_limbs_modify(bx.as_raw_mut(), ncur + 1);
                for i in bx_n..(ncur as usize) {
                    *bp.add(i) = 0;
                }
                let rp = gmp::mpz_limbs_modify(rsc.as_raw_mut(), ncur + 1);
                let ret = mpn_matrix22_mul1_inverse_vector(&m1, rp, ap, bp, ncur);
                gmp::mpz_limbs_finish(rsc.as_raw_mut(), ret);
                gmp::mpz_limbs_finish(bx.as_raw_mut(), ret);
                gmp::mpz_swap(by.as_raw_mut(), rsc.as_raw_mut());
                mpn_hgcd_matrix_mul_1(&mut m, &m1, tp.as_mut_ptr());
                if *by < *bx {
                    core::mem::swap(by, bx);
                    m.p[0].swap(0, 1);
                    m.p[1].swap(0, 1);
                }
            }

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
                (m01, Integer::from(-&m00), true)
            } else {
                (Integer::from(-&m01), m00, false)
            }
        }
    });
    super::hgcd::partial_reduce_lehmer_cont(bx, by, l, y, x, parity)
}

#[cfg(test)]
mod tests {
    use rug::rand::RandState;

    use super::*;

    fn balanced_pair(rng: &mut RandState, bits: u32) -> (Integer, Integer) {
        let mut a = Integer::from(Integer::random_bits(bits, rng));
        a.set_bit(bits - 1, true);
        a.set_bit(0, true);
        let mut b = Integer::from(Integer::random_bits(bits, rng));
        b.set_bit(bits - 1, false);
        b.set_bit(bits - 2, true);
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

    #[test]
    fn hgcd2_cofactor_invariant() {
        let mut rng = RandState::new();
        rng.seed(&Integer::from(13));
        for &bits in &[300u32, 896, 1796, 4096] {
            let l = Integer::from(1) << (bits / 2);
            for _ in 0..40 {
                let (by0, bx0) = balanced_pair(&mut rng, bits);
                let (mut bx, mut by) = (bx0.clone(), by0.clone());
                let (y, x, parity) = partial_reduce_hgcd2(&mut bx, &mut by, &l);
                let det_rel = Integer::from(&x * &by) - Integer::from(&y * &bx);
                assert_eq!(det_rel.clone().abs(), by0, "det invariant ({bits} bits)");
                assert_eq!(
                    det_rel.cmp0() == Ordering::Less,
                    parity,
                    "parity ({bits} bits)"
                );
                let r = (Integer::from(&bx) - Integer::from(&x * &bx0)) % &by0;
                assert_eq!(r, 0, "bx ≡ x·bx0 (mod by0) ({bits} bits)");
                assert!(
                    bx <= l || bx.cmp0() == Ordering::Equal,
                    "bx ≤ l ({bits} bits)"
                );
                assert!(by >= bx, "by ≥ bx ({bits} bits)");
            }
        }
    }

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
                let det_rel = Integer::from(&x * &by) - Integer::from(&y * &bx);
                assert_eq!(det_rel.clone().abs(), by0, "det invariant ({bits} bits)");
                assert_eq!(
                    det_rel.cmp0() == Ordering::Less,
                    parity,
                    "parity ({bits} bits)"
                );
                let r = (Integer::from(&bx) - Integer::from(&x * &bx0)) % &by0;
                assert_eq!(r, 0, "bx == x*bx0 mod by0 ({bits} bits)");
                assert!(
                    bx <= l || bx.cmp0() == Ordering::Equal,
                    "bx <= l ({bits} bits)"
                );
                assert!(by >= bx, "by >= bx ({bits} bits)");
            }
        }
    }

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
                (bx, by)
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
