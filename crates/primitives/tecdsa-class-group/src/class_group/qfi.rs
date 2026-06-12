use core::{cell::RefCell, cmp::Ordering, fmt};
use std::borrow::Borrow;

use gmp_mpfr_sys::gmp;
use rug::Integer;

use super::{mpz::Mpz, nt::sqrt_mod_prime};

thread_local! {
    static REDUCE_SCRATCH: RefCell<ReduceScratch> = RefCell::new(ReduceScratch::default());
}

#[cfg(test)]
thread_local! {
    static LAST_REDUCE_STEPS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static NUCOMP_FINISH_OK: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static SQ_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static SQ_SLOW: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[derive(Default)]
struct ReduceScratch {
    q: Integer,
    t: Integer,
    two: Integer,
    sc: Integer,
    nb: Integer,
}

fn solve_lc(a: &Mpz, b: &Mpz, m: &Mpz) -> Option<(Mpz, Mpz)> {
    let (g, u, _v) = a.gcdext(m);
    let (q, r) = b.fdiv_qr(&g);
    if !r.is_zero() {
        return None;
    }
    let modulus = m.divexact(&g);
    let x0 = (&q * &u).modulo(&modulus);
    Some((x0, modulus))
}

#[derive(Clone, Debug)]
pub struct QFI {
    pub(crate) a: Mpz,
    pub(crate) b: Mpz,
    pub(crate) c: Mpz,
}

impl QFI {
    pub fn from_abc(a: Mpz, b: Mpz, c: Mpz) -> QFI {
        QFI { a, b, c }
    }

    pub fn a(&self) -> &Mpz {
        &self.a
    }
    pub fn b(&self) -> &Mpz {
        &self.b
    }
    pub fn c(&self) -> &Mpz {
        &self.c
    }

    pub fn discriminant(&self) -> Mpz {
        &(&self.b * &self.b) - &(&self.a * &self.c).mul_2exp(2)
    }

    pub fn is_principal(&self) -> bool {
        self.a.is_one()
    }

    pub fn neg(&mut self) {
        use rug::ops::NegAssign;
        if self.a != self.b && self.a != self.c {
            self.b.0.neg_assign();
        }
    }

    fn primitive_coprime_to(&self, l: &Mpz) -> (Mpz, Mpz, Mpz) {
        let one = Mpz::from(1u64);
        if self.a.gcd(l) == one {
            (self.a.clone(), self.b.clone(), self.c.clone())
        } else if self.c.gcd(l) == one {
            (self.c.clone(), self.b.neg(), self.a.clone())
        } else {
            let abc = &(&self.a + &self.b) + &self.c;
            let nb = &self.b.neg() - &self.a.mul_2exp(1);
            (abc, nb, self.a.clone())
        }
    }

    pub(crate) fn lift(&self, l: &Mpz) -> QFI {
        let (a, b, c) = self.primitive_coprime_to(l);
        let l2 = l * l;
        QFI::from_abc(a, &b * l, &c * &l2)
    }

    pub(crate) fn to_maximal_order(&self, l: &Mpz, delta_k: &Mpz) -> QFI {
        let (a, b, _c) = self.primitive_coprime_to(l);
        let (_g, u, v) = l.gcdext(&a);
        let two_a = a.mul_2exp(1);
        let mut bn = (&(&b * &u) + &(&a * &v)).modulo(&two_a);
        if bn > a {
            bn = &bn - &two_a;
        }
        let cc = (&(&bn * &bn) - delta_k).divexact(&a.mul_2exp(2));
        QFI::from_abc(a, bn, cc)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for x in [&self.a(), &self.b(), &self.c()] {
            let mag = x.to_bytes_be();
            buf.push((x.sgn() < 0) as u8);
            buf.extend_from_slice(&(mag.len() as u32).to_be_bytes());
            buf.extend_from_slice(&mag);
        }
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        fn get_mpz(buf: &[u8], pos: &mut usize) -> Mpz {
            let neg = buf[*pos] == 1;
            *pos += 1;
            let len = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
            *pos += 4;
            let mut v = Mpz::from_bytes_be(&buf[*pos..*pos + len]);
            *pos += len;
            if neg {
                use rug::ops::NegAssign;
                v.0.neg_assign();
            }
            v
        }
        let mut p = 0;
        let (a, b, c) = (
            get_mpz(buf, &mut p),
            get_mpz(buf, &mut p),
            get_mpz(buf, &mut p),
        );
        Self::from_abc(a, b, c)
    }
}

impl PartialEq for QFI {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b && self.c == other.c
    }
}
impl Eq for QFI {}

impl fmt::Display for QFI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {}, {})", self.a, self.b, self.c)
    }
}

impl FixedBaseComb {
    pub fn max_bits(&self) -> usize {
        self.blocks * self.block_len
    }
}

#[derive(Clone, Debug)]
pub struct ClassGroup {
    disc: Mpz,
    l_thresh: Mpz,
}

#[derive(Clone, Debug)]
pub struct FixedBaseComb {
    blocks: usize,
    block_len: usize,
    table: Vec<QFI>,
}

impl ClassGroup {
    pub fn new(disc: Mpz) -> ClassGroup {
        debug_assert!(disc.sgn() < 0, "discriminant must be negative");
        let abs = disc.abs();
        let l_thresh = abs.fdiv_2exp(2).root(4);
        ClassGroup { disc, l_thresh }
    }

    pub fn discriminant(&self) -> &Mpz {
        &self.disc
    }

    pub fn identity(&self) -> QFI {
        let one = Mpz::from(1u64);
        if self.disc.modulo(&Mpz::from(4u64)) == 1u64 {
            let c = (&one - &self.disc).divexact(&Mpz::from(4u64));
            QFI::from_abc(one.clone(), one, c)
        } else {
            let c = self.disc.neg().divexact(&Mpz::from(4u64));
            QFI::from_abc(one, Mpz::new(), c)
        }
    }

    pub fn reduce(&self, f: &mut QFI) {
        REDUCE_SCRATCH.with(|scr| {
            let mut scr = scr.borrow_mut();
            unsafe {
                let a = f.a.0.as_raw_mut();
                let b = f.b.0.as_raw_mut();
                let c = f.c.0.as_raw_mut();
                let q = scr.q.as_raw_mut();
                let t = scr.t.as_raw_mut();
                let two = scr.two.as_raw_mut();
                let sc = scr.sc.as_raw_mut();
                let nb = scr.nb.as_raw_mut();

                gmp::mpz_mul_2exp(two, a, 1);
                gmp::mpz_sub(t, a, b);
                gmp::mpz_fdiv_q(q, t, two);
                gmp::mpz_mul(t, a, q);
                gmp::mpz_add(t, t, b);
                gmp::mpz_mul(t, t, q);
                gmp::mpz_add(c, c, t);
                gmp::mpz_mul(t, two, q);
                gmp::mpz_add(b, b, t);

                #[cfg(test)]
                let mut steps = 0u32;
                while gmp::mpz_cmp(a, c) > 0 {
                    #[cfg(test)]
                    {
                        steps += 1;
                    }
                    gmp::mpz_mul_2exp(two, c, 1);
                    gmp::mpz_add(t, c, b);
                    gmp::mpz_fdiv_q(q, t, two);
                    gmp::mpz_mul(sc, q, c);
                    gmp::mpz_sub(nb, sc, b);
                    gmp::mpz_mul(nb, nb, q);
                    gmp::mpz_add(nb, nb, a);
                    gmp::mpz_mul_2exp(t, sc, 1);
                    gmp::mpz_sub(t, t, b);
                    gmp::mpz_swap(a, c);
                    gmp::mpz_swap(b, t);
                    gmp::mpz_swap(c, nb);
                }
                if gmp::mpz_cmp(a, c) == 0 && (*b).size < 0 {
                    gmp::mpz_neg(b, b);
                }
                #[cfg(test)]
                LAST_REDUCE_STEPS.with(|s| s.set(steps));
            }
        });
    }

    pub fn reduced(&self, f: &QFI) -> QFI {
        let mut g = f.clone();
        self.reduce(&mut g);
        g
    }

    pub fn inverse(&self, f: &QFI) -> QFI {
        let mut g = QFI::from_abc(f.a.clone(), f.b.neg(), f.c.clone());
        self.reduce(&mut g);
        g
    }

    pub fn smallest_split_prime(&self) -> Mpz {
        let mut l = Mpz::from(2u64);
        loop {
            if self.disc.kronecker(&l) == 1 {
                return l;
            }
            l = l.next_prime();
        }
    }

    pub fn prime_form(&self, l: &Mpz) -> QFI {
        let (b, c);
        if *l == 2u64 {
            b = Mpz::from(1u64);
            c = (&Mpz::from(1u64) - &self.disc).divexact(&Mpz::from(8u64));
        } else {
            let dl = self.disc.modulo(l);
            let r = sqrt_mod_prime(&dl, l).expect("prime_form: l does not split the discriminant");
            let bb = if r.is_odd() { r } else { &r + l };
            let four_l = l.mul_2exp(2);
            c = (&(&bb * &bb) - &self.disc).divexact(&four_l);
            b = bb;
        }
        let mut f = QFI::from_abc(l.clone(), b, c);
        self.reduce(&mut f);
        f
    }

    pub(crate) fn compose_dirichlet(&self, f1: &QFI, f2: &QFI) -> QFI {
        let (a, b, c) = (&f1.a, &f1.b, &f1.c);
        let (al, be, ga) = (&f2.a, &f2.b, &f2.c);
        let _ = ga;

        let g = (b + be).fdiv_2exp(1);
        let h = (be - b).fdiv_2exp(1);
        let w = a.gcd(al).gcd(&g);

        let j = w.clone();
        let s = a.divexact(&w);
        let t = al.divexact(&w);
        let u = g.divexact(&w);

        let st = &s * &t;
        let tu = &t * &u;
        let rhs3 = &(&h * &u) + &(&s * c);
        let (mu, nu) = solve_lc(&tu, &rhs3, &st).expect("compose: congruence (3) unsolvable");

        let rhs4 = &h - &(&t * &mu);
        let coef4 = &t * &nu;
        let (lambda, _) = solve_lc(&coef4, &rhs4, &s).expect("compose: congruence (4) unsolvable");

        let k = &mu + &(&nu * &lambda);
        let l = (&(&k * &t) - &h).divexact(&s);
        let m = (&(&(&tu * &k) - &(&h * &u)) - &(c * &s)).divexact(&st);

        let aa = st;
        let bb = &(&j * &u) - &(&(&k * &t) + &(&l * &s));
        let cc = &(&k * &l) - &(&j * &m);

        let mut f3 = QFI::from_abc(aa, bb, cc);
        self.reduce(&mut f3);
        f3
    }

    pub fn compose(&self, f1: &QFI, f2: &QFI) -> QFI {
        let (f1, f2) = if f1.a >= f2.a { (f1, f2) } else { (f2, f1) };
        let (a1, b1, c1) = (&f1.a, &f1.b, &f1.c);
        let (a2, b2, c2) = (&f2.a, &f2.b, &f2.c);

        let ss = (b1 + b2).fdiv_2exp(1);
        let m = (b2 - b1).fdiv_2exp(1);

        let (ff, u, v) = a2.gcdext(a1);

        let (g, by, cy, dy, bx0);
        if ss.modulo(&ff).is_zero() {
            g = ff.clone();
            by = a1.divexact(&g);
            cy = a2.divexact(&g);
            dy = ss.divexact(&g);
            bx0 = (&m * &u).modulo(&by);
        } else {
            let (gg, _x, _y) = ff.gcdext(&ss);
            let hh = ff.divexact(&gg);
            by = a1.divexact(&gg);
            cy = a2.divexact(&gg);
            dy = ss.divexact(&gg);
            let l = (&_y * &(&(&u * &c1.modulo(&hh)) + &(&v * &c2.modulo(&hh)))).modulo(&hh);
            bx0 = (&(&u * &m.divexact(&hh)) + &(&l * &a1.divexact(&hh))).modulo(&by);
            g = gg;
        }
        if by.is_one() {
            return self.compose_dirichlet(f1, f2);
        }
        self.nucomp_finish(&g, bx0, by, cy, dy, &m, c2, &ss)
            .unwrap_or_else(|| self.compose_dirichlet(f1, f2))
    }

    pub fn square(&self, f: &QFI) -> QFI {
        #[cfg(test)]
        SQ_CALLS.with(|s| s.set(s.get() + 1));
        if let Some(sq) = self.nudupl(f) {
            return sq;
        }
        #[cfg(test)]
        SQ_SLOW.with(|s| s.set(s.get() + 1));
        let (a, b, c) = (&f.a, &f.b, &f.c);
        let binv = match b.invert(a) {
            Some(x) => x,
            None => return self.compose_dirichlet(f, f),
        };
        let mu = (c * &binv).modulo(a);
        let aa = a * a;
        let bb = b - &(&mu * a).mul_2exp(1);
        let cc = &(&mu * &mu) - &(&(b * &mu) - c).divexact(a);
        let mut sq = QFI::from_abc(aa, bb, cc);
        self.reduce(&mut sq);
        sq
    }

    fn nudupl(&self, f: &QFI) -> Option<QFI> {
        let (a, b, c) = (&f.a, &f.b, &f.c);
        let (gg, u, _v) = b.gcdext(a);
        let by0 = a.divexact(&gg);
        if by0.is_one() {
            return None;
        }
        let dy = b.divexact(&gg);
        let bx0 = (&u * c).modulo(&by0);

        let mut bxi = bx0.0;
        let mut byi = by0.0.clone();
        let (yi, xi, z_odd) = self.partial_reduce(&mut bxi, &mut byi);
        if bxi.cmp0() == Ordering::Equal {
            return None;
        }
        let bx = Mpz(bxi);
        let mut byr = Mpz(byi);
        let x = Mpz(xi);
        let mut y = Mpz(yi);
        if z_odd {
            byr = byr.neg();
            y = y.neg();
        }
        if x.is_zero() {
            return None;
        }
        let (ax, ay) = if gg.is_one() {
            (x.clone(), y.clone())
        } else {
            (&gg * &x, &gg * &y)
        };

        let dx = (&(&bx * &dy) - &(c * &x)).divexact_checked(&by0)?;
        let dxa = &dx * &ay;
        let dy2 = (&dxa + b).divexact_checked(&ax)?;
        let a3 = &(&byr * &byr) - &(&ay * &dy2);
        let c3 = &(&bx * &bx) - &(&ax * &dx);
        let b3 = &(&(&dxa + &dxa) + b) - &(&bx * &byr).mul_2exp(1);
        if a3.is_zero() {
            return None;
        }
        #[cfg(test)]
        NUCOMP_FINISH_OK.with(|s| s.set(s.get() + 1));
        let mut f3 = QFI::from_abc(a3, b3, c3);
        self.reduce(&mut f3);
        Some(f3)
    }

    #[inline]
    fn partial_reduce(&self, bx: &mut Integer, by: &mut Integer) -> (Integer, Integer, bool) {
        #[cfg(feature = "gmp-hgcd")]
        {
            super::hgcd_gmp::partial_reduce_hgcd2(bx, by, &self.l_thresh.0)
        }
        #[cfg(not(feature = "gmp-hgcd"))]
        {
            if by.significant_bits() >= super::hgcd::NUCOMP_HGCD_DISPATCH_BITS {
                super::hgcd::partial_reduce_hgcd(bx, by, &self.l_thresh.0)
            } else {
                super::hgcd::partial_reduce_lehmer(bx, by, &self.l_thresh.0)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn nucomp_finish(
        &self,
        g: &Mpz,
        bx0: Mpz,
        by0: Mpz,
        cy: Mpz,
        dy: Mpz,
        m: &Mpz,
        w2: &Mpz,
        ss: &Mpz,
    ) -> Option<QFI> {
        let by_orig = by0.clone();
        let mut bxi = bx0.0;
        let mut byi = by0.0;
        let (yi, xi, z_odd) = self.partial_reduce(&mut bxi, &mut byi);
        if bxi.cmp0() == Ordering::Equal {
            return None;
        }
        let bx = Mpz(bxi);
        let mut byr = Mpz(byi);
        let x = Mpz(xi);
        let mut y = Mpz(yi);
        if z_odd {
            byr = byr.neg();
            y = y.neg();
        }
        if x.is_zero() {
            return None;
        }
        let ax = g * &x;
        let ay = g * &y;
        let cx = (&(&bx * &cy) - &(m * &x)).divexact_checked(&by_orig)?;
        let dx = (&(&bx * &dy) - &(w2 * &x)).divexact_checked(&by_orig)?;
        let cy2 = (&(&byr * &cx) + m).divexact_checked(&bx)?;
        let dy2 = (&(&dx * &ay) + ss).divexact_checked(&ax)?;
        let u3 = &(&byr * &cy2) - &(&ay * &dy2);
        let w3 = &(&bx * &cx) - &(&ax * &dx);
        let v3 = &(&(&ax * &dy2) + &(&ay * &dx)) - &(&(&bx * &cy2) + &(&byr * &cx));
        if u3.is_zero() {
            return None;
        }
        #[cfg(test)]
        NUCOMP_FINISH_OK.with(|s| s.set(s.get() + 1));
        let mut f3 = QFI::from_abc(u3, v3, w3);
        self.reduce(&mut f3);
        Some(f3)
    }

    pub fn nupow(&self, f: &QFI, n: &Mpz) -> QFI {
        self.exp(f, n)
    }

    pub fn exp(&self, f: &QFI, n: &Mpz) -> QFI {
        if n.is_zero() {
            return self.identity();
        }
        let (base, e) = if n.sgn() < 0 {
            (self.inverse(f), n.neg())
        } else {
            (f.clone(), n.clone())
        };
        self.exp_window(&base, &e)
    }

    fn exp_window(&self, base: &QFI, e: &Mpz) -> QFI {
        let w = naf_width(e.nbits());
        let table_len = 1usize << (w - 2);
        let base_sq = self.square(base);
        let mut odds = Vec::with_capacity(table_len);
        odds.push(base.clone());
        for _ in 1..table_len {
            let prev = odds.last().unwrap();
            odds.push(self.compose(prev, &base_sq));
        }

        let naf = wnaf(e, w);
        let mut result = self.identity();
        for &d in naf.iter().rev() {
            result = self.square(&result);
            if d != 0 {
                let idx = (d.unsigned_abs() as usize - 1) / 2;
                if d > 0 {
                    result = self.compose(&result, &odds[idx]);
                } else {
                    result = self.compose(&result, &self.inverse(&odds[idx]));
                }
            }
        }
        result
    }

    pub fn precompute_comb(&self, base: &QFI, maxbits: usize, blocks: usize) -> FixedBaseComb {
        let block_len = maxbits.div_ceil(blocks);
        let mut pj = Vec::with_capacity(blocks);
        let mut cur = base.clone();
        pj.push(cur.clone());
        for _ in 1..blocks {
            for _ in 0..block_len {
                cur = self.square(&cur);
            }
            pj.push(cur.clone());
        }
        let mut table = vec![self.identity(); 1 << blocks];
        for i in 1..(1usize << blocks) {
            let j = i.trailing_zeros() as usize;
            table[i] = self.compose(&table[i ^ (1 << j)], &pj[j]);
        }
        FixedBaseComb {
            blocks,
            block_len,
            table,
        }
    }

    pub fn exp_comb(&self, comb: &FixedBaseComb, e: &Mpz) -> QFI {
        debug_assert!(
            e.nbits() <= comb.max_bits(),
            "exp_comb: exponent has {} bits but the comb covers only {}; use exp() for unbounded exponents",
            e.nbits(),
            comb.max_bits()
        );
        if e.sgn() <= 0 {
            return self.identity();
        }
        let mut result = self.identity();
        for k in (0..comb.block_len).rev() {
            result = self.square(&result);
            let mut idx = 0usize;
            for j in 0..comb.blocks {
                let pos = (j * comb.block_len + k) as u32;
                if e.get_bit(pos) {
                    idx |= 1 << j;
                }
            }
            if idx != 0 {
                result = self.compose(&result, &comb.table[idx]);
            }
        }
        result
    }

    pub fn multiexp(&self, bases: &[impl Borrow<QFI>], exps: &[Mpz]) -> QFI {
        assert_eq!(
            bases.len(),
            exps.len(),
            "multiexp: bases and exps must have equal length"
        );
        let mut maxbits = 0usize;
        for e in exps.iter() {
            if !e.is_zero() {
                maxbits = maxbits.max(e.nbits());
            }
        }
        if maxbits == 0 {
            return self.identity();
        }
        let w = naf_width(maxbits);
        let table_len = 1usize << (w - 2);

        let mut tables: Vec<Vec<QFI>> = Vec::with_capacity(bases.len());
        let mut nafs: Vec<Vec<i32>> = Vec::with_capacity(bases.len());
        let mut maxlen = 0usize;
        for (b, e) in bases.iter().zip(exps.iter()) {
            let b = b.borrow();
            if e.is_zero() {
                continue;
            }
            let (base, exp) = if e.sgn() < 0 {
                (self.inverse(b), e.neg())
            } else {
                ((*b).clone(), e.clone())
            };
            let base_sq = self.square(&base);
            let mut odds = Vec::with_capacity(table_len);
            odds.push(base);
            for _ in 1..table_len {
                odds.push(self.compose(odds.last().unwrap(), &base_sq));
            }
            let naf = wnaf(&exp, w);
            maxlen = maxlen.max(naf.len());
            tables.push(odds);
            nafs.push(naf);
        }

        let mut result = self.identity();
        for pos in (0..maxlen).rev() {
            result = self.square(&result);
            for (odds, naf) in tables.iter().zip(nafs.iter()) {
                let d = naf.get(pos).copied().unwrap_or(0);
                if d != 0 {
                    let idx = (d.unsigned_abs() as usize - 1) / 2;
                    if d > 0 {
                        result = self.compose(&result, &odds[idx]);
                    } else {
                        result = self.compose(&result, &self.inverse(&odds[idx]));
                    }
                }
            }
        }
        result
    }
}

fn wnaf(e: &Mpz, w: u32) -> Vec<i32> {
    debug_assert!(w >= 2 && e.sgn() >= 0);
    let two_w = 1i64 << w;
    let half = 1i64 << (w - 1);
    let mut digits = Vec::with_capacity(e.nbits() + 1);
    let mut k = e.clone();
    while k.sgn() > 0 {
        if k.is_odd() {
            let mut r = 0i64;
            for i in 0..w {
                if k.get_bit(i) {
                    r |= 1i64 << i;
                }
            }
            let d = if r >= half { r - two_w } else { r };
            k = if d >= 0 {
                &k - &Mpz::from(d as u64)
            } else {
                &k + &Mpz::from((-d) as u64)
            };
            digits.push(d as i32);
        } else {
            digits.push(0);
        }
        k = k.fdiv_2exp(1);
    }
    digits
}

fn naf_width(nbits: usize) -> u32 {
    match nbits {
        0..=160 => 4,
        161..=448 => 5,
        449..=1024 => 6,
        _ => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cg_163() -> ClassGroup {
        ClassGroup::new(Mpz::from(-163i64))
    }

    #[test]
    fn identity_is_reduced_principal() {
        let cg = cg_163();
        let id = cg.identity();
        assert_eq!(id.discriminant(), Mpz::from(-163i64));
        assert!(id.is_principal());
        assert_eq!(cg.reduced(&id), id);
    }

    #[test]
    fn reduce_makes_valid_reduced_form() {
        let cg = ClassGroup::new(Mpz::from(-2003i64));
        let mut f = QFI::from_abc(Mpz::from(9u64), Mpz::from(7u64), Mpz::new());
        f.c = (&(&f.b * &f.b) - cg.discriminant()).divexact(&f.a.mul_2exp(2));
        let d_before = f.discriminant();
        cg.reduce(&mut f);
        assert_eq!(f.discriminant(), d_before);
        assert!(f.b.abs() <= f.a);
        assert!(f.a <= f.c);
    }

    #[test]
    fn prime_form_has_right_discriminant() {
        let cg = ClassGroup::new(Mpz::from(-23i64));
        let f2 = cg.prime_form(&Mpz::from(2u64));
        assert_eq!(f2.discriminant(), Mpz::from(-23i64));
        assert_eq!(*f2.a(), Mpz::from(2u64));
    }

    fn cg_large() -> ClassGroup {
        let d = Mpz::from_str_auto("-0xb503b3a4f1e2d6c8a7f9e1d3c5b7a90123456789abcdef13").unwrap();
        let r = d.modulo(&Mpz::from(4u64));
        let d = &d - &r + &Mpz::from(1u64);
        ClassGroup::new(d)
    }

    #[test]
    fn compose_identity_and_inverse() {
        let cg = cg_large();
        let id = cg.identity();
        let f = cg.prime_form(&cg.smallest_split_prime());
        assert_eq!(cg.compose(&id, &f), f);
        assert_eq!(cg.compose(&f, &id), f);
        let inv = cg.inverse(&f);
        assert_eq!(cg.compose(&f, &inv), id);
    }

    #[test]
    fn square_equals_self_compose() {
        let cg = cg_large();
        let f = cg.prime_form(&cg.smallest_split_prime());
        assert_eq!(cg.square(&f), cg.compose(&f, &f));
    }

    #[test]
    fn associativity() {
        let cg = cg_large();
        let f = cg.prime_form(&cg.smallest_split_prime());
        let g = cg.square(&f);
        let h = cg.compose(&g, &f);
        let left = cg.compose(&cg.compose(&f, &g), &h);
        let right = cg.compose(&f, &cg.compose(&g, &h));
        assert_eq!(left, right);
    }

    #[test]
    fn multiexp_matches_naive_product() {
        let cg = cg_large();
        let f = cg.prime_form(&cg.smallest_split_prime());
        let g = cg.square(&f);
        let h = cg.compose(&g, &f);
        let owned = [f.clone(), g.clone(), h.clone(), cg.compose(&h, &f)];
        let bases: Vec<&QFI> = owned.iter().collect();
        let exps = [
            Mpz::from(12345u64),
            Mpz::from(0u64),
            Mpz::from_str_auto("0x9abcdef0123456789abcdef0").unwrap(),
            Mpz::from(7u64).neg(),
        ];
        let got = cg.multiexp(&bases, &exps);
        let mut naive = cg.identity();
        for (b, e) in bases.iter().zip(exps.iter()) {
            naive = cg.compose(&naive, &cg.exp(b, e));
        }
        assert_eq!(got, naive);
    }

    #[test]
    #[ignore = "perf micro-benchmark for B1a; run with --ignored --nocapture"]
    fn multiexp_vs_naive_timing() {
        use std::time::Instant;
        let cg = cg_large();
        let base0 = cg.prime_form(&cg.smallest_split_prime());
        const ITERS: u32 = 30;
        for n in [5usize, 11, 20] {
            let mut owned = Vec::with_capacity(n);
            let mut cur = base0.clone();
            for _ in 0..n {
                cur = cg.compose(&cur, &base0);
                owned.push(cur.clone());
            }
            let bases: Vec<&QFI> = owned.iter().collect();
            let exps: Vec<Mpz> = (0..n)
                .map(|i| {
                    Mpz::from((i as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)).mul_2exp(192)
                })
                .collect();

            let t0 = Instant::now();
            for _ in 0..ITERS {
                let _ = cg.multiexp(&bases, &exps);
            }
            let t_multi = t0.elapsed() / ITERS;

            let t1 = Instant::now();
            for _ in 0..ITERS {
                let mut r = cg.identity();
                for (b, e) in bases.iter().zip(exps.iter()) {
                    r = cg.compose(&r, &cg.exp(b, e));
                }
            }
            let t_naive = t1.elapsed() / ITERS;

            println!(
                "B1a multiexp n={n:>2}: naive={t_naive:>10.3?}  multiexp={t_multi:>10.3?}  speedup={:.2}x",
                t_naive.as_secs_f64() / t_multi.as_secs_f64()
            );
        }
    }

    #[test]
    fn law_of_exponents() {
        let cg = cg_large();
        let f = cg.prime_form(&cg.smallest_split_prime());
        let a = Mpz::from(37u64);
        let b = Mpz::from(91u64);
        let lhs = cg.compose(&cg.exp(&f, &a), &cg.exp(&f, &b));
        let rhs = cg.exp(&f, &(&a + &b));
        assert_eq!(lhs, rhs);
        assert_eq!(cg.exp(&f, &Mpz::from(-1i64)), cg.inverse(&f));
        assert_eq!(cg.exp(&f, &Mpz::new()), cg.identity());
    }

    #[test]
    fn nupow_matches_exp_and_compose() {
        let cg = cg_large();
        let f = cg.prime_form(&cg.smallest_split_prime());
        for n in [-37i64, -7, -1, 0, 1, 5, 64, 1000] {
            assert_eq!(
                cg.nupow(&f, &Mpz::from(n)),
                cg.exp(&f, &Mpz::from(n)),
                "nupow≠exp at {n}"
            );
        }
        let mut acc = cg.identity();
        for k in 0..12u64 {
            assert_eq!(cg.nupow(&f, &Mpz::from(k)), acc, "nupow(f,{k}) wrong");
            acc = cg.compose(&acc, &f);
        }
    }

    #[test]
    fn neg_in_place_is_reduced_inverse() {
        let cg = cg_large();
        let f = cg.prime_form(&cg.smallest_split_prime());
        let mut powers = vec![f.clone()];
        for _ in 0..12 {
            powers.push(cg.compose(powers.last().unwrap(), &f));
        }
        for p in &powers {
            let mut g = p.clone();
            g.neg();
            assert_eq!(g, cg.inverse(p), "neg ≠ reduced inverse");
            assert_eq!(cg.compose(p, &g), cg.identity(), "p · neg(p) ≠ e");
            let mut gg = g.clone();
            gg.neg();
            assert_eq!(gg, *p, "neg∘neg ≠ id");
        }
        let mut id = cg.identity();
        id.neg();
        assert_eq!(id, cg.identity());
    }

    #[test]
    fn lift_and_to_maximal_order_roundtrip() {
        let delta_k = Mpz::from(-23i64);
        let m = Mpz::from(5u64);
        let delta = &(&m * &m) * &delta_k;
        let clk = ClassGroup::new(delta_k.clone());
        let cl = ClassGroup::new(delta.clone());
        let base = clk.prime_form(&clk.smallest_split_prime());
        let mut w = clk.identity();
        for _ in 0..6 {
            let mut down = w.lift(&m);
            assert_eq!(down.discriminant(), delta, "lift discriminant");
            cl.reduce(&mut down);
            assert_eq!(down.discriminant(), delta, "reduced lift discriminant");
            let mut up = down.to_maximal_order(&m, &delta_k);
            assert_eq!(up.discriminant(), delta_k, "to_maximal_order discriminant");
            clk.reduce(&mut up);
            assert_eq!(up, w, "π∘lift ≠ id on Cl(Δ_K)");
            w = clk.compose(&w, &base);
        }
    }

    #[test]
    fn nucomp_matches_plain_composition() {
        let cg = cg_large();
        let f = cg.prime_form(&cg.smallest_split_prime());
        let mut powers = vec![f.clone()];
        for _ in 1..12 {
            powers.push(cg.compose(powers.last().unwrap(), &f));
        }
        for (i, a) in powers.iter().enumerate() {
            for b in powers.iter().skip(i + 1) {
                assert_eq!(
                    cg.compose(a, b),
                    cg.compose_dirichlet(a, b),
                    "NUCOMP fast path disagrees with Dirichlet composition"
                );
            }
        }
    }

    #[test]
    fn nudupl_matches_plain_square() {
        let cg = cg_large();
        let f = cg.prime_form(&cg.smallest_split_prime());
        let mut g = f.clone();
        for _ in 0..15 {
            assert_eq!(cg.square(&g), cg.compose_dirichlet(&g, &g));
            g = cg.compose(&g, &f);
        }
    }

    #[test]
    #[ignore]
    fn profile_square() {
        use std::time::Instant;
        let d = Mpz::from(1u64).mul_2exp(1796).add_ui(3).neg();
        let cg = ClassGroup::new(d);
        let base = cg.prime_form(&cg.smallest_split_prime());
        let f = cg.exp(&base, &Mpz::from(0x9e3779b97f4a7c15u64));
        let n = 4000;

        let (a, b, c) = (&f.a, &f.b, &f.c);
        let binv = b.invert(a).unwrap();
        let mu = (c * &binv).modulo(a);
        let unred = QFI::from_abc(
            a * a,
            b - &(&mu * a).mul_2exp(1),
            &(&mu * &mu) - &(&(b * &mu) - c).divexact(a),
        );

        let t = Instant::now();
        for _ in 0..n {
            let _ = f.b.invert(&f.a).unwrap();
        }
        let inv = t.elapsed().as_secs_f64() * 1e6 / n as f64;

        let t = Instant::now();
        for _ in 0..n {
            let mut g = unred.clone();
            cg.reduce(&mut g);
        }
        let red = t.elapsed().as_secs_f64() * 1e6 / n as f64;

        let t = Instant::now();
        for _ in 0..n {
            let _ = cg.square(&f);
        }
        let sq = t.elapsed().as_secs_f64() * 1e6 / n as f64;

        println!(
            "\n  |Δ|={} |a|={} bits | invert {inv:.2}µs | reduce {red:.2}µs | square {sq:.2}µs",
            cg.discriminant().abs().nbits(),
            f.a().nbits()
        );
    }

    #[test]
    #[ignore]
    fn profile_ops() {
        use std::time::Instant;
        let d = Mpz::from(1u64).mul_2exp(1796).add_ui(3).neg();
        let cg = ClassGroup::new(d);
        let base = cg.prime_form(&cg.smallest_split_prime());
        let f = cg.exp(&base, &Mpz::from(0x9e3779b97f4a7c15u64));
        let g = cg.exp(&base, &Mpz::from(0xbf58476d1ce4e5b9u64));
        let n = 4000;

        let time = |op: &dyn Fn()| {
            let t = Instant::now();
            for _ in 0..n {
                op();
            }
            t.elapsed().as_secs_f64() * 1e6 / n as f64
        };
        let dir = time(&|| {
            cg.compose_dirichlet(&f, &g);
        });
        let comp = time(&|| {
            cg.compose(&f, &g);
        });
        let sq = time(&|| {
            cg.square(&f);
        });

        let rho = |op: &dyn Fn()| {
            op();
            LAST_REDUCE_STEPS.with(|s| s.get())
        };
        let dir_rho = rho(&|| {
            cg.compose_dirichlet(&f, &g);
        });
        let comp_rho = rho(&|| {
            cg.compose(&f, &g);
        });
        let sq_rho = rho(&|| {
            cg.square(&f);
        });
        println!(
            "\n  |Δ|={}b |a|={}b\n  dirichlet {dir:.2}µs ({dir_rho}ρ) | compose(NUCOMP) {comp:.2}µs ({comp_rho}ρ) | square(NUDUPL) {sq:.2}µs ({sq_rho}ρ)",
            cg.discriminant().abs().nbits(),
            f.a().nbits()
        );
    }

    #[test]
    #[ignore]
    fn profile_square_breakdown() {
        use std::time::Instant;
        let d = Mpz::from(1u64).mul_2exp(1796).add_ui(3).neg();
        let cg = ClassGroup::new(d);
        let base = cg.prime_form(&cg.smallest_split_prime());
        let f = cg.exp(&base, &Mpz::from(0x9e3779b97f4a7c15u64));
        let (a, b, c) = (&f.a, &f.b, &f.c);
        let n = 4000;
        let bench = |label: &str, op: &dyn Fn()| {
            for _ in 0..200 {
                op();
            }
            let mut best = f64::MAX;
            for _ in 0..9 {
                let t = Instant::now();
                for _ in 0..n {
                    op();
                }
                best = best.min(t.elapsed().as_secs_f64() * 1e6 / n as f64);
            }
            println!("  {label:28} {best:7.3} µs (min/9)");
            best
        };

        let total = bench("square (NUDUPL, full)", &|| {
            cg.square(&f);
        });
        bench("  gcdext(b,a)", &|| {
            let _ = b.gcdext(a);
        });
        bench("  invert(b mod a)", &|| {
            let _ = b.invert(a);
        });
        bench("  a*a (full §3a A)", &|| {
            let _ = a * a;
        });
        let setup = bench("  setup (gcdext+divs+bx0)", &|| {
            let (gg, u, _v) = b.gcdext(a);
            let by = a.divexact(&gg);
            let _dy = b.divexact(&gg);
            let _bx0 = (&u * c).modulo(&by);
        });
        let (gg, u, _v) = b.gcdext(a);
        let by0 = a.divexact(&gg);
        let bx0 = (&u * c).modulo(&by0);
        use std::sync::atomic::Ordering as AO;
        super::super::hgcd::PR_CALLS.store(0, AO::Relaxed);
        super::super::hgcd::PR_BATCHES.store(0, AO::Relaxed);
        super::super::hgcd::PR_STEPS0.store(0, AO::Relaxed);
        let partial = bench("  partial_reduce_lehmer", &|| {
            let mut bxi = bx0.0.clone();
            let mut byi = by0.0.clone();
            let _ = super::super::hgcd::partial_reduce_lehmer(&mut bxi, &mut byi, &cg.l_thresh.0);
        });
        let calls = super::super::hgcd::PR_CALLS.load(AO::Relaxed);
        println!(
            "    partial: {:.1} batches/call, {:.2} steps0/call ({} calls incl warmup)",
            super::super::hgcd::PR_BATCHES.load(AO::Relaxed) as f64 / calls as f64,
            super::super::hgcd::PR_STEPS0.load(AO::Relaxed) as f64 / calls as f64,
            calls
        );
        println!(
            "  => setup {setup:.2} | partial {partial:.2} | assembly+reduce ≈ {:.2} | total {total:.2}",
            total - setup - partial
        );
    }

    #[test]
    #[ignore]
    fn profile_square_chain() {
        use std::time::Instant;
        let d = Mpz::from(1u64).mul_2exp(1796).add_ui(3).neg();
        let cg = ClassGroup::new(d);
        let base = cg.prime_form(&cg.smallest_split_prime());
        let mut g = cg.exp(&base, &Mpz::from(0x9e3779b97f4a7c15u64));
        for _ in 0..500 {
            g = cg.square(&g);
        }
        SQ_CALLS.with(|s| s.set(0));
        SQ_SLOW.with(|s| s.set(0));
        let n = 4000;
        let mut us = f64::MAX;
        for _ in 0..9 {
            let t = Instant::now();
            for _ in 0..n {
                g = cg.square(&g);
            }
            us = us.min(t.elapsed().as_secs_f64() * 1e6 / n as f64);
            std::hint::black_box(&g);
        }
        let calls = SQ_CALLS.with(|s| s.get());
        let slow = SQ_SLOW.with(|s| s.get());
        println!(
            "\n  chain square: {us:.3} µs/op | §3a fallback {slow}/{calls} ({:.2}%)",
            100.0 * slow as f64 / calls as f64
        );
    }

    #[test]
    fn square_matches_dirichlet_over_chain() {
        let d = Mpz::from(1u64).mul_2exp(1796).add_ui(3).neg();
        let cg = ClassGroup::new(d);
        let base = cg.prime_form(&cg.smallest_split_prime());
        let mut g = cg.exp(&base, &Mpz::from(0x9e3779b97f4a7c15u64));
        let mut gcd_gt1 = 0;
        for i in 0..400 {
            assert_eq!(
                cg.square(&g),
                cg.compose_dirichlet(&g, &g),
                "square≠dirichlet at step {i}"
            );
            if !g.a().gcd(g.b()).is_one() {
                gcd_gt1 += 1;
            }
            g = cg.square(&g);
        }
        assert!(
            gcd_gt1 > 0,
            "chain visited no gcd(a,b)>1 forms — general-G path untested"
        );
    }

    #[test]
    fn nucomp_fast_path_fires_and_is_near_reduced() {
        let d = Mpz::from(1u64).mul_2exp(1796).add_ui(3).neg();
        let cg = ClassGroup::new(d);
        let base = cg.prime_form(&cg.smallest_split_prime());
        let f = cg.exp(&base, &Mpz::from(0x9e3779b97f4a7c15u64));
        let g = cg.exp(&base, &Mpz::from(0xbf58476d1ce4e5b9u64));

        assert_eq!(cg.compose(&f, &g), cg.compose_dirichlet(&f, &g));
        NUCOMP_FINISH_OK.with(|s| s.set(0));
        let _ = cg.compose(&f, &g);
        assert_eq!(
            NUCOMP_FINISH_OK.with(|s| s.get()),
            1,
            "compose did not fire NUCOMP"
        );
        let comp_rho = LAST_REDUCE_STEPS.with(|s| s.get());
        assert!(
            comp_rho < 20,
            "compose form not near-reduced: {comp_rho} ρ steps"
        );

        assert_eq!(cg.square(&f), cg.compose_dirichlet(&f, &f));
        NUCOMP_FINISH_OK.with(|s| s.set(0));
        let _ = cg.square(&f);
        assert_eq!(
            NUCOMP_FINISH_OK.with(|s| s.get()),
            1,
            "square did not fire NUDUPL"
        );
        let sq_rho = LAST_REDUCE_STEPS.with(|s| s.get());
        assert!(
            sq_rho < 20,
            "square form not near-reduced: {sq_rho} ρ steps"
        );
    }

    #[test]
    fn nucomp_matches_plain_large() {
        let d = Mpz::from(1u64).mul_2exp(6000).add_ui(3).neg();
        let cg = ClassGroup::new(d);
        let f = cg.prime_form(&cg.smallest_split_prime());
        let mut powers = vec![f.clone()];
        for _ in 1..6 {
            powers.push(cg.compose(powers.last().unwrap(), &f));
        }
        for (i, a) in powers.iter().enumerate() {
            for b in powers.iter().skip(i + 1) {
                assert_eq!(
                    cg.compose(a, b),
                    cg.compose_dirichlet(a, b),
                    "NUCOMP ≠ Dirichlet at large Δ"
                );
            }
        }
    }

    #[test]
    fn small_group_z3_disc_minus_23() {
        let cg = ClassGroup::new(Mpz::from(-23i64));
        let id = cg.identity();
        let f2 = cg.prime_form(&Mpz::from(2u64));
        assert_ne!(f2, id);
        let f2sq = cg.square(&f2);
        assert_ne!(f2sq, id);
        assert_eq!(f2sq, cg.inverse(&f2));
        assert_eq!(cg.exp(&f2, &Mpz::from(3u64)), id);
    }
}
