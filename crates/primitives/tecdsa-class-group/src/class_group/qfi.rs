//! Binary quadratic forms and ideal-class-group arithmetic.
//!
//! A [`QFI`] is a primitive positive-definite integral binary quadratic form
//! `(a, b, c)` with discriminant `Δ = b² − 4ac < 0`. We keep forms *reduced*
//! (`|b| ≤ a ≤ c`, with `b ≥ 0` when `|b| = a` or `a = c`); a reduced form is
//! the canonical representative of its ideal class, so structural equality of
//! reduced forms is class equality.
//!
//! [`ClassGroup`] bundles a discriminant with the operations of its ideal class
//! group (composition, squaring, exponentiation, reduction, prime forms).

use core::{cell::RefCell, cmp::Ordering, fmt};

use gmp_mpfr_sys::gmp;
use rug::Integer;

use super::{mpz::Mpz, nt::sqrt_mod_prime};

thread_local! {
    /// Reused scratch for the in-place `mpz_*` reduction (one per thread).
    static REDUCE_SCRATCH: RefCell<ReduceScratch> = RefCell::new(ReduceScratch::default());
}

#[cfg(test)]
thread_local! {
    /// Number of ρ iterations performed by the most recent `reduce` call
    /// (instrumentation: lets tests check how near-reduced an input form was).
    static LAST_REDUCE_STEPS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// Count of `nucomp_finish` calls that produced a form (did not fall back).
    static NUCOMP_FINISH_OK: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// `square` call count and how many missed the `nudupl_fast` path.
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

/// Solve `a·x ≡ b (mod m)` for `m > 0`. Returns `(x0, m')` such that the
/// solution set is `x ≡ x0 (mod m')` with `x0 ∈ [0, m')`, or `None` if there
/// is no solution.
fn solve_lc(a: &Mpz, b: &Mpz, m: &Mpz) -> Option<(Mpz, Mpz)> {
    // g = u·a + v·m  ⇒  u·a ≡ g (mod m)
    let (g, u, _v) = a.gcdext(m);
    let (q, r) = b.fdiv_qr(&g);
    if !r.is_zero() {
        return None; // g ∤ b
    }
    let modulus = m.divexact(&g);
    let x0 = (&q * &u).modulo(&modulus);
    Some((x0, modulus))
}

/// A reduced (unless stated otherwise) binary quadratic form `(a, b, c)`.
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

    /// The discriminant `b² − 4ac`.
    pub fn discriminant(&self) -> Mpz {
        &(&self.b * &self.b) - &(&self.a * &self.c).mul_2exp(2)
    }

    /// Whether this is the principal form (the class-group identity).
    pub fn is_principal(&self) -> bool {
        self.a.is_one()
    }

    /// Negate the class **in place**: `(a, b, c) ↦ (a, −b, c)` (the inverse).
    ///
    /// For a reduced form this yields the *reduced* inverse directly: when
    /// `0 < |b| < a < c` flipping `b`’s sign keeps it reduced, while at the
    /// `b = a` or `a = c` boundary the canonical representative has `b ≥ 0` and
    /// the class equals its own inverse, so `b` is left unchanged. (Matches
    /// [`ClassGroup::inverse`] for reduced inputs, but mutates in place with no
    /// allocation or reduction.)
    pub fn neg(&mut self) {
        use rug::ops::NegAssign;
        if self.a != self.b && self.a != self.c {
            self.b.0.neg_assign();
        }
    }

    /// An equivalent form (same discriminant) whose first coefficient is coprime
    /// to `l` (HJPT98 Algorithm 1 / FindIdealPrimeTo). Because the form is
    /// primitive (`gcd(a, b, c) = 1`), one of `a`, `c`, `a + b + c` is always
    /// coprime to `l`; the corresponding `SL₂(ℤ)`-equivalent `(a′, b′, c′)` is
    /// returned.
    fn primitive_coprime_to(&self, l: &Mpz) -> (Mpz, Mpz, Mpz) {
        let one = Mpz::from(1u64);
        if self.a.gcd(l) == one {
            (self.a.clone(), self.b.clone(), self.c.clone())
        } else if self.c.gcd(l) == one {
            (self.c.clone(), self.b.neg(), self.a.clone()) // (c, -b, a)
        } else {
            let abc = &(&self.a + &self.b) + &self.c;
            let nb = &self.b.neg() - &self.a.mul_2exp(1); // -b - 2a
            (abc, nb, self.a.clone())
        }
    }

    /// Lift this form (of discriminant `Δ`) into the order of conductor `l`:
    /// take an equivalent representative with `a` coprime to `l` and scale to
    /// `(a, l·b, l²·c)`, of discriminant `l²·Δ` (the ideal "go-down" map of
    /// HJPT98/CL09). The result is **not** reduced — reduce it in the target
    /// [`ClassGroup`].
    pub(crate) fn lift(&self, l: &Mpz) -> QFI {
        let (a, b, c) = self.primitive_coprime_to(l);
        let l2 = l * l;
        QFI::from_abc(a, &b * l, &c * &l2)
    }

    /// Map this form (of discriminant `l²·Δ_K`, in the order of conductor `l`)
    /// to the maximal order of discriminant `Δ_K` — the go-up surjection `π`
    /// (HJPT98 Alg. 3 / CL09 Alg. 2). Takes an `a` coprime to `l`, sets
    /// `b′ ≡ b·l⁻¹ (mod 2a)` centered into `(−a, a]`, and
    /// `c′ = (b′² − Δ_K)/(4a)`. The result is **not** reduced.
    pub(crate) fn to_maximal_order(&self, l: &Mpz, delta_k: &Mpz) -> QFI {
        let (a, b, _c) = self.primitive_coprime_to(l); // gcd(a, l) = 1
                                                       // 1 = u·l + v·a  ⇒  b′ = b·l⁻¹ ≡ b·u + a·v (mod 2a).
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
            let mag = x.to_bytes_be(); // |x|, big-endian
            buf.push((x.sgn() < 0) as u8); // sign byte
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
    /// The largest exponent bit-length this table exponentiates correctly.                                                             
    /// [`ClassGroup::exp_comb`] silently ignores exponent bits at or above this,                                                       
    /// so exponents that may exceed it (e.g. an unbounded Schnorr response) must
    /// go through [`ClassGroup::exp`] instead.
    pub fn max_bits(&self) -> usize {
        self.blocks * self.block_len
    }
}

/// The ideal class group of a negative discriminant `Δ ≡ 0 or 1 (mod 4)`.
#[derive(Clone, Debug)]
pub struct ClassGroup {
    disc: Mpz,
    /// `⌊(|Δ|/4)^(1/4)⌋`, the partial-reduction threshold used by NUCOMP.
    l_thresh: Mpz,
}

/// A fixed-base comb precomputation table for fast exponentiation of one base.
#[derive(Clone, Debug)]
pub struct FixedBaseComb {
    blocks: usize,
    block_len: usize,
    table: Vec<QFI>,
}

impl ClassGroup {
    /// Create the class group of discriminant `disc` (must be `< 0` and
    /// `≡ 0 or 1 (mod 4)`).
    pub fn new(disc: Mpz) -> ClassGroup {
        debug_assert!(disc.sgn() < 0, "discriminant must be negative");
        let abs = disc.abs();
        // L = floor((|Δ|/4)^(1/4)) = floor(|Δ|^(1/4) / sqrt(2))
        let l_thresh = abs.fdiv_2exp(2).root(4);
        ClassGroup { disc, l_thresh }
    }

    pub fn discriminant(&self) -> &Mpz {
        &self.disc
    }

    /// The principal form (identity element).
    pub fn identity(&self) -> QFI {
        let one = Mpz::from(1u64);
        if self.disc.modulo(&Mpz::from(4u64)) == 1u64 {
            // (1, 1, (1-Δ)/4)
            let c = (&one - &self.disc).divexact(&Mpz::from(4u64));
            QFI::from_abc(one.clone(), one, c)
        } else {
            // Δ ≡ 0 (mod 4): (1, 0, -Δ/4)
            let c = self.disc.neg().divexact(&Mpz::from(4u64));
            QFI::from_abc(one, Mpz::new(), c)
        }
    }

    /// Reduce a form in place (Long §5.2.1: normalize then ρ-iterate).
    ///
    /// Implemented with reused `rug` scratch integers and in-place operations,
    /// so the (hundreds of) ρ steps allocate no per-step heap memory.
    pub fn reduce(&self, f: &mut QFI) {
        // Raw `mpz_*` in-place arithmetic with thread-reused scratch (the
        // reference's approach): the ρ loop allocates nothing and avoids the
        // per-operation dispatch of the safe wrappers. The scratch and the
        // form's three coefficients are all distinct GMP integers (no aliasing).
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

                // normalize: r = ⌊(a-b)/2a⌋ ; c += r·(b + a·r) ; b += 2a·r
                gmp::mpz_mul_2exp(two, a, 1); // 2a
                gmp::mpz_sub(t, a, b); // a - b
                gmp::mpz_fdiv_q(q, t, two); // q = r
                gmp::mpz_mul(t, a, q); // a·r
                gmp::mpz_add(t, t, b); // b + a·r
                gmp::mpz_mul(t, t, q); // r·(b + a·r)
                gmp::mpz_add(c, c, t); // c += …
                gmp::mpz_mul(t, two, q); // 2a·r
                gmp::mpz_add(b, b, t); // b += …

                // ρ loop while a > c
                #[cfg(test)]
                let mut steps = 0u32;
                while gmp::mpz_cmp(a, c) > 0 {
                    #[cfg(test)]
                    {
                        steps += 1;
                    }
                    gmp::mpz_mul_2exp(two, c, 1); // 2c
                    gmp::mpz_add(t, c, b); // c + b
                    gmp::mpz_fdiv_q(q, t, two); // s = ⌊(c+b)/2c⌋
                    gmp::mpz_mul(sc, q, c); // s·c
                    gmp::mpz_sub(nb, sc, b); // sc - b
                    gmp::mpz_mul(nb, nb, q); // s·(sc - b)
                    gmp::mpz_add(nb, nb, a); // new_c = a + …
                    gmp::mpz_mul_2exp(t, sc, 1); // 2sc
                    gmp::mpz_sub(t, t, b); // new_b = 2sc - b
                                           // (a, b, c) ← (old c, new_b, new_c) via O(1) buffer swaps
                    gmp::mpz_swap(a, c); // a = old c
                    gmp::mpz_swap(b, t); // b = new_b
                    gmp::mpz_swap(c, nb); // c = new_c
                }
                // reduced tie-break: if a == c then b ≥ 0  (size < 0 ⇔ negative)
                if gmp::mpz_cmp(a, c) == 0 && (*b).size < 0 {
                    gmp::mpz_neg(b, b);
                }
                #[cfg(test)]
                LAST_REDUCE_STEPS.with(|s| s.set(steps));
            }
        });
    }

    /// Return a reduced copy.
    pub fn reduced(&self, f: &QFI) -> QFI {
        let mut g = f.clone();
        self.reduce(&mut g);
        g
    }

    /// Inverse of a class: `(a, b, c) ↦ (a, -b, c)` (then reduced).
    pub fn inverse(&self, f: &QFI) -> QFI {
        let mut g = QFI::from_abc(f.a.clone(), f.b.neg(), f.c.clone());
        self.reduce(&mut g);
        g
    }

    /// The smallest prime `l` that splits (Kronecker `(Δ|l) = 1`), so that a
    /// non-trivial prime form of norm `l` exists.
    pub fn smallest_split_prime(&self) -> Mpz {
        let mut l = Mpz::from(2u64);
        loop {
            if self.disc.kronecker(&l) == 1 {
                return l;
            }
            l = l.next_prime();
        }
    }

    /// The reduced form of the prime ideal above the prime `l`
    /// (requires `(Δ | l) ≠ -1`, i.e. `l` splits or ramifies).
    pub fn prime_form(&self, l: &Mpz) -> QFI {
        let (b, c);
        if *l == 2u64 {
            // requires Δ ≡ 1 (mod 8)
            b = Mpz::from(1u64);
            c = (&Mpz::from(1u64) - &self.disc).divexact(&Mpz::from(8u64));
        } else {
            let dl = self.disc.modulo(l);
            let r = sqrt_mod_prime(&dl, l).expect("prime_form: l does not split the discriminant");
            // Δ is odd ⇒ b must be odd; r²≡Δ (mod l), pick odd representative.
            let bb = if r.is_odd() { r } else { &r + l };
            let four_l = l.mul_2exp(2);
            c = (&(&bb * &bb) - &self.disc).divexact(&four_l);
            b = bb;
        }
        let mut f = QFI::from_abc(l.clone(), b, c);
        self.reduce(&mut f);
        f
    }

    /// General Dirichlet composition (van der Poorten / Long §6.1.1): correct
    /// for any discriminant, including the case `f == g` (squaring). The
    /// composite is then fully reduced. This is the correctness baseline and the
    /// fallback for the NUCOMP fast path ([`compose`](Self::compose)); it forms
    /// the full `|Δ|`-sized product and reduces it, so it is ~3× slower than
    /// NUCOMP at CL sizes — used directly only in tests and degenerate cases.
    pub(crate) fn compose_dirichlet(&self, f1: &QFI, f2: &QFI) -> QFI {
        let (a, b, c) = (&f1.a, &f1.b, &f1.c);
        let (al, be, ga) = (&f2.a, &f2.b, &f2.c);
        let _ = ga; // c2 is not needed by this formulation

        // 1. g = (b+β)/2, h = (β−b)/2, w = gcd(a, α, g)
        let g = (b + be).fdiv_2exp(1);
        let h = (be - b).fdiv_2exp(1);
        let w = a.gcd(al).gcd(&g);

        // 2. j = w, s = a/w, t = α/w, u = g/w
        let j = w.clone();
        let s = a.divexact(&w);
        let t = al.divexact(&w);
        let u = g.divexact(&w);

        // 3. solve (t·u)·k ≡ h·u + s·c  (mod s·t)
        let st = &s * &t;
        let tu = &t * &u;
        let rhs3 = &(&h * &u) + &(&s * c);
        let (mu, nu) = solve_lc(&tu, &rhs3, &st).expect("compose: congruence (3) unsolvable");

        // 4. solve (t·ν)·n ≡ h − t·μ  (mod s)
        let rhs4 = &h - &(&t * &mu);
        let coef4 = &t * &nu;
        let (lambda, _) = solve_lc(&coef4, &rhs4, &s).expect("compose: congruence (4) unsolvable");

        // 5. k, l, m
        let k = &mu + &(&nu * &lambda);
        let l = (&(&k * &t) - &h).divexact(&s);
        let m = (&(&(&tu * &k) - &(&h * &u)) - &(c * &s)).divexact(&st);

        // 6. A = s·t, B = j·u − (k·t + l·s), C = k·l − j·m
        let aa = st;
        let bb = &(&j * &u) - &(&(&k * &t) + &(&l * &s));
        let cc = &(&k * &l) - &(&j * &m);

        let mut f3 = QFI::from_abc(aa, bb, cc);
        self.reduce(&mut f3);
        f3
    }

    /// Compose two classes (returns a reduced form), via **NUCOMP** partial
    /// reduction (van der Poorten): the intermediate operands are kept near
    /// `|Δ|^{1/2}` by a Lehmer-accelerated partial extended Euclidean on the
    /// cofactor pair, and the assembled product form is already *near-reduced*
    /// (a handful of ρ steps, vs ~185 for the full Dirichlet product). At CL
    /// sizes this is ~3.7× faster than [`compose_dirichlet`](Self::compose_dirichlet),
    /// to which it falls back on the rare degenerate state.
    pub fn compose(&self, f1: &QFI, f2: &QFI) -> QFI {
        // Order so a1 >= a2.
        let (f1, f2) = if f1.a >= f2.a { (f1, f2) } else { (f2, f1) };
        let (a1, b1, c1) = (&f1.a, &f1.b, &f1.c);
        let (a2, b2, c2) = (&f2.a, &f2.b, &f2.c);

        let ss = (b1 + b2).fdiv_2exp(1); // (b1+b2)/2
        let m = (b2 - b1).fdiv_2exp(1); // (b2-b1)/2

        // F = gcd(a2, a1) = u·a2 + v·a1
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
            // Degenerate partial reduction; plain composition is correct.
            return self.compose_dirichlet(f1, f2);
        }
        self.nucomp_finish(&g, bx0, by, cy, dy, &m, c2, &ss)
            .unwrap_or_else(|| self.compose_dirichlet(f1, f2))
    }

    /// Square a class (returns a reduced form), via **NUDUPL** — the squaring
    /// specialisation of NUCOMP. Sets up the duplication directly from
    /// `gcd(a, b)` (one extended gcd) and assembles a near-reduced form via the
    /// shared partial-reduction tail; falls back to a §3a square + full
    /// reduction on the rare degenerate state. ~2.6× faster than §3a alone at
    /// CL sizes (the result is near-reduced, so the final reduction is short).
    pub fn square(&self, f: &QFI) -> QFI {
        #[cfg(test)]
        SQ_CALLS.with(|s| s.set(s.get() + 1));
        if let Some(sq) = self.nudupl(f) {
            return sq;
        }
        #[cfg(test)]
        SQ_SLOW.with(|s| s.set(s.get() + 1));
        // Fallback (degenerate states only): §3a square + full reduction, or
        // general composition if b is not invertible mod a.
        let (a, b, c) = (&f.a, &f.b, &f.c);
        let binv = match b.invert(a) {
            Some(x) => x,
            None => return self.compose_dirichlet(f, f),
        };
        let mu = (c * &binv).modulo(a);
        let aa = a * a; // A = a²
        let bb = b - &(&mu * a).mul_2exp(1); // B = b - 2aμ
        let cc = &(&mu * &mu) - &(&(b * &mu) - c).divexact(a); // C = μ² - (bμ-c)/a
        let mut sq = QFI::from_abc(aa, bb, cc);
        self.reduce(&mut sq);
        sq
    }

    /// NUDUPL — the squaring specialisation of NUCOMP, for **any** `G = gcd(a, b)`.
    ///
    /// Setup is one extended gcd `G = u·b + _·a` (handling `G = 1` and `G > 1`
    /// uniformly; `G > 1` arises for a non-negligible fraction of forms in a
    /// non-maximal order, so a fast path for it matters). Because `cy = By₀`
    /// for squaring, the assembly simplifies for every `G`: `cx = bx` and
    /// `cy2 = byr` are free (no division), and `ax·dy2 = dx·ay + b` is reused:
    ///
    /// ```text
    ///   By₀ = a/G ,  Dy = b/G ,  bx0 = (u·c) mod By₀
    ///   (bx, byr, x, y) ← partial-reduce (bx0, By₀)   (byr, y negated on odd parity)
    ///   ax = G·x ,  ay = G·y
    ///   dx  = (bx·Dy − c·x) / By₀
    ///   dy2 = (dx·ay + b) / ax
    ///   a₃ = byr² − ay·dy2 ,  c₃ = bx² − ax·dx ,  b₃ = 2·(dx·ay) + b − 2·bx·byr
    /// ```
    ///
    /// (Verified equal to the general `nucomp_finish` assembly over random
    /// trials.) Returns `None` on the rare degenerate states (then `square`
    /// falls back to a §3a square).
    fn nudupl(&self, f: &QFI) -> Option<QFI> {
        let (a, b, c) = (&f.a, &f.b, &f.c);
        // G = u·b + _·a = gcd(b, a).  By₀ = a/G, Dy = b/G.  (Always extended-gcd:
        // a modular inverse would be wasted work on the G>1 forms.)
        let (gg, u, _v) = b.gcdext(a);
        let by0 = a.divexact(&gg);
        if by0.is_one() {
            return None; // a = G ⇒ b = 0 or |b| = a; degenerate, fall back
        }
        let dy = b.divexact(&gg);
        let bx0 = (&u * c).modulo(&by0); // = c·b⁻¹ mod a when G = 1 (the §3a μ)

        // Partial extended-Euclidean reduction of (bx0, By₀) until bx ≈ L.
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
        // ax = G·x, ay = G·y (when G = 1 these are just x, y — avoid the mul).
        let (ax, ay) = if gg.is_one() {
            (x.clone(), y.clone())
        } else {
            (&gg * &x, &gg * &y)
        };

        // Assembly (m = 0). cx = bx, cy2 = byr are exact by construction (no
        // division). The only checked divisions are dx (÷ By₀) and dy2 (÷ ax);
        // a non-exact one ⇒ bail to the caller's §3a fallback. (Measured: a
        // raw-mpz reused-scratch rewrite of this assembly gives no speedup — only
        // ~10 ops, so allocation is negligible next to the multiplications.)
        let dx = (&(&bx * &dy) - &(c * &x)).divexact_checked(&by0)?;
        let dxa = &dx * &ay;
        let dy2 = (&dxa + b).divexact_checked(&ax)?;
        let a3 = &(&byr * &byr) - &(&ay * &dy2);
        let c3 = &(&bx * &bx) - &(&ax * &dx);
        // b₃ = ax·dy2 + ay·dx − (bx·cy2 + byr·cx) = 2·(dx·ay) + b − 2·bx·byr.
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

    /// Partial extended-Euclidean reduction of `(bx, by)` (`by > bx ≥ 0`) used by
    /// NUCOMP/NUDUPL: reduces in place to `bx ≤ L` and returns the cofactors
    /// `(y, x)` and the reduction parity. Word-batched (i64) Lehmer; the recursive
    /// `partial_reduce_hgcd` is reserved for huge operands. (GMP's `mpn_hgcd`/
    /// `mpn_hgcd2` were investigated as a driver here and are not faster at the CL
    /// operand size — see `hgcd_gmp` docs.)
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

    /// Shared NUCOMP/NUDUPL tail: partial Euclidean reduction of `(Bx, By)`,
    /// then assemble the (near-)reduced product and finish reduction.
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
        // Partial extended Euclidean on (bx, by) until bx <= L. Word-batched
        // schoolbook Lehmer is fastest in every practical range; recursive HGCD
        // is reachable only for enormous operands (see hgcd::NUCOMP_HGCD_DISPATCH_BITS).
        // `by0` (the *original*, pre-reduction By) is needed below as the modulus
        // for the cofactor relations; the partial reduction overwrites `byi`.
        let by_orig = by0.clone();
        let mut bxi = bx0.0;
        let mut byi = by0.0;
        let (yi, xi, z_odd) = self.partial_reduce(&mut bxi, &mut byi);
        // Degenerate (the pair shared a common factor); caller falls back.
        if bxi.cmp0() == Ordering::Equal {
            return None;
        }
        let bx = Mpz(bxi);
        let mut byr = Mpz(byi); // *reduced* By (R_{i-1}); used in the final assembly
        let x = Mpz(xi);
        let mut y = Mpz(yi);
        if z_odd {
            byr = byr.neg();
            y = y.neg();
        }
        if x.is_zero() {
            return None; // ax = g·x would be 0
        }
        let ax = g * &x;
        let ay = g * &y;
        // Recover the remaining coefficients. The cofactor identity guarantees
        // `bx ≡ x·bx0 (mod by0)`, so `cx`, `dx` divide *exactly* by the **original**
        // `by0` (not the reduced `byr`); `cy2` then divides by the reduced `bx`.
        // Checked divisions: on the rare degenerate state a relation is non-exact
        // ⇒ bail and let the caller fall back to plain composition.
        let cx = (&(&bx * &cy) - &(m * &x)).divexact_checked(&by_orig)?;
        let dx = (&(&bx * &dy) - &(w2 * &x)).divexact_checked(&by_orig)?;
        let cy2 = (&(&byr * &cx) + m).divexact_checked(&bx)?;
        let dy2 = (&(&dx * &ay) + ss).divexact_checked(&ax)?; // d_y·a_x = d_x·a_y + ss
                                                              // Compound (vdP): the near-reduced product form (a₃, b₃, c₃).
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

    /// `f^n` via NUCOMP/NUDUPL exponentiation: a width-5 sliding window whose
    /// squarings are NUDUPL ([`square`](Self::square)) and whose multiplications
    /// are NUCOMP ([`compose`](Self::compose)). Handles `n = 0` and `n < 0`.
    /// [`exp`](Self::exp) is the same routine.
    pub fn nupow(&self, f: &QFI, n: &Mpz) -> QFI {
        self.exp(f, n)
    }

    /// `f^n` via width-5 sliding-window exponentiation (handles `n = 0`, `n < 0`).
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

    /// Sliding-window exponentiation for a non-negative exponent `e`.
    fn exp_window(&self, base: &QFI, e: &Mpz) -> QFI {
        const W: usize = 5;
        // Odd-power table: odds[i] = base^(2i+1), i = 0 .. 2^(W-1)-1.
        let base_sq = self.square(base);
        let mut odds = Vec::with_capacity(1 << (W - 1));
        odds.push(base.clone());
        for _ in 1..(1 << (W - 1)) {
            let prev = odds.last().unwrap();
            odds.push(self.compose(prev, &base_sq));
        }

        let mut result = self.identity();
        let mut i = e.nbits() as isize - 1;
        while i >= 0 {
            if !e.get_bit(i as u32) {
                result = self.square(&result);
                i -= 1;
                continue;
            }
            // Longest window of width ≤ W ending in a set bit.
            let low = (i - W as isize + 1).max(0);
            let mut l = low;
            while !e.get_bit(l as u32) {
                l += 1;
            }
            for _ in 0..(i - l + 1) {
                result = self.square(&result);
            }
            let mut wval = 0usize;
            for k in (l..=i).rev() {
                wval = (wval << 1) | (e.get_bit(k as u32) as usize);
            }
            result = self.compose(&result, &odds[(wval - 1) / 2]);
            i = l - 1;
        }
        result
    }

    /// Build a fixed-base comb table (Lim–Lee) for exponents up to `maxbits`
    /// bits, split into `blocks` blocks. Amortises repeated exponentiations of
    /// the same base (e.g. `h`, or a public key).
    pub fn precompute_comb(&self, base: &QFI, maxbits: usize, blocks: usize) -> FixedBaseComb {
        let block_len = maxbits.div_ceil(blocks);
        // pj[j] = base^(2^(j·block_len))
        let mut pj = Vec::with_capacity(blocks);
        let mut cur = base.clone();
        pj.push(cur.clone());
        for _ in 1..blocks {
            for _ in 0..block_len {
                cur = self.square(&cur);
            }
            pj.push(cur.clone());
        }
        // table[i] = product of pj[j] over set bits j of i.
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

    /// Exponentiate a comb-precomputed base by a non-negative exponent `e`.
    ///                                                             
    /// `e` must fit in [`FixedBaseComb::max_bits`]; higher bits are ignored (the                                                       
    /// comb is sized for the bounded secret-key / randomness exponents). For a
    /// possibly-larger exponent use [`exp`](Self::exp).
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small fundamental-ish discriminant for structural tests of reduction
    // (Δ = -163, class number 1).
    fn cg_163() -> ClassGroup {
        ClassGroup::new(Mpz::from(-163i64))
    }

    #[test]
    fn identity_is_reduced_principal() {
        let cg = cg_163();
        let id = cg.identity();
        assert_eq!(id.discriminant(), Mpz::from(-163i64));
        assert!(id.is_principal());
        // reducing the identity is a no-op
        assert_eq!(cg.reduced(&id), id);
    }

    #[test]
    fn reduce_makes_valid_reduced_form() {
        let cg = ClassGroup::new(Mpz::from(-2003i64)); // -2003 ≡ 1 mod 4
                                                       // An unreduced form of the same discriminant.
        let mut f = QFI::from_abc(Mpz::from(9u64), Mpz::from(7u64), Mpz::new());
        // fix c so discriminant matches: c = (b²-Δ)/(4a)
        f.c = (&(&f.b * &f.b) - cg.discriminant()).divexact(&f.a.mul_2exp(2));
        let d_before = f.discriminant();
        cg.reduce(&mut f);
        // discriminant preserved
        assert_eq!(f.discriminant(), d_before);
        // reduced predicate: |b| <= a <= c
        assert!(f.b.abs() <= f.a);
        assert!(f.a <= f.c);
    }

    #[test]
    fn prime_form_has_right_discriminant() {
        let cg = ClassGroup::new(Mpz::from(-23i64)); // class number 3
                                                     // 2 splits in Q(sqrt(-23)) since -23 ≡ 1 mod 8
        let f2 = cg.prime_form(&Mpz::from(2u64));
        assert_eq!(f2.discriminant(), Mpz::from(-23i64));
        assert_eq!(*f2.a(), Mpz::from(2u64));
    }

    // --- group-law tests --------------------------------------------------

    fn cg_large() -> ClassGroup {
        // A 200-ish-bit negative discriminant ≡ 1 mod 4 (not necessarily
        // fundamental — group laws hold regardless).
        let d = Mpz::from_str_auto("-0xb503b3a4f1e2d6c8a7f9e1d3c5b7a90123456789abcdef13").unwrap();
        // make it ≡ 1 mod 4
        let r = d.modulo(&Mpz::from(4u64));
        let d = &d - &r + &Mpz::from(1u64); // now ≡ 1 mod 4 (still negative)
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
        let h = cg.compose(&g, &f); // f^3
        let left = cg.compose(&cg.compose(&f, &g), &h);
        let right = cg.compose(&f, &cg.compose(&g, &h));
        assert_eq!(left, right);
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
        // negative exponents
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
        // matches repeated composition
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
        // identity and an order-2 / boundary element are fixed by neg.
        let mut id = cg.identity();
        id.neg();
        assert_eq!(id, cg.identity());
    }

    #[test]
    fn lift_and_to_maximal_order_roundtrip() {
        // Δ_K = -23 (fundamental, ≡1 mod 4), conductor M = 5, Δ = 25·Δ_K = -575.
        let delta_k = Mpz::from(-23i64);
        let m = Mpz::from(5u64);
        let delta = &(&m * &m) * &delta_k;
        let clk = ClassGroup::new(delta_k.clone());
        let cl = ClassGroup::new(delta.clone());
        let base = clk.prime_form(&clk.smallest_split_prime());
        let mut w = clk.identity();
        for _ in 0..6 {
            // lift Δ_K → Δ: discriminant becomes M²·Δ_K.
            let mut down = w.lift(&m);
            assert_eq!(down.discriminant(), delta, "lift discriminant");
            cl.reduce(&mut down);
            assert_eq!(down.discriminant(), delta, "reduced lift discriminant");
            // go-up π: Δ → Δ_K, and π∘lift = id on Cl(Δ_K).
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
        // build a set of distinct reduced forms f^1..f^12
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

    /// Break down where `square` spends its time at a CL-sized discriminant.
    /// `cargo test --release --lib -- --ignored --nocapture profile_square`
    #[test]
    #[ignore]
    fn profile_square() {
        use std::time::Instant;
        // CL-sized: |Δ| ≈ 1796 bits, ≡ 1 (mod 4).
        let d = Mpz::from(1u64).mul_2exp(1796).add_ui(3).neg();
        let cg = ClassGroup::new(d);
        let base = cg.prime_form(&cg.smallest_split_prime());
        let f = cg.exp(&base, &Mpz::from(0x9e3779b97f4a7c15u64)); // generic reduced form
        let n = 4000;

        // unreduced §3a square for isolating reduce()
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

    /// Measure compose/square (NUCOMP/NUDUPL) vs the Dirichlet baseline at a
    /// CL-sized discriminant, with the final-reduction ρ-step count (near-reduced
    /// ⇒ few). `cargo test --release --lib -- --ignored --nocapture profile_ops`
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

        // ρ steps in the *final* reduce (near-reduced ⇒ few).
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

    /// Fine-grained breakdown of `square` (NUDUPL) at the CL size: time the
    /// setup (gcdext + divexacts + bx0), the partial reduction, the assembly,
    /// and the final reduction separately, to locate the dominant cost.
    /// `cargo test --release --lib -- --ignored --nocapture profile_square_breakdown`
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
        // Min over K sub-runs: scheduling/thermal noise only adds time, so the
        // minimum is the most stable estimator of true compute cost.
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
        // setup: gcdext + by/dy + bx0
        let setup = bench("  setup (gcdext+divs+bx0)", &|| {
            let (gg, u, _v) = b.gcdext(a);
            let by = a.divexact(&gg);
            let _dy = b.divexact(&gg);
            let _bx0 = (&u * c).modulo(&by);
        });
        // partial reduce
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
        // assembly + final reduce: total - setup - partial (approx)
        println!(
            "  => setup {setup:.2} | partial {partial:.2} | assembly+reduce ≈ {:.2} | total {total:.2}",
            total - setup - partial
        );
    }

    /// Realistic squaring cost: a chain `g ← square(g)` over *varying* forms
    /// (not the cache-friendly same-input loop), reporting the `nudupl_fast`
    /// miss rate (slow §3a fallbacks inflate the average).
    /// `cargo test --release --lib -- --ignored --nocapture profile_square_chain`
    #[test]
    #[ignore]
    fn profile_square_chain() {
        use std::time::Instant;
        let d = Mpz::from(1u64).mul_2exp(1796).add_ui(3).neg();
        let cg = ClassGroup::new(d);
        let base = cg.prime_form(&cg.smallest_split_prime());
        let mut g = cg.exp(&base, &Mpz::from(0x9e3779b97f4a7c15u64));
        // warm + advance
        for _ in 0..500 {
            g = cg.square(&g);
        }
        SQ_CALLS.with(|s| s.set(0));
        SQ_SLOW.with(|s| s.set(0));
        // True data-dependent latency (each square feeds the next, as in an
        // exponentiation): min over sub-chains to filter scheduling noise.
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

    /// Regression guard for the NUCOMP/NUDUPL fast path: at a CL-sized
    /// discriminant the partial-reduction assembly must actually *fire* (not
    /// silently fall back to Dirichlet composition) and must produce a
    /// *near-reduced* form (the final reduction takes only a few ρ steps, vs the
    /// ~185 a full `|Δ|`-sized product needs). This pins the modulus bug fix
    /// (`cx, dx` divide by the original `By`, not the reduced one).
    /// Fuzz the NUDUPL `square` against the Dirichlet baseline over a long chain
    /// of squarings at a CL-sized discriminant. A squaring chain naturally visits
    /// forms with `gcd(a, b) > 1` (~1 in 8), so this exercises the general-`G`
    /// assembly path — not just the `G = 1` fast case — and the i64-division
    /// Lehmer inner loop. Any divergence from `compose_dirichlet` fails here.
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
        // The chain must actually have visited some gcd(a,b)>1 forms, else the
        // general-G path is untested.
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

        // compose fires the fast path and equals the Dirichlet reference.
        assert_eq!(cg.compose(&f, &g), cg.compose_dirichlet(&f, &g));
        // Call compose alone (the equality above also ran Dirichlet, which would
        // overwrite the instrumentation) to capture the fast path's own counters.
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

        // square fires NUDUPL and equals the Dirichlet self-composition.
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
        // NUCOMP agrees with plain composition at a large (~6000-bit) discriminant.
        // (HGCD itself is exercised directly in the `hgcd` module's tests.)
        let d = Mpz::from(1u64).mul_2exp(6000).add_ui(3).neg(); // ≡ 1 (mod 4), < 0
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
        let cg = ClassGroup::new(Mpz::from(-23i64)); // Cl(-23) ≅ Z/3
        let id = cg.identity();
        let f2 = cg.prime_form(&Mpz::from(2u64));
        assert_ne!(f2, id);
        let f2sq = cg.square(&f2);
        assert_ne!(f2sq, id);
        // order 3: f2^2 == f2^{-1}, f2^3 == id
        assert_eq!(f2sq, cg.inverse(&f2));
        assert_eq!(cg.exp(&f2, &Mpz::from(3u64)), id);
    }
}
