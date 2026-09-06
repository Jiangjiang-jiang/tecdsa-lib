//! Arbitrary-precision integers backed by GMP through the `rug` crate (LGPL).
//!
//! `Mpz` is a thin newtype over [`rug::Integer`]. The wrapper exists so the
//! public API is independent of the backend and so we can expose exactly the
//! surface the rest of the crate (and clients) need.

use core::{cmp::Ordering, fmt};

use rug::{
    integer::{IsPrime, Order},
    ops::Pow,
    Integer,
};

use super::error::{ClassGroupError, Result};

/// Arbitrary-precision signed integer.
#[derive(Clone, Debug, Default)]
pub struct Mpz(pub(crate) Integer);

impl Mpz {
    // ---- construction / backend access ------------------------------------

    /// Zero.
    pub fn new() -> Self {
        Mpz(Integer::new())
    }

    pub fn from_inner(i: Integer) -> Self {
        Mpz(i)
    }
    pub fn inner(&self) -> &Integer {
        &self.0
    }
    pub fn into_inner(self) -> Integer {
        self.0
    }

    /// Parse with GMP base-0 semantics: `0x`/`0X` hex, `0b`/`0B` binary,
    /// leading-`0` octal, otherwise decimal. A leading `+`/`-` is accepted.
    pub fn from_str_auto(s: &str) -> Result<Mpz> {
        let t = s.trim();
        if t.is_empty() {
            return Err(ClassGroupError::ParseError("empty string".into()));
        }
        let (neg, rest) = match t.as_bytes()[0] {
            b'-' => (true, &t[1..]),
            b'+' => (false, &t[1..]),
            _ => (false, t),
        };
        let (radix, digits): (i32, &str) =
            if let Some(r) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
                (16, r)
            } else if let Some(r) = rest.strip_prefix("0b").or_else(|| rest.strip_prefix("0B")) {
                (2, r)
            } else if rest.len() > 1 && rest.starts_with('0') {
                (8, &rest[1..])
            } else {
                (10, rest)
            };
        let parsed = Integer::parse_radix(digits, radix)
            .map_err(|e| ClassGroupError::ParseError(e.to_string()))?;
        let mut v = Integer::from(parsed);
        if neg {
            v = -v;
        }
        Ok(Mpz(v))
    }

    // ---- predicates / inspection ------------------------------------------

    /// `-1`, `0`, or `1`.
    pub fn sgn(&self) -> i32 {
        match self.0.cmp0() {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }
    pub fn is_zero(&self) -> bool {
        self.0.cmp0() == Ordering::Equal
    }
    pub fn is_one(&self) -> bool {
        self.0 == 1
    }
    pub fn is_odd(&self) -> bool {
        self.0.is_odd()
    }
    pub fn is_even(&self) -> bool {
        self.0.is_even()
    }
    /// Number of significant bits in the absolute value (0 for zero).
    pub fn nbits(&self) -> usize {
        self.0.significant_bits() as usize
    }
    pub fn get_bit(&self, i: u32) -> bool {
        self.0.get_bit(i)
    }
    pub fn cmp_abs(&self, other: &Mpz) -> Ordering {
        self.0.clone().abs().cmp(&other.0.clone().abs())
    }

    // ---- byte (de)serialisation (magnitude, big-endian) -------------------

    pub fn to_bytes_be(&self) -> Vec<u8> {
        let n = self.0.significant_digits::<u8>();
        let mut buf = vec![0u8; n];
        self.0.write_digits(&mut buf, Order::Msf);
        buf
    }
    pub fn from_bytes_be(b: &[u8]) -> Mpz {
        Mpz(Integer::from_digits(b, Order::Msf))
    }

    // ---- basic arithmetic --------------------------------------------------

    pub fn abs(&self) -> Mpz {
        Mpz(self.0.clone().abs())
    }
    pub fn neg(&self) -> Mpz {
        Mpz(Integer::from(-&self.0))
    }
    pub fn double(&self) -> Mpz {
        Mpz(Integer::from(&self.0 << 1))
    }
    /// `self * 2^n`.
    pub fn mul_2exp(&self, n: u32) -> Mpz {
        Mpz(Integer::from(&self.0 << n))
    }
    /// `floor(self / 2^n)`.
    pub fn fdiv_2exp(&self, n: u32) -> Mpz {
        Mpz(Integer::from(&self.0 >> n))
    }
    pub fn add_ui(&self, n: u64) -> Mpz {
        Mpz(Integer::from(&self.0 + n))
    }
    pub fn mul_ui(&self, n: u64) -> Mpz {
        Mpz(Integer::from(&self.0 * n))
    }

    // ---- division / modular reduction -------------------------------------

    /// Floored quotient and remainder; for positive `d`, `r ∈ [0, d)`.
    pub fn fdiv_qr(&self, d: &Mpz) -> (Mpz, Mpz) {
        let (q, r) = self.0.clone().div_rem_floor(d.0.clone());
        (Mpz(q), Mpz(r))
    }
    /// Non-negative remainder `self mod m` (requires `m > 0`).
    pub fn modulo(&self, m: &Mpz) -> Mpz {
        let (_, r) = self.0.clone().div_rem_floor(m.0.clone());
        Mpz(r)
    }
    /// Exact division (caller guarantees divisibility).
    pub fn divexact(&self, d: &Mpz) -> Mpz {
        Mpz(self.0.clone().div_exact(&d.0))
    }
    /// Exact division, or `None` if `d` is zero or does not divide `self`.
    pub fn divexact_checked(&self, d: &Mpz) -> Option<Mpz> {
        if d.is_zero() || !self.0.is_divisible(&d.0) {
            None
        } else {
            Some(Mpz(self.0.clone().div_exact(&d.0)))
        }
    }
    /// Floored quotient.
    pub fn fdiv_q(&self, d: &Mpz) -> Mpz {
        Mpz(self.0.clone().div_rem_floor(d.0.clone()).0)
    }
    /// `true` iff `self` divides `n`.
    pub fn divides(&self, n: &Mpz) -> bool {
        n.0.is_divisible(&self.0)
    }

    // ---- number theory -----------------------------------------------------

    pub fn gcd(&self, other: &Mpz) -> Mpz {
        Mpz(self.0.clone().gcd(&other.0))
    }
    /// Extended gcd: returns `(g, u, v)` with `g = u*self + v*other`, `g >= 0`.
    pub fn gcdext(&self, other: &Mpz) -> (Mpz, Mpz, Mpz) {
        let (g, u, v) = self.0.clone().extended_gcd(other.0.clone(), Integer::new());
        (Mpz(g), Mpz(u), Mpz(v))
    }
    /// Modular inverse of `self` mod `m`, or `None` if not invertible.
    pub fn invert(&self, m: &Mpz) -> Option<Mpz> {
        self.0.clone().invert(&m.0).ok().map(Mpz)
    }
    /// `self^exp mod m` (exp may be negative if `self` is invertible mod `m`).
    pub fn powm(&self, exp: &Mpz, m: &Mpz) -> Mpz {
        Mpz(self
            .0
            .clone()
            .pow_mod(&exp.0, &m.0)
            .expect("pow_mod: base not invertible for negative exponent"))
    }
    /// Kronecker symbol `(self | n)`.
    pub fn kronecker(&self, n: &Mpz) -> i32 {
        self.0.kronecker(&n.0)
    }
    /// Floor of the square root (requires `self >= 0`).
    pub fn sqrt(&self) -> Mpz {
        Mpz(self.0.clone().sqrt())
    }
    pub fn is_perfect_square(&self) -> bool {
        self.0.is_perfect_square()
    }
    /// Floor of the `n`-th root (requires `self >= 0`).
    pub fn root(&self, n: u32) -> Mpz {
        Mpz(self.0.clone().root(n))
    }
    /// Probabilistic primality test (Miller–Rabin with `reps` rounds).
    pub fn is_probab_prime(&self, reps: u32) -> bool {
        !matches!(self.0.is_probably_prime(reps), IsPrime::No)
    }
    /// Smallest prime strictly greater than `self`.
    pub fn next_prime(&self) -> Mpz {
        Mpz(self.0.clone().next_prime())
    }
    /// `self^e` (non-modular).
    pub fn pow_u(&self, e: u32) -> Mpz {
        Mpz(self.0.clone().pow(e))
    }
}

// ---- trait implementations -------------------------------------------------

impl PartialEq for Mpz {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Mpz {}
impl PartialOrd for Mpz {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Mpz {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialEq<u64> for Mpz {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}
impl PartialOrd<u64> for Mpz {
    fn partial_cmp(&self, other: &u64) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}

impl fmt::Display for Mpz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl core::str::FromStr for Mpz {
    type Err = ClassGroupError;
    /// Parses with GMP base-0 semantics (see [`Mpz::from_str_auto`]).
    fn from_str(s: &str) -> Result<Mpz> {
        Mpz::from_str_auto(s)
    }
}

macro_rules! impl_from {
    ($($t:ty),*) => {$(
        impl From<$t> for Mpz {
            fn from(v: $t) -> Self { Mpz(Integer::from(v)) }
        }
    )*};
}
impl_from!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

macro_rules! impl_binop {
    ($Trait:ident, $method:ident, $op:tt) => {
        impl core::ops::$Trait<&Mpz> for &Mpz {
            type Output = Mpz;
            fn $method(self, rhs: &Mpz) -> Mpz { Mpz(Integer::from(&self.0 $op &rhs.0)) }
        }
        impl core::ops::$Trait for Mpz {
            type Output = Mpz;
            fn $method(self, rhs: Mpz) -> Mpz { Mpz(self.0 $op rhs.0) }
        }
        impl core::ops::$Trait<&Mpz> for Mpz {
            type Output = Mpz;
            fn $method(self, rhs: &Mpz) -> Mpz { Mpz(self.0 $op &rhs.0) }
        }
    };
}
impl_binop!(Add, add, +);
impl_binop!(Sub, sub, -);
impl_binop!(Mul, mul, *);

impl core::ops::Neg for &Mpz {
    type Output = Mpz;
    fn neg(self) -> Mpz {
        Mpz(Integer::from(-&self.0))
    }
}
impl core::ops::Neg for Mpz {
    type Output = Mpz;
    fn neg(self) -> Mpz {
        Mpz(-self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_decimal_octal_binary() {
        assert_eq!(Mpz::from_str_auto("0xff").unwrap(), Mpz::from(255u64));
        assert_eq!(Mpz::from_str_auto("255").unwrap(), Mpz::from(255u64));
        assert_eq!(Mpz::from_str_auto("0377").unwrap(), Mpz::from(255u64));
        assert_eq!(Mpz::from_str_auto("0b11111111").unwrap(), Mpz::from(255u64));
        assert_eq!(Mpz::from_str_auto("-0x10").unwrap(), Mpz::from(-16i64));
        assert_eq!(Mpz::from_str_auto("0").unwrap(), Mpz::from(0u64));
    }

    #[test]
    fn parse_large_hex() {
        let q = Mpz::from_str_auto("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d")
            .unwrap();
        assert_eq!(q.nbits(), 224);
        assert!(q.is_odd());
    }

    #[test]
    fn bytes_roundtrip() {
        let a = Mpz::from_str_auto("0xdeadbeef0123456789").unwrap();
        let b = Mpz::from_bytes_be(&a.to_bytes_be());
        assert_eq!(a, b);
    }

    #[test]
    fn arithmetic_and_modular() {
        let a = Mpz::from(17u64);
        let b = Mpz::from(5u64);
        assert_eq!(&a + &b, Mpz::from(22u64));
        assert_eq!(&a - &b, Mpz::from(12u64));
        assert_eq!(&a * &b, Mpz::from(85u64));
        assert_eq!(a.modulo(&b), Mpz::from(2u64));
        // floored mod is non-negative
        assert_eq!(Mpz::from(-3i64).modulo(&Mpz::from(5u64)), Mpz::from(2u64));
        let inv = a.invert(&Mpz::from(101u64)).unwrap();
        assert_eq!((&a * &inv).modulo(&Mpz::from(101u64)), Mpz::from(1u64));
    }

    #[test]
    fn gcdext_identity() {
        let a = Mpz::from(240u64);
        let b = Mpz::from(46u64);
        let (g, u, v) = a.gcdext(&b);
        assert_eq!(g, Mpz::from(2u64));
        assert_eq!(&(&u * &a) + &(&v * &b), g);
    }

    #[test]
    fn kronecker_symbol() {
        // (2|7) = 1, (3|7) = -1
        assert_eq!(Mpz::from(2u64).kronecker(&Mpz::from(7u64)), 1);
        assert_eq!(Mpz::from(3u64).kronecker(&Mpz::from(7u64)), -1);
    }
}
