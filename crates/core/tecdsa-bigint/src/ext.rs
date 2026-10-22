// SPDX-License-Identifier: MIT OR Apache-2.0
//! Extension methods on [`rug::Integer`].
//!
//! The workspace shares a single big-integer type, `rug::Integer`. These are
//! the helpers it does not provide inherently: byte (de)serialisation in the
//! orderings the protocols use, `rand_core`-driven sampling, safe-prime
//! generation, and a few number-theoretic predicates.
//!
//! Import the trait to use them:
//!
//! ```rust
//! use rug::Integer;
//! use tecdsa_bigint::BigIntExt;
//! assert_eq!(Integer::two_pow(8), Integer::from(256));
//! ```
//!
//! Methods that would collide with an inherent `rug::Integer` method are
//! deliberately absent: Rust resolves inherent methods before trait methods, so
//! such a method could never be called and would silently diverge from the
//! inherent one. Use rug's own API for `is_probably_prime`, `from_str_radix`,
//! and the `random_*` family (the `rand_core`-adapting variants are named
//! `sample_*` here to avoid the clash).

use rug::Complete;

/// Sign of a number, to distinguish positives and zero from negatives.
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Sign {
    /// Positive or zero
    NonNegative,
    Negative,
}

pub trait BigIntExt: Sized {
    /// Converts to bytes, with bytes representing _least_ significant base256
    /// digits appearing first. Discards the sign
    ///
    /// ## Example
    /// ```rust
    /// # use rug::Integer;
    /// # use tecdsa_bigint::BigIntExt;
    /// let x = Integer::from(0x11223344);
    /// assert_eq!(x.to_bytes_lsf(), vec![0x44, 0x33, 0x22, 0x11]);
    /// ```
    fn to_bytes_lsf(&self) -> Vec<u8>;
    /// Converts to bytes, with bytes representing _most_ significant base256
    /// digits appearing first. Discards the sign
    ///
    /// ## Example
    /// ```rust
    /// # use rug::Integer;
    /// # use tecdsa_bigint::BigIntExt;
    /// let x = Integer::from(0x11223344);
    /// assert_eq!(x.to_bytes_msf(), vec![0x11, 0x22, 0x33, 0x44]);
    /// ```
    fn to_bytes_msf(&self) -> Vec<u8>;
    /// Converts to bytes, with bytes representing _most_ significant base256
    /// digits appearing first
    ///
    /// ## Example
    /// ```rust
    /// # use rug::Integer;
    /// # use tecdsa_bigint::{BigIntExt, Sign};
    /// let x = Integer::from(-0x11223344);
    /// assert_eq!(
    ///     x.to_bytes_msf_signed(),
    ///     (vec![0x11, 0x22, 0x33, 0x44], Sign::Negative)
    /// );
    /// ```
    fn to_bytes_msf_signed(&self) -> (Vec<u8>, Sign);
    /// Converts bytes to Integer. Inverse of [`Integer::to_bytes_msf`]
    fn from_bytes_msf(bytes: &[u8]) -> Self;
    /// Converts bytes to Integer. Inverse of [`Integer::to_bytes_msf_signed`]
    fn from_bytes_msf_signed(bytes: &[u8], sign: Sign) -> Self;
    /// Returns a string representation of the number for the specified radix
    fn to_str_radix(&self, radix: u16) -> String;

    fn one() -> Self;
    fn zero() -> Self;
    fn is_one(&self) -> bool;

    /// `2^exp`.
    ///
    /// These powers of two are everywhere in the range/slack bounds of the ZK
    /// proofs, so they get a name rather than being spelled
    /// `Integer::u_pow_u(2, exp).complete()` at every use.
    ///
    /// Implemented with `u_pow_u` rather than `Integer::from(1) << exp`: the
    /// two are equal, but GMP special-cases base 2 in `mpz_ui_pow_ui` and
    /// benchmarks about 15% faster than the shift.
    fn two_pow(exp: u32) -> Self;

    fn sign(&self) -> Sign;

    fn significant_dwords(&self) -> usize;

    /// Uniform sample in `[0, self)`, consuming `self`.
    ///
    /// Named `sample_*` rather than `random_*` to avoid shadowing by
    /// [`rug::Integer::random_below`], which takes rug's own RNG type and
    /// returns a lazy value. This variant adapts a [`rand_core`] RNG and
    /// returns an owned `Integer`.
    fn sample_below(self, rng: &mut impl rand_core::RngCore) -> Self;
    /// Uniform sample in `[0, self)`. See [`BigIntExt::sample_below`].
    fn sample_below_ref(&self, rng: &mut impl rand_core::RngCore) -> Self;
    /// Uniform sample from the symmetric range around zero:
    /// `[-range/2, range/2]` when `range` is even, `[-(range-1)/2, (range-1)/2]`
    /// when it is odd.
    fn from_rng_half_pm(rng: &mut impl rand_core::RngCore, range: &Self) -> Self;

    /// Whether `self` lies in the symmetric range described by
    /// [`BigIntExt::from_rng_half_pm`].
    fn is_in_half_pm(&self, range: &Self) -> bool;

    /// Uniform sample in `[1, self)`.
    ///
    /// Drawn as `1 + sample_below(self - 1)` rather than by rejecting zero, so
    /// it always terminates in one draw. See [`BigIntExt::sample_below`].
    ///
    /// # Panics
    /// Panics if `self <= 1`, where the range is empty.
    fn sample_positive_below(&self, rng: &mut impl rand_core::RngCore) -> Self;
    /// Uniform sample of `bits` random bits. See [`BigIntExt::sample_below`].
    fn sample_bits(bits: u32, rng: &mut impl rand_core::RngCore) -> Self;
    fn random_bits_signed(bits: u32, rng: &mut impl rand_core::RngCore) -> Self;

    fn assign_random_below(
        &mut self,
        modulo: &Self,
        rng: &mut impl rand_core::RngCore,
    ) -> &mut Self;

    fn assign_random_bits(&mut self, bits: u32, rng: &mut impl rand_core::RngCore) -> &mut Self;

    fn generate_prime(rng: &mut impl rand_core::RngCore, bit_size: u32) -> Self;

    /// Compute l^le * r^re modulo self
    fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Option<Self>;

    /// Simultaneous multi-exponentiation `prod bases[i]^exps[i]` modulo self,
    /// via an interleaved fixed-window (Straus/Shamir) algorithm.
    ///
    /// A single squaring chain is shared across all bases (`max_bits` squarings
    /// instead of one full chain per base), which is the dominant cost. Each
    /// base contributes one multiplication per nonzero `W`-bit window.
    ///
    /// Modular inversion is *not* free here (unlike class groups), so this uses
    /// plain unsigned windows rather than signed-digit (NAF/JSF) recoding. All
    /// exponents must be non-negative.
    ///
    /// # Panics
    /// Panics if `bases.len() != exps.len()`.
    fn multi_exp(&self, bases: &[&Self], exps: &[&Self]) -> Self;

    /// Modular square root by Tonelli-Shanks: returns `r` with `r^2 = self (mod p)`,
    /// or `None` if `self` is a quadratic non-residue mod `p`.
    ///
    /// `p` must be an odd prime.
    fn sqrt_mod(&self, p: &Self) -> Option<Self>;

    /// Checks that `self` is in Z<super>*</super><sub>n</sub>
    fn in_mult_group_of(&self, n: &Self) -> bool;

    /// Checks that `abs(self)` is in Z<super>*</super><sub>n</sub>
    fn abs_in_mult_group_of(&self, n: &Self) -> bool;

    /// Samples `x` in Z*_n
    fn sample_in_mult_group_of(rng: &mut impl rand_core::RngCore, n: &Self) -> Self;

    /// Samples `x` such that abs(x) is in `Z*_n`
    fn sample_pm_in_mult_group_of(rng: &mut impl rand_core::RngCore, n: &Self) -> Self;

    /// Samples `w` in `Z*_n` with Jacobi symbol `(w/n) = -1`.
    fn sample_neg_jacobi(rng: &mut impl rand_core::RngCore, n: &Self) -> Self;

    /// Principal square root of `self` modulo a Blum integer `n = p*q`.
    ///
    /// Uses the exponent `((p-1)(q-1) + 4) / 8` from [Handbook of Applied
    /// Cryptography, p. 75, Fact 2.160](https://cacr.uwaterloo.ca/hac/about/chap2.pdf).
    ///
    /// Requires `self` to be a quadratic residue mod `n` and `p`, `q` to be Blum
    /// primes; otherwise the result is a meaningless element of `Z_n`.
    fn blum_sqrt(&self, p: &Self, q: &Self, n: &Self) -> Self;

    /// Fourth root of `self` modulo a Blum integer, i.e. [`BigIntExt::blum_sqrt`] twice.
    fn blum_fourth_root(&self, p: &Self, q: &Self, n: &Self) -> Self;

    /// Finds `(a, b, y')` with `y' = (-1)^a * w^b * self` a quadratic residue mod `n`,
    /// where `a` and `b` are `false = 0` / `true = 1`.
    ///
    /// Requires `n = p*q` with `p`, `q` Blum primes and `jacobi(w, n) = -1`. Returns
    /// `None` when no such `y'` exists, which cannot happen if those hold.
    fn find_residue(&self, w: &Self, p: &Self, q: &Self, n: &Self) -> Option<(bool, bool, Self)>;

    /// Generate a random safe prime using a windowed double sieve.
    ///
    /// Generates a Sophie Germain prime `q` of `bits - 1` bits and returns the safe
    /// prime `p = 2q + 1` of `bits` bits.
    ///
    /// Rather than testing random candidates one at a time, this draws a single
    /// random odd base and sieves a whole window of candidates `q = base + 2j`
    /// against every odd prime below the sieve limit, ruling out in one pass any
    /// position where either `q` or `2q + 1` is divisible by a small prime. Survivors
    /// are first cheaply filtered with a single Miller-Rabin round; `p = 2q + 1` is
    /// then checked with one base-2 Fermat test which, by Pocklington's criterion
    /// (`q` prime and `q > sqrt(p)`), *proves* `p` prime, so the full confidence
    /// rounds are spent only on `q`. This minimises the big-integer primality checks
    /// per safe prime found.
    ///
    /// The sieve limit grows with `bits`: a larger limit removes more composite
    /// candidates up front at the cost of a bigger sieve.
    fn generate_safe_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Self;

    /// Generates a random Blum prime, i.e. a safe prime `p = 3 (mod 4)`.
    ///
    /// For a safe prime `p = 2p' + 1` with `p' > 2`, `p = 3 (mod 4)` holds
    /// automatically; this asserts it rather than leaving it implicit.
    fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Self;

    /// Returns `true` if `self` is a safe prime, i.e. both `self` and
    /// `(self - 1) / 2` are (probably) prime.
    fn is_safe_prime(&self) -> bool;
}

impl BigIntExt for rug::Integer {
    fn to_bytes_lsf(&self) -> Vec<u8> {
        self.to_digits(rug::integer::Order::Lsf)
    }

    fn to_bytes_msf(&self) -> Vec<u8> {
        self.to_digits(rug::integer::Order::Msf)
    }

    fn to_bytes_msf_signed(&self) -> (Vec<u8>, Sign) {
        (
            self.to_digits(rug::integer::Order::Msf),
            match self.cmp0() {
                core::cmp::Ordering::Less => Sign::Negative,
                _ => Sign::NonNegative,
            },
        )
    }

    fn from_bytes_msf(bytes: &[u8]) -> Self {
        rug::Integer::from_digits(bytes, rug::integer::Order::Msf)
    }

    fn from_bytes_msf_signed(bytes: &[u8], sign: Sign) -> Self {
        let r = rug::Integer::from_digits(bytes, rug::integer::Order::Msf);
        if sign == Sign::Negative {
            -r
        } else {
            r
        }
    }

    fn to_str_radix(&self, radix: u16) -> String {
        self.to_string_radix(radix.into())
    }

    fn one() -> Self {
        rug::Integer::ONE.clone()
    }

    fn zero() -> Self {
        rug::Integer::new()
    }

    fn is_one(&self) -> bool {
        self == rug::Integer::ONE
    }

    fn two_pow(exp: u32) -> Self {
        rug::Integer::u_pow_u(2, exp).complete()
    }

    fn sign(&self) -> Sign {
        match self.cmp0() {
            core::cmp::Ordering::Less => Sign::Negative,
            _ => Sign::NonNegative,
        }
    }

    fn significant_dwords(&self) -> usize {
        self.significant_digits::<u32>()
    }

    fn sample_below(self, rng: &mut impl rand_core::RngCore) -> Self {
        let mut adapter = crate::prime::SyncRng(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        self.random_below(&mut rng)
    }

    fn sample_below_ref(&self, rng: &mut impl rand_core::RngCore) -> Self {
        let mut adapter = crate::prime::SyncRng(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        self.random_below_ref(&mut rng).complete()
    }

    fn from_rng_half_pm(rng: &mut impl rand_core::RngCore, range: &Self) -> Self {
        if range.is_even() {
            let half_range = (range >> 1u32).complete();
            let range_plus_one = (range + 1u32).complete();
            range_plus_one.sample_below(rng) - half_range
        } else {
            // `range` is odd, so `(range - 1) / 2` is just `range >> 1`.
            let half_range_minus_one = (range >> 1u32).complete();
            range.sample_below_ref(rng) - half_range_minus_one
        }
    }

    fn is_in_half_pm(&self, range: &Self) -> bool {
        // Even: `range >> 1` is exactly `range / 2`.
        // Odd:  `range >> 1 == (range - 1) / 2`, the low bit being discarded.
        let bound = (range >> 1u32).complete();
        self.cmp_abs(&bound).is_le()
    }

    fn sample_positive_below(&self, rng: &mut impl rand_core::RngCore) -> Self {
        assert!(*self > 1, "sample_positive_below: range [1, self) is empty");
        (self - 1u32).complete().sample_below(rng) + 1u32
    }

    fn sample_bits(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let mut adapter = crate::prime::SyncRng(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        rug::Integer::random_bits(bits, &mut rng).complete()
    }

    fn random_bits_signed(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let mut adapter = crate::prime::SyncRng(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        let r = rug::Integer::random_bits(bits, &mut rng).complete();
        let negative = rng.bits(1);
        if negative == 0 {
            r
        } else {
            -r
        }
    }

    fn assign_random_below(
        &mut self,
        modulo: &Self,
        rng: &mut impl rand_core::RngCore,
    ) -> &mut Self {
        let mut adapter = crate::prime::SyncRng(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        let r = modulo.random_below_ref(&mut rng);
        rug::Assign::assign(self, r);
        self
    }

    fn assign_random_bits(&mut self, bits: u32, rng: &mut impl rand_core::RngCore) -> &mut Self {
        let mut adapter = crate::prime::SyncRng(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        let r = rug::Integer::random_bits(bits, &mut rng);
        rug::Assign::assign(self, r);
        self
    }

    fn generate_prime(rng: &mut impl rand_core::RngCore, bit_size: u32) -> Self {
        let mut x = rug::Integer::zero();
        loop {
            x.assign_random_bits(bit_size, rng);
            x.set_bit(bit_size - 1, true);
            x |= 1u32;
            if let rug::integer::IsPrime::Yes | rug::integer::IsPrime::Probably =
                x.is_probably_prime(25)
            {
                return x;
            }
        }
    }

    fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Option<Self> {
        // The two exponentiations are independent. This is the innermost hot
        // spot of every Ring-Pedersen commitment (pi_enc, pi_aff_g, pi_fac,
        // ...), so parallelising it here speeds up the whole ZK stack at once.
        let (l_to_le, r_to_re) = crate::par::join(
            || l.pow_mod_ref(le, self).map(Self::from),
            || r.pow_mod_ref(re, self).map(Self::from),
        );
        Some((l_to_le? * r_to_re?).modulo(self))
    }

    fn multi_exp(&self, bases: &[&Self], exps: &[&Self]) -> Self {
        assert_eq!(
            bases.len(),
            exps.len(),
            "multi_exp: bases and exps must have equal length"
        );
        /// Window width in bits.
        const W: u32 = 4;
        const TABLE: usize = 1 << W;

        let mut maxbits = 0u32;
        for e in exps {
            maxbits = maxbits.max(e.significant_bits());
        }
        if maxbits == 0 {
            return Self::one();
        }

        // Per-base window table: base^d mod self for d in 0..2^W.
        let mut tables: Vec<Vec<Self>> = Vec::with_capacity(bases.len());
        for b in bases {
            let mut tab = Vec::with_capacity(TABLE);
            tab.push(Self::one());
            tab.push((*b).clone());
            for d in 2..TABLE {
                tab.push(rug::Integer::from(&tab[d - 1] * *b).modulo(self));
            }
            tables.push(tab);
        }

        let nblocks = maxbits.div_ceil(W);
        let mut result = Self::one();
        for blk in (0..nblocks).rev() {
            for _ in 0..W {
                result = result.square().modulo(self);
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
                    result = (result * &tab[d]).modulo(self);
                }
            }
        }
        result
    }

    #[allow(clippy::many_single_char_names)]
    fn sqrt_mod(&self, p: &Self) -> Option<Self> {
        if self.jacobi(p) != 1 {
            return None;
        }
        let one = Self::one();

        let p_minus_1 = (p - &one).complete();
        let mut q = p_minus_1.clone();
        let mut s: u32 = 0;
        while q.is_even() {
            q >>= 1u32;
            s += 1;
        }

        if s == 1 {
            let exp = (p + &one).complete() >> 2u32;
            return self.clone().pow_mod(&exp, p).ok();
        }

        let mut z = rug::Integer::from(2);
        while z.jacobi(p) != -1 {
            z += &one;
        }

        let mut m_val = s;
        let mut c = z.pow_mod(&q, p).unwrap();
        let mut t = self.clone().pow_mod(&q, p).unwrap();
        let mut r = self.clone().pow_mod(&((q + one) >> 1u32), p).unwrap();

        loop {
            if t == 1 {
                return Some(r);
            }
            let mut i: u32 = 1;
            let mut tmp = t.square_ref().complete() % p;
            while tmp != 1 {
                tmp = tmp.square() % p;
                i += 1;
            }
            let b = c
                .pow_mod(
                    &rug::Integer::from(2)
                        .pow_mod(&rug::Integer::from(m_val - i - 1), &p_minus_1)
                        .unwrap(),
                    p,
                )
                .unwrap();
            m_val = i;
            c = b.square_ref().complete() % p;
            t = t * &c % p;
            r = r * b % p;
        }
    }

    fn in_mult_group_of(&self, n: &Self) -> bool {
        self.cmp0().is_gt() && self < n && self.gcd_ref(n).complete().is_one()
    }

    fn abs_in_mult_group_of(&self, n: &Self) -> bool {
        self.cmp_abs(n).is_lt() && self.gcd_ref(n).complete().is_one()
    }

    fn sample_in_mult_group_of(rng: &mut impl rand_core::RngCore, n: &Self) -> Self {
        let mut x = Self::zero();
        loop {
            x.assign_random_below(n, rng);
            if x.in_mult_group_of(n) {
                return x;
            }
        }
    }

    fn sample_pm_in_mult_group_of(rng: &mut impl rand_core::RngCore, n: &Self) -> Self {
        let mut x = Self::zero();
        let mut sign_buf = [0u8; 1];
        loop {
            x.assign_random_below(n, rng);
            rng.fill_bytes(&mut sign_buf);
            if sign_buf[0] & 1 == 1 {
                x = -x;
            }
            if x.abs_in_mult_group_of(n) {
                return x;
            }
        }
    }

    fn sample_neg_jacobi(rng: &mut impl rand_core::RngCore, n: &Self) -> Self {
        loop {
            let w = Self::sample_in_mult_group_of(rng, n);
            // jacobi(1, n) == 1, so w == 1 is rejected here rather than by an
            // explicit guard.
            if w.jacobi(n) == -1 {
                return w;
            }
        }
    }

    fn blum_sqrt(&self, p: &Self, q: &Self, n: &Self) -> Self {
        let e = ((p - 1u32).complete() * (q - 1u32).complete() + 4u32) / 8u32;
        // e is non-negative because p and q are Blum primes.
        self.pow_mod_ref(&e, n)
            .expect("e is non-negative")
            .complete()
    }

    fn blum_fourth_root(&self, p: &Self, q: &Self, n: &Self) -> Self {
        self.blum_sqrt(p, q, n).blum_sqrt(p, q, n)
    }

    fn find_residue(&self, w: &Self, p: &Self, q: &Self, n: &Self) -> Option<(bool, bool, Self)> {
        // Euclidean reduction, so the Jacobi symbols are taken on non-negative
        // representatives even when `self` is negative.
        let jacobi_pair = |y: &Self| {
            (
                y.modulo_ref(p).complete().jacobi(p),
                y.modulo_ref(q).complete().jacobi(q),
            )
        };

        match jacobi_pair(self) {
            (1, 1) => return Some((false, false, self.clone())),
            (-1, -1) => return Some((true, false, (n - self).complete())),
            _ => {}
        }

        let wy = (self * w).complete().modulo(n);
        match jacobi_pair(&wy) {
            (1, 1) => Some((false, true, wy)),
            (-1, -1) => {
                let neg = (n - &wy).complete();
                Some((true, true, neg))
            }
            _ => None,
        }
    }

    fn generate_safe_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Self {
        let mut sync = crate::prime::SyncRng(rng);
        let rug_rng = &mut rug::rand::ThreadRandState::new_custom(&mut sync);
        let sieve_limit = crate::prime::default_sieve_limit(u64::from(bits));
        let primes = crate::prime::small_odd_primes(sieve_limit);
        // a = 2 makes the chain prime `2q + 1`, i.e. the safe prime.
        #[cfg(not(feature = "parallel"))]
        let gen_pair = crate::prime::gen_pair;
        #[cfg(feature = "parallel")]
        let gen_pair = crate::prime::gen_pair_par;
        let (_, p) = gen_pair(
            bits - 1,
            &rug::Integer::from(2),
            crate::prime::MR_ROUNDS,
            crate::prime::WINDOW_BITS,
            &primes,
            rug_rng,
        );
        p
    }

    fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Self {
        let p = Self::generate_safe_prime(rng, bits);
        assert_eq!(p.mod_u(4), 3, "safe prime must be = 3 mod 4 for bits >= 3");
        p
    }

    fn is_safe_prime(&self) -> bool {
        if self.is_probably_prime(crate::prime::MR_ROUNDS) == rug::integer::IsPrime::No {
            return false;
        }
        let sophie = (self - 1u32).complete() >> 1u32;
        sophie.is_probably_prime(crate::prime::MR_ROUNDS) != rug::integer::IsPrime::No
    }
}
