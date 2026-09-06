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
        let mut adapter = RngAdapter(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        self.random_below(&mut rng)
    }

    fn sample_below_ref(&self, rng: &mut impl rand_core::RngCore) -> Self {
        let mut adapter = RngAdapter(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        self.random_below_ref(&mut rng).complete()
    }

    fn sample_bits(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let mut adapter = RngAdapter(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        rug::Integer::random_bits(bits, &mut rng).complete()
    }

    fn random_bits_signed(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let mut adapter = RngAdapter(rng);
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
        let mut adapter = RngAdapter(rng);
        let mut rng = rug::rand::ThreadRandState::new_custom(&mut adapter);
        let r = modulo.random_below_ref(&mut rng);
        rug::Assign::assign(self, r);
        self
    }

    fn assign_random_bits(&mut self, bits: u32, rng: &mut impl rand_core::RngCore) -> &mut Self {
        let mut adapter = RngAdapter(rng);
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
        let l_to_le = l.pow_mod_ref(le, self)?.complete();
        let r_to_re = r.pow_mod_ref(re, self)?.complete();
        Some((l_to_le * r_to_re).modulo(self))
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

    fn generate_safe_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Self {
        // Sieve bound grows with size: small primes barely need sieving, while large ones
        // benefit from removing far more composite candidates up front (tuned by benchmark).
        let sieve_limit = if bits <= 512 {
            50_000
        } else if bits <= 1024 {
            200_000
        } else {
            500_000
        };
        /// Width (in bits) of the candidate window scanned per random base.
        const WINDOW_BITS: u32 = 15;
        /// Cheap pre-filter: one Miller-Rabin round rejects almost all composites.
        const FILTER_ROUNDS: u32 = 1;
        /// Final confidence for the accepted Sophie Germain prime `q` (25 as in `mpz_nextprime`).
        const CONFIRM_ROUNDS: u32 = 25;

        let window: usize = 1 << WINDOW_BITS;
        let seed_bits = bits - 1;
        let small_primes = small_odd_primes(sieve_limit);

        loop {
            // Random odd base; the window holds candidates q = base + 2*j, j in [0, window).
            let mut base = rug::Integer::zero();
            base.assign_random_bits(seed_bits, rng);
            base.set_bit(seed_bits - 1, true);
            base |= 1u32;

            // `true` marks a candidate position ruled out by the small-prime sieve.
            let mut ruled_out = vec![false; window];

            for &l in &small_primes {
                let base_l = u64::from(base.mod_u(l as u32));
                let inv2 = l.div_ceil(2); // 2^-1 mod l, for odd l

                // Kill positions where q = base + 2j == 0 (mod l).
                let j0 = ((l - base_l) % l * inv2 % l) as usize;
                let mut idx = j0;
                while idx < window {
                    ruled_out[idx] = true;
                    idx += l as usize;
                }

                // Kill positions where 2q + 1 == 0 (mod l): 4j == -(2*base + 1) (mod l).
                let c = (2 * base_l + 1) % l;
                let jf = ((l - c) % l * inv_mod(4 % l, l) % l) as usize;
                let mut idx = jf;
                while idx < window {
                    ruled_out[idx] = true;
                    idx += l as usize;
                }
            }

            for j in 0..window {
                if ruled_out[j] {
                    continue;
                }
                let q = (&base + 2 * (j as u64)).complete();
                // Cheap filter: one Miller-Rabin round rejects almost all composite `q`
                // before we pay for the full confirmation or touch `p`.
                if q.is_probably_prime(FILTER_ROUNDS) == rug::integer::IsPrime::No {
                    continue;
                }
                let mut p = q.clone();
                p <<= 1;
                p += 1; // p = 2q + 1
                        // Pocklington: `q = (p-1)/2` is a (probable) prime with `q > sqrt(p)`, and
                        // `gcd(2^2 - 1, p) = gcd(3, p) = 1` (3 is in the sieve), so a single base-2
                        // Fermat test is a primality *proof* for `p` given `q` is prime.
                if p.mod_u(3) == 0 {
                    continue; // 3 | p => p composite (defensive; the sieve already drops these)
                }
                let p_minus_1 = (&p - 1i32).complete();
                if !rug::Integer::from(2u32)
                    .pow_mod(&p_minus_1, &p)
                    .unwrap()
                    .is_one()
                {
                    continue;
                }
                // `p` is prime provided `q` is; spend the confidence rounds on `q` only.
                if q.is_probably_prime(CONFIRM_ROUNDS) == rug::integer::IsPrime::No {
                    continue;
                }
                return p;
            }
            // Window exhausted without success: draw a fresh random base.
        }
    }
}

/// Adapts a [`rand_core::RngCore`] to rug's [`rug::rand::ThreadRandGen`].
///
/// Held as a local by each sampling method below; rug's `ThreadRandState`
/// borrows it, so it cannot be returned from a helper without a transparent
/// transmute (the upstream crate used `bytemuck` for that). Keeping it local
/// avoids the dependency and the `unsafe` the workspace forbids.
struct RngAdapter<'a, R: rand_core::RngCore + ?Sized>(&'a mut R);

impl<R: rand_core::RngCore + ?Sized> rug::rand::ThreadRandGen for RngAdapter<'_, R> {
    fn gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}

/// Odd primes below `limit` (sieve of Eratosthenes), used for the double sieve.
fn small_odd_primes(limit: usize) -> Vec<u64> {
    let mut composite = vec![false; limit];
    let mut out = Vec::new();
    for i in 2..limit {
        if !composite[i] {
            if i > 2 {
                out.push(i as u64);
            }
            let mut m = i * i;
            while m < limit {
                composite[m] = true;
                m += i;
            }
        }
    }
    out
}

/// `x^(l-2) mod l == x^-1 mod l` (Fermat; `l` an odd prime, `0 < x < l`).
fn inv_mod(x: u64, l: u64) -> u64 {
    let (mut result, mut base, mut e) = (1u64, x % l, l - 2);
    while e > 0 {
        if e & 1 == 1 {
            result = result * base % l;
        }
        base = base * base % l;
        e >>= 1;
    }
    result
}
