#![allow(missing_docs)]

use alloc::{string::String, vec::Vec};

use rug::Complete;
/// Big integer type used in this crate.
///
/// This is a plain re-export of [`rug::Integer`] rather than a newtype, so that
/// the whole workspace shares a single big-integer type. The helper methods that
/// used to be inherent on the newtype now live on the [`BigIntExt`] extension
/// trait below.
///
/// Note that methods which would collide with an inherent `rug::Integer` method
/// are deliberately *not* on the trait: Rust resolves inherent methods before
/// trait methods, so such a method could never be called and would silently
/// diverge from the inherent one. Use rug's own API for those.
pub use rug::Integer;

use crate::backend::{inv_mod, small_odd_primes};

/// Extension methods on [`Integer`] used throughout this crate.
///
/// Import this trait to bring them into scope:
/// ```rust
/// use fast_paillier::backend::BigIntExt;
/// ```
pub trait BigIntExt: Sized {
    /// Converts to bytes, with bytes representing _least_ significant base256
    /// digits appearing first. Discards the sign
    ///
    /// ## Example
    /// ```rust
    /// # use fast_paillier::backend::rug::Integer;
    /// let x = Integer::from(0x11223344);
    /// assert_eq!(x.to_bytes_lsf(), vec![0x44, 0x33, 0x22, 0x11]);
    /// ```
    fn to_bytes_lsf(&self) -> Vec<u8>;
    /// Converts to bytes, with bytes representing _most_ significant base256
    /// digits appearing first. Discards the sign
    ///
    /// ## Example
    /// ```rust
    /// # use fast_paillier::backend::rug::Integer;
    /// let x = Integer::from(0x11223344);
    /// assert_eq!(x.to_bytes_msf(), vec![0x11, 0x22, 0x33, 0x44]);
    /// ```
    fn to_bytes_msf(&self) -> Vec<u8>;
    /// Converts to bytes, with bytes representing _most_ significant base256
    /// digits appearing first
    ///
    /// ## Example
    /// ```rust
    /// # use fast_paillier::backend::{rug::Integer, Sign};
    /// let x = Integer::from(-0x11223344);
    /// assert_eq!(
    ///     x.to_bytes_msf_signed(),
    ///     (vec![0x11, 0x22, 0x33, 0x44], Sign::Negative)
    /// );
    /// ```
    fn to_bytes_msf_signed(&self) -> (Vec<u8>, super::Sign);
    /// Converts bytes to Integer. Inverse of [`Integer::to_bytes_msf`]
    fn from_bytes_msf(bytes: &[u8]) -> Self;
    /// Converts bytes to Integer. Inverse of [`Integer::to_bytes_msf_signed`]
    fn from_bytes_msf_signed(bytes: &[u8], sign: super::Sign) -> Self;
    /// Returns a string representation of the number for the specified radix
    fn to_str_radix(&self, radix: u16) -> String;

    fn one() -> Self;
    fn zero() -> Self;
    fn is_one(&self) -> bool;

    fn sign(&self) -> super::Sign;

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

    fn to_bytes_msf_signed(&self) -> (Vec<u8>, super::Sign) {
        (
            self.to_digits(rug::integer::Order::Msf),
            match self.cmp0() {
                core::cmp::Ordering::Less => super::Sign::Negative,
                _ => super::Sign::NonNegative,
            },
        )
    }

    fn from_bytes_msf(bytes: &[u8]) -> Self {
        rug::Integer::from_digits(bytes, rug::integer::Order::Msf)
    }

    fn from_bytes_msf_signed(bytes: &[u8], sign: super::Sign) -> Self {
        let r = rug::Integer::from_digits(bytes, rug::integer::Order::Msf);
        if sign == super::Sign::Negative {
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

    fn sign(&self) -> super::Sign {
        match self.cmp0() {
            core::cmp::Ordering::Less => super::Sign::Negative,
            _ => super::Sign::NonNegative,
        }
    }

    fn significant_dwords(&self) -> usize {
        self.significant_digits::<u32>()
    }

    fn sample_below(self, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
        self.random_below(&mut rng)
    }

    fn sample_below_ref(&self, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
        self.random_below_ref(&mut rng).complete()
    }

    fn sample_bits(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
        rug::Integer::random_bits(bits, &mut rng).complete()
    }

    fn random_bits_signed(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
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
        let mut rng = external_rand(rng);
        let r = modulo.random_below_ref(&mut rng);
        rug::Assign::assign(self, r);
        self
    }

    fn assign_random_bits(&mut self, bits: u32, rng: &mut impl rand_core::RngCore) -> &mut Self {
        let mut rng = external_rand(rng);
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
        let l_to_le = l.pow_mod_ref(&le, &self)?.complete();
        let r_to_re = r.pow_mod_ref(&re, &self)?.complete();
        let r = (l_to_le * r_to_re).modulo(&self);
        Some(r)
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
            let mut ruled_out = alloc::vec![false; window];

            for &l in &small_primes {
                let base_l = u64::from(base.mod_u(l as u32));
                let inv2 = (l + 1) / 2; // 2^-1 mod l, for odd l

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

/// Wraps any randomness source that implements [`rand_core::RngCore`] and makes
/// it compatible with [`rug::rand`].
pub fn external_rand(rng: &mut impl rand_core::RngCore) -> rug::rand::ThreadRandState<'_> {
    use bytemuck::TransparentWrapper;

    #[derive(TransparentWrapper)]
    #[repr(transparent)]
    pub struct ExternalRand<R>(R);

    impl<R: rand_core::RngCore> rug::rand::ThreadRandGen for ExternalRand<R> {
        fn gen(&mut self) -> u32 {
            self.0.next_u32()
        }
    }

    rug::rand::ThreadRandState::new_custom(ExternalRand::wrap_mut(rng))
}

#[cfg(feature = "quickcheck")]
impl quickcheck::Arbitrary for Integer {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let bytes = Vec::<u8>::arbitrary(g);
        let sign = super::Sign::arbitrary(g);
        Integer::from_bytes_msf_signed(&bytes, sign)
    }

    fn shrink(&self) -> alloc::boxed::Box<dyn Iterator<Item = Self>> {
        let mut prev = self.clone();
        alloc::boxed::Box::new(core::iter::from_fn(move || {
            if prev.cmp0().is_eq() {
                None
            } else {
                prev >>= 1;
                Some(prev.clone())
            }
        }))
    }
}
