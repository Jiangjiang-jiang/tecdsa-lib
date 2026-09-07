// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2023 Dfns <https://github.com/LFDT-Lockness/cggmp21>
use rug::Integer;
use tecdsa_bigint::BigIntExt;

/// Auxiliary data known to both prover and verifier
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Aux {
    /// ring-pedersen parameter
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub s: Integer,
    /// ring-pedersen parameter
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub t: Integer,
    /// N^ in paper
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub rsa_modulo: Integer,
}

impl Aux {
    /// Returns `s^x t^y mod rsa_modulo`
    pub fn combine(&self, x: &Integer, y: &Integer) -> Result<Integer, BadExponent> {
        self.rsa_modulo
            .combine(&self.s, x, &self.t, y)
            .ok_or_else(BadExponent::undefined)
    }

    /// Returns `x^e mod rsa_modulo`
    pub fn pow_mod(&self, x: &Integer, e: &Integer) -> Result<Integer, BadExponent> {
        x.pow_mod_ref(e, &self.rsa_modulo)
            .map(Integer::from)
            .ok_or_else(BadExponent::undefined)
    }

    /// Checks if `x` is in multiplicative group Z<super>*</super><sub>N</sub> where `N = ` [`rsa_modulo`](Self::rsa_modulo)
    pub fn is_in_mult_group(&self, x: &Integer) -> bool {
        x.in_mult_group_of(&self.rsa_modulo)
    }

    /// Returns a stripped version of `Aux` that contains only public data which can be digested
    /// via [`udigest::Digestable`]
    pub fn digest_public_data(&self) -> impl udigest::Digestable {
        udigest::inline_struct!("paillier_zk.aux" {
            s: udigest::Bytes(self.s.to_bytes_msf()),
            t: udigest::Bytes(self.t.to_bytes_msf()),
            rsa_modulo: udigest::Bytes(self.rsa_modulo.to_bytes_msf()),
        })
    }
}

/// Error indicating that proof is invalid
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof(
    #[source]
    #[from]
    InvalidProofReason,
);

/// Reason for failure. If the proof fails, you should only be interested in a
/// reason for debugging purposes
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum InvalidProofReason {
    /// One equality doesn't hold. Parameterized by equality index
    #[error("equality check failed {0}")]
    EqualityCheck(usize),
    /// Check that integer belongs to multiplicative group failed. Parameterized by equality index
    #[error("mult group check failed {0}")]
    MultGroupCheck(usize),
    /// One range check doesn't hold. Parameterized by check index
    #[error("range check failed {0}")]
    RangeCheck(usize),
    /// Encryption of supplied data failed when attempting to verify
    #[error("encryption failed")]
    Encryption,
    #[error("paillier encryption failed")]
    PaillierEnc,
    #[error("paillier homomorphic op failed")]
    PaillierOp,
    /// Failed to evaluate powmod
    #[error("powmod failed")]
    ModPow,
    /// Paillier-Blum modulus is prime
    #[error("modulus is prime")]
    ModulusIsPrime,
    /// Paillier-Blum modulus is even
    #[error("modulus is even")]
    ModulusIsEven,
    /// Proof's z value in n-th power does not equal commitment value
    #[error("incorrect nth root")]
    IncorrectNthRoot,
    /// Proof's x value in 4-th power does not equal commitment value
    #[error("incorrect 4th root")]
    IncorrectFourthRoot,
    /// Conversion failed (e.g. from u32 to usize)
    #[error("conversion failed")]
    Conversion,
}

impl InvalidProof {
    #[cfg(test)]
    pub(crate) fn reason(&self) -> InvalidProofReason {
        self.0
    }
}

impl From<BadExponent> for InvalidProof {
    fn from(_err: BadExponent) -> Self {
        InvalidProofReason::ModPow.into()
    }
}

impl From<PaillierError> for InvalidProof {
    fn from(_err: PaillierError) -> Self {
        InvalidProof(InvalidProofReason::Encryption)
    }
}

/// Error indicating that encryption failed
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("paillier encryption failed")]
pub struct PaillierError;

/// Error indicating that computation cannot be evaluated because of bad exponent
///
/// Returned by [`Aux::pow_mod`] and other functions that do exponentiation internally
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error(transparent)]
pub struct BadExponent(#[from] BadExponentReason);

impl BadExponent {
    /// Constructs an error that exponent is undefined
    pub fn undefined() -> Self {
        Self(BadExponentReason::Undefined)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum BadExponentReason {
    #[error("exponent is undefined")]
    Undefined,
}

/// Returns `Err(err)` if `assertion` is false
pub fn fail_if<E>(err: E, assertion: bool) -> Result<(), E> {
    if assertion {
        Ok(())
    } else {
        Err(err)
    }
}

/// Returns `Err(err)` if `lhs != rhs`
pub fn fail_if_ne<T: PartialEq, E>(err: E, lhs: T, rhs: T) -> Result<(), E> {
    if lhs == rhs {
        Ok(())
    } else {
        Err(err)
    }
}

pub mod encoding {
    use tecdsa_bigint::{BigIntExt, Sign};

    /// Digests a big integer as a sign byte followed by the big-endian magnitude.
    ///
    /// The sign byte is load-bearing: `to_bytes_msf` returns the magnitude only,
    /// so encoding it alone would digest `x` and `-x` identically. Every value
    /// reached today is non-negative (ciphertexts mod `N^2`, Ring-Pedersen
    /// commitments mod `N^`, moduli, the curve order), but nothing enforces
    /// that, and a Fiat-Shamir transcript must bind its inputs injectively.
    /// Since the magnitude is minimal big-endian, `(sign, magnitude)` is
    /// injective over the integers.
    pub struct Integer;
    impl udigest::DigestAs<rug::Integer> for Integer {
        fn digest_as<B: udigest::Buffer>(
            value: &rug::Integer,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            let (magnitude, sign) = value.to_bytes_msf_signed();
            let mut bytes = Vec::with_capacity(magnitude.len() + 1);
            bytes.push(u8::from(sign == Sign::Negative));
            bytes.extend_from_slice(&magnitude);
            encoder.encode_leaf_value(bytes);
        }
    }

    /// Digests a curve point by its canonical (compressed) encoding.
    ///
    /// Replaces `generic-ec`'s own `Digestable` impl. The encoding is fixed
    /// width and canonical, so it is injective on the point set.
    pub struct Point;
    impl<G: elliptic_curve::group::GroupEncoding> udigest::DigestAs<G> for Point {
        fn digest_as<B: udigest::Buffer>(value: &G, encoder: udigest::encoding::EncodeValue<B>) {
            encoder.encode_leaf_value(value.to_bytes());
        }
    }

    /// Digests any encryption key by its modulus.
    pub struct AnyEncryptionKey;
    impl udigest::DigestAs<&dyn crate::scheme::AnyEncryptionKey> for AnyEncryptionKey {
        fn digest_as<B: udigest::Buffer>(
            value: &&dyn crate::scheme::AnyEncryptionKey,
            encoder: udigest::encoding::EncodeValue<B>,
        ) {
            Integer::digest_as(value.n(), encoder);
        }
    }
}

#[cfg(test)]
mod encoding_tests {
    use rug::Integer;

    use super::encoding;

    #[derive(udigest::Digestable)]
    struct Wrap {
        #[udigest(as = encoding::Integer)]
        v: Integer,
    }

    fn hash(v: Integer) -> Vec<u8> {
        udigest::hash::<sha2::Sha256>(&Wrap { v }).to_vec()
    }

    /// `to_bytes_msf` drops the sign, so digesting the magnitude alone made
    /// `x` and `-x` collide. A Fiat-Shamir transcript has to bind its inputs
    /// injectively, so the encoding carries a sign byte.
    #[test]
    fn sign_is_bound() {
        assert_ne!(hash(Integer::from(12345)), hash(Integer::from(-12345)));
        assert_ne!(hash(Integer::from(1)), hash(Integer::from(-1)));
    }

    /// Zero has an empty magnitude and is not negative, so it must not collide
    /// with anything else.
    #[test]
    fn zero_is_distinct() {
        assert_ne!(hash(Integer::ZERO), hash(Integer::from(1)));
        assert_ne!(hash(Integer::ZERO), hash(Integer::from(-1)));
    }

    /// The magnitude is minimal big-endian, so no two distinct integers share
    /// an encoding.
    #[test]
    fn distinct_values_do_not_collide() {
        let mut seen = std::collections::HashSet::new();
        for i in -260i32..=260 {
            assert!(seen.insert(hash(Integer::from(i))), "collision at {i}");
        }
    }
}

/// A common logic shared across tests and doctests
#[cfg(test)]
pub mod test {
    use rug::{Complete, Integer};
    use tecdsa_bigint::BigIntExt;

    pub fn random_key<R: rand_core::RngCore>(rng: &mut R) -> Option<crate::scheme::DecryptionKey> {
        let p = generate_blum_prime(rng, 1536);
        let q = generate_blum_prime(rng, 1536);
        crate::scheme::DecryptionKey::from_primes(p, q).ok()
    }

    pub fn aux<R: rand_core::RngCore>(rng: &mut R) -> super::Aux {
        let p = generate_blum_prime(rng, 1536);
        let q = generate_blum_prime(rng, 1536);
        let n = (&p * &q).complete();

        let (s, t) = {
            let phi_n = (p - 1u8) * (q - 1u8);
            let r = Integer::sample_in_mult_group_of(rng, &n);
            let lambda = phi_n.sample_below(rng);

            let t = r.square().modulo(&n);
            let s = Integer::from(t.pow_mod_ref(&lambda, &n).unwrap());

            (s, t)
        };

        super::Aux {
            s,
            t,
            rsa_modulo: n,
        }
    }

    pub fn generate_blum_prime(rng: &mut impl rand_core::RngCore, bits_size: u32) -> Integer {
        loop {
            let n = Integer::generate_prime(rng, bits_size);
            if n.mod_u(4) == 3 {
                break n;
            }
        }
    }
}

#[cfg(test)]
mod _test {
    use rug::Integer;
    use tecdsa_bigint::BigIntExt;

    #[test]
    fn test_from_rng_half_pm_bounds() {
        let mut rng = rand_dev::DevRng::new();
        // Testing even case
        let range = Integer::from(10);
        let upper_bound = Integer::from(&range >> 1);
        let lower_bound = Integer::from(-&upper_bound);
        let mut min = Integer::from(0);
        let mut max = Integer::from(0);

        // Obtaining lower and upper bounds
        for _ in 0..10000 {
            let value = Integer::from_rng_half_pm(&mut rng, &range);
            if value > max {
                max.clone_from(&value);
            }
            if value < min {
                min.clone_from(&value);
            }
        }

        assert_eq!(
            min, lower_bound,
            "Minimum value {min} did not match expected lower bound {lower_bound}"
        );
        assert_eq!(
            max, upper_bound,
            "Maximum value {max} did not match expected upper bound {upper_bound}"
        );

        // Testing odd case
        let range = Integer::from(9);
        let range_minus_one = &range - Integer::one();
        let upper_bound = range_minus_one >> 1;
        let lower_bound = Integer::from(-&upper_bound);
        let mut min = Integer::from(0);
        let mut max = Integer::from(0);

        // Obtaining lower and upper bounds
        for _ in 0..10000 {
            let value = Integer::from_rng_half_pm(&mut rng, &range);
            if value > max {
                max.clone_from(&value);
            }
            if value < min {
                min.clone_from(&value);
            }
        }

        assert_eq!(
            min, lower_bound,
            "Minimum value {min} did not match expected lower bound {lower_bound}"
        );
        assert_eq!(
            max, upper_bound,
            "Maximum value {max} did not match expected upper bound {upper_bound}"
        );
    }

    #[test]
    fn test_is_in_half_pm() {
        // Testing even case
        let range = Integer::from(10);
        let a_1 = Integer::from(-6);
        let a_2 = Integer::from(-5);
        let a_3 = Integer::from(5);
        let a_4 = Integer::from(6);
        assert!(
            !a_1.is_in_half_pm(&range),
            "{a_1} should be outside [-range/2,range/2]"
        );
        assert!(
            a_2.is_in_half_pm(&range),
            "{a_2} should be in [-range/2,range/2]"
        );
        assert!(
            a_3.is_in_half_pm(&range),
            "{a_3} should be in [-range/2,range/2]"
        );
        assert!(
            !a_4.is_in_half_pm(&range),
            "{a_4} should be outside [-range/2,range/2]"
        );

        // Testing odd case
        let range = Integer::from(9);
        let a_1 = Integer::from(-5);
        let a_2 = Integer::from(-4);
        let a_3 = Integer::from(4);
        let a_4 = Integer::from(5);
        assert!(
            !a_1.is_in_half_pm(&range),
            "{a_1} should be outside [-(range-1)/2,(range-1)/2]"
        );
        assert!(
            a_2.is_in_half_pm(&range),
            "{a_1} should be in [-(range-1)/2,(range-1)/2]"
        );
        assert!(
            a_3.is_in_half_pm(&range),
            "{a_3} should be in [-(range-1)/2,(range-1)/2]"
        );
        assert!(
            !a_4.is_in_half_pm(&range),
            "{a_4} should be outside [-(range-1)/2,(range-1)/2]"
        );
    }
}
