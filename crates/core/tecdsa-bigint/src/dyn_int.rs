use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DynInt(BigUint);

impl Zeroize for DynInt {
    fn zeroize(&mut self) {
        let digits = self.0.to_u32_digits();
        self.0 = BigUint::zero();
        let _ = digits.len();
    }
}

impl DynInt {
    #[must_use]
    pub fn zero() -> Self {
        Self(BigUint::zero())
    }

    #[must_use]
    pub fn one() -> Self {
        Self(BigUint::one())
    }

    #[must_use]
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self(BigUint::from_bytes_be(bytes))
    }

    #[must_use]
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.0.to_bytes_be()
    }

    #[must_use]
    pub fn bits(&self) -> u64 {
        self.0.bits()
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    #[must_use]
    pub fn is_odd(&self) -> bool {
        self.0.bit(0)
    }

    #[must_use]
    pub fn modpow(&self, exp: &Self, modulus: &Self) -> Self {
        Self(self.0.modpow(&exp.0, &modulus.0))
    }

    #[must_use]
    pub fn inner(&self) -> &BigUint {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> BigUint {
        self.0
    }
}

impl From<u64> for DynInt {
    fn from(v: u64) -> Self {
        Self(BigUint::from(v))
    }
}

impl From<BigUint> for DynInt {
    fn from(v: BigUint) -> Self {
        Self(v)
    }
}

impl std::ops::Add for &DynInt {
    type Output = DynInt;
    fn add(self, rhs: Self) -> DynInt {
        DynInt(&self.0 + &rhs.0)
    }
}

impl std::ops::Sub for &DynInt {
    type Output = DynInt;
    fn sub(self, rhs: Self) -> DynInt {
        DynInt(&self.0 - &rhs.0)
    }
}

impl std::ops::Mul for &DynInt {
    type Output = DynInt;
    fn mul(self, rhs: Self) -> DynInt {
        DynInt(&self.0 * &rhs.0)
    }
}

impl std::ops::Rem for DynInt {
    type Output = DynInt;
    fn rem(self, rhs: Self) -> DynInt {
        DynInt(self.0 % rhs.0)
    }
}

impl std::ops::Shr<u64> for &DynInt {
    type Output = DynInt;
    fn shr(self, rhs: u64) -> DynInt {
        DynInt(&self.0 >> rhs)
    }
}
