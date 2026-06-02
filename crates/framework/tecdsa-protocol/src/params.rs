// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical parameter types for threshold ECDSA protocols.
//!
//! `t` always means the corruption threshold (maximum number of corrupted parties).
//! The reconstruction/signing quorum is `t + 1`.

use crate::party::PartyId;
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamError {
    ZeroParties,
    CorruptionThresholdTooLarge { n: u16, t: u16 },
    PartyCountMismatch { expected: u16, got: usize },
    DuplicatePartyId(PartyId),
    LocalPartyNotInSet(PartyId),
}

impl fmt::Display for ParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroParties => write!(f, "n must be > 0"),
            Self::CorruptionThresholdTooLarge { n, t } => {
                write!(f, "corruption threshold t={t} must be < n={n}")
            }
            Self::PartyCountMismatch { expected, got } => {
                write!(f, "expected {expected} parties, got {got}")
            }
            Self::DuplicatePartyId(id) => write!(f, "duplicate party ID: {id}"),
            Self::LocalPartyNotInSet(id) => write!(f, "local party {id} not in party set"),
        }
    }
}

impl std::error::Error for ParamError {}

// ---------------------------------------------------------------------------
// Threshold
// ---------------------------------------------------------------------------

/// Protocol threshold parameters.
///
/// `t` is the corruption threshold: the maximum number of parties that may be
/// corrupted. The reconstruction/signing quorum is `t + 1`.
///
/// For example, `Threshold::new(3, 1)` means 3 parties, at most 1 corrupted,
/// any 2 can sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Threshold {
    n: u16,
    t: u16,
}

impl Threshold {
    pub fn new(n: u16, t: u16) -> Result<Self, ParamError> {
        if n == 0 {
            return Err(ParamError::ZeroParties);
        }
        if t >= n {
            return Err(ParamError::CorruptionThresholdTooLarge { n, t });
        }
        Ok(Self { n, t })
    }

    /// Total number of parties.
    pub const fn n(self) -> u16 {
        self.n
    }

    /// Corruption threshold (max corrupted parties).
    pub const fn t(self) -> u16 {
        self.t
    }

    /// Reconstruction/signing quorum = t + 1.
    pub const fn reconstruct_threshold(self) -> u16 {
        self.t + 1
    }
}

impl fmt::Display for Threshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(n={}, t={})", self.n, self.t)
    }
}

// ---------------------------------------------------------------------------
// SecurityLevel
// ---------------------------------------------------------------------------

/// Cryptographic security level, determining parameter sizes across all
/// primitive families (RSA/Paillier, class-group, Joye-Libert, OT).
///
/// Parameter table (from BICYCL seclevel.inl):
///
/// | Level | Paillier N | CL |Delta_K| | JL N | lambda_s | Curve |
/// |-------|------------|--------------|------|----------|---------|
/// | 112 | 2048-bit | 1348-bit | 2048 | 42 | secp256k1 |
/// | 128 | 3072-bit | 1827-bit | 3072 | 42 | secp256k1 |
/// | 192 | 7680-bit | 3598-bit | - | 66 | - |
/// | 256 | 15360-bit | 5971-bit | - | 66 | - |
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecurityLevel {
    /// Small parameters for fast unit tests. NOT for benchmarks or production.
    TestOnly,
    /// 112-bit security: 2048-bit Paillier, 1348-bit CL discriminant.
    Bits112,
    /// 128-bit security: 3072-bit Paillier, 1827-bit CL discriminant.
    Bits128,
    /// 192-bit security (reserved).
    Bits192,
    /// 256-bit security (reserved).
    Bits256,
}

impl SecurityLevel {
    /// RSA/Paillier modulus bit-length.
    pub const fn paillier_modulus_bits(self) -> u32 {
        match self {
            Self::TestOnly => 1024,
            Self::Bits112 => 2048,
            Self::Bits128 => 3072,
            Self::Bits192 => 7680,
            Self::Bits256 => 15360,
        }
    }

    /// Class-group discriminant bit-length |Delta_K|.
    pub const fn cl_discriminant_bits(self) -> u32 {
        match self {
            Self::TestOnly => 300,
            Self::Bits112 => 1348,
            Self::Bits128 => 1827,
            Self::Bits192 => 3598,
            Self::Bits256 => 5971,
        }
    }

    /// Joye-Libert modulus bit-length.
    pub const fn jl_modulus_bits(self) -> u32 {
        match self {
            Self::TestOnly => 1024,
            Self::Bits112 => 2048,
            Self::Bits128 => 3072,
            Self::Bits192 => 7680,
            Self::Bits256 => 15360,
        }
    }

    /// Statistical security parameter lambda_s.
    pub const fn statistical_security(self) -> u32 {
        match self {
            Self::TestOnly => 40,
            Self::Bits112 | Self::Bits128 => 42,
            Self::Bits192 | Self::Bits256 => 66,
        }
    }

    /// OT extension security parameter kappa.
    pub const fn ot_kappa(self) -> u32 {
        match self {
            Self::TestOnly => 128,
            Self::Bits112 => 224,
            Self::Bits128 => 256,
            Self::Bits192 => 384,
            Self::Bits256 => 512,
        }
    }
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TestOnly => write!(f, "test-only"),
            Self::Bits112 => write!(f, "112-bit"),
            Self::Bits128 => write!(f, "128-bit"),
            Self::Bits192 => write!(f, "192-bit"),
            Self::Bits256 => write!(f, "256-bit"),
        }
    }
}

// ---------------------------------------------------------------------------
// PartySet
// ---------------------------------------------------------------------------

/// Validated set of protocol participants with threshold parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartySet {
    local_party: PartyId,
    parties: Vec<PartyId>,
    threshold: Threshold,
}

impl PartySet {
    pub fn new(
        local_party: PartyId,
        mut parties: Vec<PartyId>,
        threshold: Threshold,
    ) -> Result<Self, ParamError> {
        if parties.len() != threshold.n() as usize {
            return Err(ParamError::PartyCountMismatch {
                expected: threshold.n(),
                got: parties.len(),
            });
        }
        parties.sort_by_key(|p| p.0);
        for w in parties.windows(2) {
            if w[0] == w[1] {
                return Err(ParamError::DuplicatePartyId(w[0]));
            }
        }
        if !parties.contains(&local_party) {
            return Err(ParamError::LocalPartyNotInSet(local_party));
        }
        Ok(Self {
            local_party,
            parties,
            threshold,
        })
    }

    pub fn local_party(&self) -> PartyId {
        self.local_party
    }

    pub fn parties(&self) -> &[PartyId] {
        &self.parties
    }

    pub fn threshold(&self) -> Threshold {
        self.threshold
    }

    pub fn reconstruct_threshold(&self) -> u16 {
        self.threshold.reconstruct_threshold()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstruct_threshold_is_t_plus_one() {
        let threshold = Threshold::new(3, 1).unwrap();
        assert_eq!(threshold.n(), 3);
        assert_eq!(threshold.t(), 1);
        assert_eq!(threshold.reconstruct_threshold(), 2);
    }

    #[test]
    fn rejects_t_ge_n() {
        assert!(Threshold::new(3, 3).is_err());
        assert!(Threshold::new(0, 0).is_err());
    }

    #[test]
    fn rejects_t_eq_n_minus_one_is_valid() {
        // t = n-1 is valid (all but one corrupted)
        assert!(Threshold::new(3, 2).is_ok());
    }

    #[test]
    fn security_level_paillier_bits() {
        assert_eq!(SecurityLevel::Bits112.paillier_modulus_bits(), 2048);
        assert_eq!(SecurityLevel::Bits128.paillier_modulus_bits(), 3072);
    }

    #[test]
    fn security_level_cl_bits() {
        assert_eq!(SecurityLevel::Bits112.cl_discriminant_bits(), 1348);
        assert_eq!(SecurityLevel::Bits128.cl_discriminant_bits(), 1827);
    }

    #[test]
    fn party_set_requires_local_party() {
        let threshold = Threshold::new(3, 1).unwrap();
        let parties = vec![PartyId(1), PartyId(2), PartyId(3)];
        assert!(PartySet::new(PartyId(4), parties, threshold).is_err());
    }

    #[test]
    fn party_set_rejects_wrong_n() {
        let threshold = Threshold::new(3, 1).unwrap();
        let parties = vec![PartyId(1), PartyId(2)];
        assert!(PartySet::new(PartyId(1), parties, threshold).is_err());
    }

    #[test]
    fn party_set_rejects_duplicates() {
        let threshold = Threshold::new(3, 1).unwrap();
        let parties = vec![PartyId(1), PartyId(1), PartyId(2)];
        assert!(PartySet::new(PartyId(1), parties, threshold).is_err());
    }

    #[test]
    fn party_set_valid() {
        let threshold = Threshold::new(3, 1).unwrap();
        let parties = vec![PartyId(3), PartyId(1), PartyId(2)];
        let ps = PartySet::new(PartyId(2), parties, threshold).unwrap();
        assert_eq!(ps.local_party(), PartyId(2));
        assert_eq!(ps.parties(), &[PartyId(1), PartyId(2), PartyId(3)]);
        assert_eq!(ps.reconstruct_threshold(), 2);
    }

    #[test]
    fn threshold_display() {
        let t = Threshold::new(5, 2).unwrap();
        assert_eq!(format!("{t}"), "(n=5, t=2)");
    }

    #[test]
    fn security_level_display() {
        assert_eq!(format!("{}", SecurityLevel::Bits128), "128-bit");
        assert_eq!(format!("{}", SecurityLevel::TestOnly), "test-only");
    }
}
