use std::fmt;

use crate::party::PartyId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamError {
    ZeroParties,
    InvalidThreshold { n: u16, t: u16 },
    PartyCountMismatch { expected: u16, got: usize },
    DuplicatePartyId(PartyId),
    LocalPartyNotInSet(PartyId),
}

impl fmt::Display for ParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroParties => write!(f, "n must be > 0"),
            Self::InvalidThreshold { n, t } => {
                write!(f, "threshold t={t} must satisfy 1 <= t <= n={n}")
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
        if t == 0 || t > n {
            return Err(ParamError::InvalidThreshold { n, t });
        }
        Ok(Self { n, t })
    }

    pub const fn n(self) -> u16 {
        self.n
    }

    pub const fn t(self) -> u16 {
        self.t
    }

    pub const fn reconstruct_threshold(self) -> u16 {
        self.t
    }

    pub const fn max_corruptions(self) -> u16 {
        self.t - 1
    }
}

impl fmt::Display for Threshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(n={}, t={})", self.n, self.t)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecurityLevel {
    TestOnly,
    Bits112,
    Bits128,
    Bits192,
    Bits256,
}

impl SecurityLevel {
    pub const fn paillier_modulus_bits(self) -> u32 {
        match self {
            Self::TestOnly => 1024,
            Self::Bits112 => 2048,
            Self::Bits128 => 3072,
            Self::Bits192 => 7680,
            Self::Bits256 => 15360,
        }
    }

    pub const fn cl_discriminant_bits(self) -> u32 {
        match self {
            Self::TestOnly => 300,
            Self::Bits112 => 1348,
            Self::Bits128 => 1827,
            Self::Bits192 => 3598,
            Self::Bits256 => 5971,
        }
    }

    pub const fn jl_modulus_bits(self) -> u32 {
        match self {
            Self::TestOnly => 1024,
            Self::Bits112 => 2048,
            Self::Bits128 => 3072,
            Self::Bits192 => 7680,
            Self::Bits256 => 15360,
        }
    }

    pub const fn statistical_security(self) -> u32 {
        match self {
            Self::TestOnly => 40,
            Self::Bits112 | Self::Bits128 => 42,
            Self::Bits192 | Self::Bits256 => 66,
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_new_semantics() {
        let threshold = Threshold::new(5, 3).unwrap();
        assert_eq!(threshold.n(), 5);
        assert_eq!(threshold.t(), 3);
        assert_eq!(threshold.reconstruct_threshold(), 3);
        assert_eq!(threshold.max_corruptions(), 2);
    }

    #[test]
    fn threshold_2_of_3() {
        let threshold = Threshold::new(3, 2).unwrap();
        assert_eq!(threshold.n(), 3);
        assert_eq!(threshold.t(), 2);
        assert_eq!(threshold.reconstruct_threshold(), 2);
        assert_eq!(threshold.max_corruptions(), 1);
    }

    #[test]
    fn threshold_n_of_n() {
        let threshold = Threshold::new(3, 3).unwrap();
        assert_eq!(threshold.reconstruct_threshold(), 3);
        assert_eq!(threshold.max_corruptions(), 2);
    }

    #[test]
    fn rejects_t_zero() {
        assert!(Threshold::new(3, 0).is_err());
    }

    #[test]
    fn rejects_t_greater_than_n() {
        assert!(Threshold::new(3, 4).is_err());
    }

    #[test]
    fn rejects_n_zero() {
        assert!(Threshold::new(0, 0).is_err());
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
        let threshold = Threshold::new(3, 2).unwrap();
        let parties = vec![PartyId(1), PartyId(2), PartyId(3)];
        assert!(PartySet::new(PartyId(4), parties, threshold).is_err());
    }

    #[test]
    fn party_set_rejects_wrong_n() {
        let threshold = Threshold::new(3, 2).unwrap();
        let parties = vec![PartyId(1), PartyId(2)];
        assert!(PartySet::new(PartyId(1), parties, threshold).is_err());
    }

    #[test]
    fn party_set_rejects_duplicates() {
        let threshold = Threshold::new(3, 2).unwrap();
        let parties = vec![PartyId(1), PartyId(1), PartyId(2)];
        assert!(PartySet::new(PartyId(1), parties, threshold).is_err());
    }

    #[test]
    fn party_set_valid() {
        let threshold = Threshold::new(3, 2).unwrap();
        let parties = vec![PartyId(3), PartyId(1), PartyId(2)];
        let ps = PartySet::new(PartyId(2), parties, threshold).unwrap();
        assert_eq!(ps.local_party(), PartyId(2));
        assert_eq!(ps.parties(), &[PartyId(1), PartyId(2), PartyId(3)]);
        assert_eq!(ps.reconstruct_threshold(), 2);
    }

    #[test]
    fn threshold_display() {
        let t = Threshold::new(5, 3).unwrap();
        assert_eq!(format!("{t}"), "(n=5, t=3)");
    }

    #[test]
    fn security_level_display() {
        assert_eq!(format!("{}", SecurityLevel::Bits128), "128-bit");
        assert_eq!(format!("{}", SecurityLevel::TestOnly), "test-only");
    }
}
