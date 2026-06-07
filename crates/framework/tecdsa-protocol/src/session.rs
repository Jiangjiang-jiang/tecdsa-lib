// SPDX-License-Identifier: MIT OR Apache-2.0
use serde::{Deserialize, Serialize};

use crate::{
    params::{ParamError, PartySet, Threshold},
    party::{PartyId, PartyInfo},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_id: SessionId,
    pub local_party: PartyInfo,
    pub parties: Vec<PartyId>,
}

impl SessionConfig {
    /// Create a SessionConfig from canonical parameter types.
    ///
    /// `PartyInfo.threshold` is set to the reconstruction threshold `t`
    /// (number of parties required to sign).
    pub fn from_party_set(session_id: SessionId, party_set: &PartySet) -> Self {
        let local_id = party_set.local_party();
        let parties = party_set.parties().to_vec();
        let index = parties.iter().position(|p| *p == local_id).unwrap() as u16;
        Self {
            session_id,
            local_party: PartyInfo {
                id: local_id,
                index: index + 1, // 1-based
                total: party_set.threshold().n(),
                threshold: party_set.threshold().t(),
            },
            parties,
        }
    }

    /// Extract a `Threshold` from the legacy fields.
    ///
    /// Interprets `local_party.threshold` as the reconstruction threshold `t`.
    pub fn try_threshold(&self) -> Result<Threshold, ParamError> {
        Threshold::new(self.local_party.total, self.local_party.threshold)
    }

    /// Maximum tolerated corruptions = t - 1.
    ///
    /// Panics if legacy fields are invalid. Prefer [`try_threshold`](Self::try_threshold)
    /// in fallible contexts.
    pub fn max_corruptions(&self) -> u16 {
        self.try_threshold()
            .expect("SessionConfig has invalid threshold fields")
            .max_corruptions()
    }

    /// Reconstruction/signing threshold `t` (number of parties required).
    ///
    /// This is the value stored in `local_party.threshold`.
    pub fn reconstruct_threshold(&self) -> u16 {
        self.local_party.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{PartySet, Threshold};

    #[test]
    fn from_party_set_derives_fields() {
        let threshold = Threshold::new(3, 2).unwrap();
        let party_set = PartySet::new(
            PartyId(2),
            vec![PartyId(1), PartyId(2), PartyId(3)],
            threshold,
        )
        .unwrap();

        let config = SessionConfig::from_party_set(SessionId([42u8; 32]), &party_set);

        assert_eq!(config.local_party.id, PartyId(2));
        assert_eq!(config.local_party.total, 3);
        assert_eq!(config.local_party.threshold, 2);
        assert_eq!(config.parties.len(), 3);
    }

    #[test]
    fn try_threshold_roundtrips() {
        let threshold = Threshold::new(3, 2).unwrap();
        let party_set = PartySet::new(
            PartyId(1),
            vec![PartyId(1), PartyId(2), PartyId(3)],
            threshold,
        )
        .unwrap();

        let config = SessionConfig::from_party_set(SessionId([0u8; 32]), &party_set);
        let recovered = config.try_threshold().unwrap();
        assert_eq!(recovered.n(), 3);
        assert_eq!(recovered.t(), 2);
        assert_eq!(recovered.reconstruct_threshold(), 2);
        assert_eq!(recovered.max_corruptions(), 1);
    }

    #[test]
    fn corruption_and_reconstruct_accessors() {
        let threshold = Threshold::new(5, 3).unwrap();
        let party_set = PartySet::new(
            PartyId(1),
            vec![PartyId(1), PartyId(2), PartyId(3), PartyId(4), PartyId(5)],
            threshold,
        )
        .unwrap();

        let config = SessionConfig::from_party_set(SessionId([0u8; 32]), &party_set);
        assert_eq!(config.max_corruptions(), 2);
        assert_eq!(config.reconstruct_threshold(), 3);
    }

    #[test]
    fn try_threshold_rejects_zero_reconstruct() {
        let config = SessionConfig {
            session_id: SessionId([0u8; 32]),
            local_party: PartyInfo {
                id: PartyId(1),
                index: 1,
                total: 3,
                threshold: 0, // invalid
            },
            parties: vec![PartyId(1), PartyId(2), PartyId(3)],
        };
        assert!(config.try_threshold().is_err());
    }
}
