// SPDX-License-Identifier: MIT OR Apache-2.0
//! Participant bookkeeping shared by all KU25 phases.
//!
//! KU25 is stated over the evaluation points `[n] = {1, ..., n}`.  To stay
//! agnostic of how callers number their [`PartyId`]s, we sort the participant
//! set once and use each party's **1-based position** as its Shamir evaluation
//! point.  When callers use `PartyId(1) ..= PartyId(n)` -- as the rest of the
//! workspace does -- the position and the id coincide.

use tecdsa_protocol::PartyId;

use crate::{
    error::{Ku25Error, Ku25Result},
    prss::check_params,
};

/// The participant set of a KU25 execution, from the point of view of one party.
#[derive(Debug, Clone)]
pub struct Committee {
    parties: Vec<PartyId>,
    my_id: PartyId,
    my_index: u16,
    degree: u16,
}

impl Committee {
    /// Build the committee view for `my_id`.
    ///
    /// `threshold` is the *reconstruction* threshold (`t + 1` in the paper's
    /// notation), matching the workspace-wide `(n, t)` convention.
    ///
    /// # Errors
    /// Fails if the party set is malformed, if `my_id` is absent, if the
    /// configuration does not admit an honest majority (`n >= 2t + 1`), or if
    /// `n` exceeds [`crate::prss::MAX_PARTIES`].
    pub fn new(my_id: PartyId, all_parties: Vec<PartyId>, threshold: u16) -> Ku25Result<Self> {
        let mut parties = all_parties;
        parties.sort_unstable();
        let len = parties.len();
        parties.dedup();
        if parties.len() != len {
            return Err(Ku25Error::InvalidPartySet(
                "duplicate party identifiers".into(),
            ));
        }
        let n = u16::try_from(parties.len())
            .map_err(|_| Ku25Error::InvalidPartySet("too many parties".into()))?;
        if n == 0 {
            return Err(Ku25Error::InvalidPartySet("empty party set".into()));
        }
        let degree = check_params(n, threshold)?;

        let position = parties
            .iter()
            .position(|p| *p == my_id)
            .ok_or(Ku25Error::NotAParticipant(my_id))?;
        let my_index = u16::try_from(position + 1).expect("n fits in u16");

        Ok(Self {
            parties,
            my_id,
            my_index,
            degree,
        })
    }

    /// Number of parties `n`.
    #[must_use]
    pub fn n(&self) -> u16 {
        u16::try_from(self.parties.len()).expect("n fits in u16")
    }

    /// Number of peers, `n - 1`.
    #[must_use]
    pub fn peers(&self) -> usize {
        self.parties.len() - 1
    }

    /// The paper's `t`: the corruption threshold and the sharing degree.
    #[must_use]
    pub fn degree(&self) -> u16 {
        self.degree
    }

    /// The reconstruction threshold `t + 1`.
    #[must_use]
    pub fn threshold(&self) -> u16 {
        self.degree + 1
    }

    /// The local party's identifier.
    #[must_use]
    pub fn my_id(&self) -> PartyId {
        self.my_id
    }

    /// The local party's 1-based evaluation point.
    #[must_use]
    pub fn my_index(&self) -> u16 {
        self.my_index
    }

    /// All participants, sorted ascending.
    #[must_use]
    pub fn parties(&self) -> &[PartyId] {
        &self.parties
    }

    /// The evaluation points `1 ..= n`.
    #[must_use]
    pub fn indices(&self) -> Vec<u16> {
        (1..=self.n()).collect()
    }

    /// The 1-based evaluation point of `party`, if it is a participant.
    #[must_use]
    pub fn index_of(&self, party: PartyId) -> Option<u16> {
        self.parties
            .iter()
            .position(|p| *p == party)
            .map(|pos| u16::try_from(pos + 1).expect("n fits in u16"))
    }

    /// The party sitting at the 1-based evaluation point `index`.
    ///
    /// # Panics
    /// Panics if `index` is out of range.
    #[must_use]
    pub fn party_at(&self, index: u16) -> PartyId {
        self.parties[usize::from(index) - 1]
    }

    /// Resolve a sender, rejecting unknown parties and self-messages.
    ///
    /// # Errors
    /// Fails if `from` is not a participant or is the local party.
    pub fn sender_index(&self, from: PartyId) -> Ku25Result<u16> {
        if from == self.my_id {
            return Err(Ku25Error::UnknownSender(from));
        }
        self.index_of(from).ok_or(Ku25Error::UnknownSender(from))
    }
}
