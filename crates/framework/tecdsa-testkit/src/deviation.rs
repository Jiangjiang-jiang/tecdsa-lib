// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adversarial deviation plans for negative-path protocol testing.
//!
//! A [`DeviationPlan`] describes a sequence of [`Deviation`]s — structured
//! faults that the orchestrator or test harness injects into a protocol run.
//! This enables systematic testing of abort-identification, blame attribution,
//! and security guarantees under malicious-party behaviour.

use tecdsa_protocol::PartyId;

/// A single deviation (fault) to inject into a protocol execution.
#[derive(Debug, Clone)]
pub enum Deviation {
    /// Silently drop a unicast message from `from` to `to` in `round`.
    DropMessage {
        from: PartyId,
        to: PartyId,
        round: u16,
    },
    /// Replace `party`'s commitment in `round` with an incorrect value.
    WrongCommitment { party: PartyId, round: u16 },
    /// Replace `party`'s zero-knowledge proof in `round` with an invalid one.
    BadZkProof { party: PartyId, round: u16 },
    /// Deliver `party`'s messages out of the normal round order.
    ReorderRounds { party: PartyId },
    /// Send different broadcast payloads to different recipients in `round`.
    EquivocateBroadcast { party: PartyId, round: u16 },
}

/// A collection of [`Deviation`]s that define an adversarial scenario.
#[derive(Debug, Default)]
pub struct DeviationPlan {
    /// The ordered list of deviations to apply during execution.
    pub deviations: Vec<Deviation>,
}

impl DeviationPlan {
    /// Create an empty plan (no deviations — honest execution).
    #[must_use]
    pub fn new() -> Self {
        Self {
            deviations: Vec::new(),
        }
    }

    /// Append a deviation and return `self` for chaining.
    #[must_use]
    pub fn with(mut self, d: Deviation) -> Self {
        self.deviations.push(d);
        self
    }

    /// Return `true` if this plan calls for dropping the message from `from`
    /// to `to` at the given `round`.
    #[must_use]
    pub fn should_drop(&self, from: PartyId, to: PartyId, round: u16) -> bool {
        self.deviations.iter().any(|d| {
            matches!(d,
                Deviation::DropMessage { from: f, to: t, round: r }
                if *f == from && *t == to && *r == round
            )
        })
    }
}
