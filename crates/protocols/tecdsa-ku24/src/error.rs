// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error types for the KU24 protocol.

use tecdsa_protocol::PartyId;

/// Errors raised by the KU24 protocol.
#[derive(Debug, thiserror::Error)]
pub enum Ku24Error {
    /// The (n, t) configuration is not compatible with an honest majority.
    #[error("invalid threshold configuration: n = {n}, reconstruction threshold = {threshold} (need 1 <= t and n >= 2t+1 with t = threshold - 1)")]
    InvalidThreshold {
        /// Number of parties.
        n: u16,
        /// Reconstruction threshold (`t + 1` in the paper's notation).
        threshold: u16,
    },

    /// The party count exceeds the PRSS blow-up limit.
    ///
    /// Pseudorandom secret sharing needs one key per subset of size `n - t`,
    /// i.e. `binomial(n, t)` keys in total, so it is only practical for small `n`.
    #[error("too many parties for PRSS: n = {n} exceeds the supported maximum of {max}")]
    TooManyParties {
        /// Requested number of parties.
        n: u16,
        /// Supported maximum.
        max: u16,
    },

    /// The local party is not part of the participant set.
    #[error("local party {0} is not a member of the participant set")]
    NotAParticipant(PartyId),

    /// The participant set is malformed (duplicates, or a zero party id).
    #[error("invalid participant set: {0}")]
    InvalidPartySet(String),

    /// A message arrived from a party that is not in the participant set.
    #[error("unknown sender {0}")]
    UnknownSender(PartyId),

    /// A party sent two messages for the same round.
    #[error("duplicate round-{round} message from {party}")]
    DuplicateMessage {
        /// Protocol round.
        round: u16,
        /// Offending party.
        party: PartyId,
    },

    /// A message was received out of order.
    #[error("unexpected message for round {got} while in round {expected}")]
    RoundMismatch {
        /// Round the machine is currently in.
        expected: u16,
        /// Round the message belongs to.
        got: u16,
    },

    /// A wire payload could not be decoded.
    #[error("malformed payload: {0}")]
    Malformed(String),

    /// Broadcast shares are not consistent with a polynomial of the expected degree.
    ///
    /// In the honest-majority setting this always indicates a deviating party.
    #[error("shares of {what} are not consistent with a degree-{degree} polynomial")]
    InconsistentShares {
        /// Human-readable name of the shared value.
        what: &'static str,
        /// Expected polynomial degree.
        degree: usize,
    },

    /// The batch triple-verification check of `Pi_triple` failed (`T != 0`).
    #[error("triple verification failed: T != 0 (a party cheated in the weak multiplication)")]
    TripleCheckFailed,

    /// A reconstructed value was degenerate (zero scalar / identity point).
    #[error("degenerate value in presignature {index}: {what}")]
    Degenerate {
        /// Index within the presignature batch.
        index: usize,
        /// Human-readable name of the offending value.
        what: &'static str,
    },

    /// Parties disagree on the `r` component of the presignature being used.
    #[error("signers disagree on the presignature: {0} broadcast a different r")]
    PresignatureMismatch(PartyId),

    /// The combined signature failed ECDSA verification.
    #[error("the reconstructed signature does not verify under the public key")]
    InvalidSignature,

    /// The machine was asked for its output before completing.
    #[error("{0} is not complete")]
    NotComplete(&'static str),

    /// The machine was poisoned by a previous error.
    #[error("state machine is poisoned after an earlier failure")]
    Poisoned,

    /// Catch-all.
    #[error("{0}")]
    Other(String),
}

impl From<Ku24Error> for tecdsa_core::TecdsaError {
    fn from(e: Ku24Error) -> Self {
        match e {
            Ku24Error::InconsistentShares { .. }
            | Ku24Error::TripleCheckFailed
            | Ku24Error::Degenerate { .. } => tecdsa_core::TecdsaError::InvalidShare(e.to_string()),
            Ku24Error::InvalidSignature => tecdsa_core::TecdsaError::InvalidProof(e.to_string()),
            Ku24Error::UnknownSender(p) => tecdsa_core::TecdsaError::UnknownSender(p.0),
            Ku24Error::DuplicateMessage { party, .. } => {
                tecdsa_core::TecdsaError::DuplicateMessage(party.0)
            }
            Ku24Error::RoundMismatch { expected, got } => {
                tecdsa_core::TecdsaError::RoundMismatch { expected, got }
            }
            Ku24Error::Malformed(_) => tecdsa_core::TecdsaError::Serialization(e.to_string()),
            Ku24Error::PresignatureMismatch(_) | Ku24Error::Poisoned => {
                tecdsa_core::TecdsaError::Abort(e.to_string())
            }
            other => tecdsa_core::TecdsaError::Other(other.to_string()),
        }
    }
}

/// Convenience alias for KU24 results.
pub type Ku24Result<T> = Result<T, Ku24Error>;
