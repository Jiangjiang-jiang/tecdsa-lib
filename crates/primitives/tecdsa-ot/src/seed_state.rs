// SPDX-License-Identifier: MIT OR Apache-2.0
//! Persistent OT seed state for cross-session base OT reuse.
//!
//! After the initial base OT exchange, the resulting seeds can be stored
//! in a party's key share.  On subsequent signing sessions the expensive
//! base OT phase is skipped: `MulSender` and `MulReceiver` are
//! reconstructed from the persisted seeds via `OtExtensionSender::from_seeds`
//! and `OtExtensionReceiver::from_seeds`.
//!
//! # Forward security
//!
//! The `usage_counter` field records how many times the seeds have been
//! used.  Callers may enforce a rotation policy (e.g., re-run base OT
//! after N signing sessions).  The counter is incremented each time
//! [`OtSeedState::increment_counter`] is called.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::soft_spoken::HashOutput;

// ---------------------------------------------------------------------------
// OtSeedState
// ---------------------------------------------------------------------------

/// Persistent state from a completed base OT exchange with one counterparty.
///
/// Stores the OTE sender-side seeds (correlation bits + KAPPA seeds) and the
/// OTE receiver-side seeds (two seed vectors of KAPPA seeds each) so that
/// `MulSender`/`MulReceiver` can be reconstructed without re-running base OT.
///
/// # Zeroize
///
/// All seed material is zeroized on drop.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtSeedState {
    /// Correlation bits used by the OTE sender (KAPPA bits).
    pub sender_correlation: Vec<bool>,
    /// OTE sender seeds: one 32-byte seed per base OT instance (KAPPA seeds).
    pub sender_seeds: Vec<HashOutput>,
    /// OTE receiver seeds for base OT message 0 (KAPPA seeds).
    pub receiver_seeds0: Vec<HashOutput>,
    /// OTE receiver seeds for base OT message 1 (KAPPA seeds).
    pub receiver_seeds1: Vec<HashOutput>,
    /// Number of times these seeds have been used for signing sessions.
    /// Callers may enforce a rotation threshold for forward security.
    pub usage_counter: u64,
}

impl OtSeedState {
    /// Create a new `OtSeedState` with a zero usage counter.
    #[must_use]
    pub fn new(
        sender_correlation: Vec<bool>,
        sender_seeds: Vec<HashOutput>,
        receiver_seeds0: Vec<HashOutput>,
        receiver_seeds1: Vec<HashOutput>,
    ) -> Self {
        Self {
            sender_correlation,
            sender_seeds,
            receiver_seeds0,
            receiver_seeds1,
            usage_counter: 0,
        }
    }

    /// Increment the usage counter and return the new value.
    pub fn increment_counter(&mut self) -> u64 {
        self.usage_counter += 1;
        self.usage_counter
    }
}

impl Zeroize for OtSeedState {
    fn zeroize(&mut self) {
        for seed in &mut self.sender_seeds {
            seed.zeroize();
        }
        for seed in &mut self.receiver_seeds0 {
            seed.zeroize();
        }
        for seed in &mut self.receiver_seeds1 {
            seed.zeroize();
        }
        // Correlation bits are not secret per se (they protect the
        // sender's input, not an independent secret), but zeroize
        // defensively.
        self.sender_correlation.clear();
        self.usage_counter = 0;
    }
}

impl Drop for OtSeedState {
    fn drop(&mut self) {
        self.zeroize();
    }
}
