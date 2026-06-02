// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unified benchmarking interface for threshold ECDSA protocols.
//!
//! Provides types for recording per-phase timing of protocol executions.
//! Each protocol phase (KeyGen, Presign, OnlineSign) can be timed independently.

use std::time::{Duration, Instant};

/// Timing results for a single protocol execution.
#[derive(Debug, Clone)]
pub struct ProtocolTiming {
    /// Protocol name (e.g., "CGGMP20", "GG18", "LN18")
    pub protocol: String,
    /// Number of parties
    pub n: u16,
    /// Threshold
    pub t: u16,
    /// Per-phase timing
    pub phases: Vec<PhaseTiming>,
}

/// Timing for a single protocol phase.
#[derive(Debug, Clone)]
pub struct PhaseTiming {
    /// Phase name (e.g., "KeyGen", "Presign", "OnlineSign", "MtA-Paillier", "MtA-OT")
    pub name: String,
    /// Number of interaction rounds
    pub rounds: u16,
    /// Wall-clock duration (per party, single-threaded)
    pub duration: Duration,
}

/// Timer utility for measuring phase durations.
pub struct PhaseTimer {
    name: String,
    rounds: u16,
    start: Instant,
}

impl PhaseTimer {
    /// Start timing a phase.
    pub fn start(name: &str, rounds: u16) -> Self {
        Self {
            name: name.to_string(),
            rounds,
            start: Instant::now(),
        }
    }

    /// Stop timing and return the result.
    pub fn stop(self) -> PhaseTiming {
        PhaseTiming {
            name: self.name,
            rounds: self.rounds,
            duration: self.start.elapsed(),
        }
    }
}

impl ProtocolTiming {
    /// Create a new timing record.
    pub fn new(protocol: &str, n: u16, t: u16) -> Self {
        Self {
            protocol: protocol.to_string(),
            n,
            t,
            phases: Vec::new(),
        }
    }

    /// Add a phase timing.
    pub fn add_phase(&mut self, phase: PhaseTiming) {
        self.phases.push(phase);
    }

    /// Get total duration across all phases.
    pub fn total_duration(&self) -> Duration {
        self.phases.iter().map(|p| p.duration).sum()
    }

    /// Get duration of a specific phase by name.
    pub fn phase_duration(&self, name: &str) -> Option<Duration> {
        self.phases
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.duration)
    }

    /// Get offline (presign) duration.
    pub fn offline_duration(&self) -> Option<Duration> {
        self.phase_duration("Presign")
    }

    /// Get online (sign) duration.
    pub fn online_duration(&self) -> Option<Duration> {
        self.phase_duration("OnlineSign")
    }
}
