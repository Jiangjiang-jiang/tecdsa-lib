// SPDX-License-Identifier: MIT OR Apache-2.0
use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

use crate::state_machine::StateMachine;

/// Describes how a protocol phase is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseMode {
    /// Real multi-round StateMachine: handle() processes messages, drain_outgoing() emits them.
    Interactive,
    /// Pure local computation (e.g., CGGMP20 partial_sign + combine). No network rounds.
    Local,
    /// Wrapper that computes everything at construction; handle() rejects all messages.
    SimulationWrapper,
    /// The paper defines this as part of a larger phase that was split for benchmarking.
    /// E.g., LN18's "presign" is derived from its canonical 8-round full-sign.
    DerivedSplit,
    /// This phase does not exist for this protocol (e.g., no aux_info, no refresh).
    NotApplicable,
}

impl PhaseMode {
    /// Whether this phase should appear in the computation-only main table.
    pub fn is_main_table_eligible(self) -> bool {
        matches!(self, Self::Interactive | Self::Local | Self::DerivedSplit)
    }

    /// Whether this phase has a real message-driven StateMachine for wire benchmarks.
    pub fn is_wire_eligible(self) -> bool {
        matches!(self, Self::Interactive)
    }
}

/// Per-phase mode declarations for a protocol.
#[derive(Debug, Clone, Copy)]
pub struct PhaseModes {
    pub keygen: PhaseMode,
    pub aux: PhaseMode,
    pub presign: PhaseMode,
    pub sign: PhaseMode,
    pub refresh: PhaseMode,
}

/// Per-phase eligibility for benchmark tables.
///
/// Derived from [`PhaseModes`] via [`PhaseModes::main_table_eligibility`] and
/// [`PhaseModes::wire_table_eligibility`].
#[derive(Debug, Clone, Copy)]
pub struct PhaseEligibility {
    pub keygen: bool,
    pub presign: bool,
    pub sign: bool,
}

impl PhaseModes {
    pub fn main_table_eligibility(&self) -> PhaseEligibility {
        PhaseEligibility {
            keygen: self.keygen.is_main_table_eligible(),
            presign: self.presign.is_main_table_eligible(),
            sign: self.sign.is_main_table_eligible(),
        }
    }

    pub fn wire_table_eligibility(&self) -> PhaseEligibility {
        PhaseEligibility {
            keygen: self.keygen.is_wire_eligible(),
            presign: self.presign.is_wire_eligible(),
            sign: self.sign.is_wire_eligible(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolMetadata {
    pub name: &'static str,
    pub version: &'static str,
    pub primitive: &'static str,
    /// Total signing rounds as stated in the paper (theoretical minimum with
    /// full parallelism). Used for paper-to-paper comparison.
    pub signing_rounds_paper: u16,
    /// Actual signing rounds in this implementation (presign + online, sequential).
    /// This is what benchmarks will measure.
    pub signing_rounds_impl: u16,
    pub security_model: &'static str,
    /// Rounds in the offline (message-independent) presign phase.
    /// 0 if the protocol has no presign phase.
    pub presign_rounds: u16,
    /// Rounds in the online (message-dependent) sign phase.
    pub online_sign_rounds: u16,
    /// Rounds in the key generation phase.
    pub keygen_rounds: u16,
    /// MtA variant description (e.g., "Paillier", "OT", "Paillier+OT").
    pub mta_variant: &'static str,
    /// Whether this protocol supports proactive key refresh.
    pub has_refresh: bool,
    /// Semantic description of each phase's implementation mode.
    pub phase_modes: PhaseModes,
    /// Per-phase eligibility for the computation-only main table.
    /// Derived from `phase_modes` — kept for backward compatibility.
    pub main_table: PhaseEligibility,
    /// Per-phase eligibility for the wire (message-driven) benchmark table.
    /// Derived from `phase_modes` — kept for backward compatibility.
    pub wire_table: PhaseEligibility,
}

/// Unified type-level interface for a threshold ECDSA protocol.
///
/// Each concrete protocol (CGGMP20, GG20, FROST, etc.) implements this trait
/// to declare its associated types and state machines.  The trait intentionally
/// avoids `Serialize`/`DeserializeOwned` bounds so that upstream types (e.g.
/// Paillier keys, elliptic-curve points) do not need to carry serde derives.
/// Call sites that need serialization can add those bounds locally.
pub trait Protocol: 'static
where
    FieldBytesSize<Self::Curve>: ModulusSize,
{
    type Curve: TecdsaCurve;

    type KeyShare: Zeroize + Send;
    type PublicKey: Send;
    type AuxInfo: Send;
    type Presignature: Send;
    type Signature: Send;

    type KeyGen: StateMachine<Output = Self::KeyShare>;
    type AuxGen: StateMachine<Output = Self::AuxInfo>;
    type Presign: StateMachine<Output = Self::Presignature>;
    type Sign: StateMachine<Output = Self::Signature>;

    /// Proactive key refresh state machine.
    ///
    /// Produces a new [`KeyShare`](Self::KeyShare) with re-randomized secret
    /// shares while preserving the public key.  Protocols that do not support
    /// refresh should use [`NoRefreshMachine`](crate::NoRefreshMachine).
    type Refresh: StateMachine<Output = Self::KeyShare>;

    const METADATA: ProtocolMetadata;
}
