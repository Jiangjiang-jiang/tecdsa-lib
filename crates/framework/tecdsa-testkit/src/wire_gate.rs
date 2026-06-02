// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_protocol::{PhaseMode, ProtocolMetadata};

#[derive(Debug, Clone, Copy)]
pub enum Phase {
    Keygen,
    Presign,
    Sign,
}

impl Phase {
    /// Get the declared PhaseMode for this phase from protocol metadata.
    pub fn mode(&self, meta: &ProtocolMetadata) -> PhaseMode {
        match self {
            Phase::Keygen => meta.phase_modes.keygen,
            Phase::Presign => meta.phase_modes.presign,
            Phase::Sign => meta.phase_modes.sign,
        }
    }

    /// Whether this phase should appear in wire (message-driven) benchmarks.
    /// Only Interactive phases have real StateMachine message exchange.
    pub fn is_wire_eligible(&self, meta: &ProtocolMetadata) -> bool {
        self.mode(meta).is_wire_eligible()
    }

    /// Whether this phase should appear in the computation-only main table.
    pub fn is_main_table_eligible(&self, meta: &ProtocolMetadata) -> bool {
        self.mode(meta).is_main_table_eligible()
    }
}

/// Check if a phase should be included in wire benchmarks.
/// Returns an error message if the phase is not eligible.
pub fn check_wire_eligible(meta: &ProtocolMetadata, phase: Phase) -> Result<(), String> {
    if phase.is_wire_eligible(meta) {
        Ok(())
    } else {
        Err(format!(
            "{} {:?} phase is {:?}, not wire-eligible",
            meta.name,
            phase,
            phase.mode(meta)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tecdsa_protocol::PhaseModes;

    fn make_meta(modes: PhaseModes) -> ProtocolMetadata {
        ProtocolMetadata {
            name: "TestProto",
            version: "0.1",
            primitive: "test",
            signing_rounds_paper: 1,
            signing_rounds_impl: 1,
            security_model: "test",
            presign_rounds: 1,
            online_sign_rounds: 1,
            keygen_rounds: 1,
            mta_variant: "none",
            has_refresh: false,
            phase_modes: modes,
            main_table: modes.main_table_eligibility(),
            wire_table: modes.wire_table_eligibility(),
        }
    }

    #[test]
    fn interactive_is_wire_eligible() {
        let meta = make_meta(PhaseModes {
            keygen: PhaseMode::Interactive,
            aux: PhaseMode::NotApplicable,
            presign: PhaseMode::Interactive,
            sign: PhaseMode::Interactive,
            refresh: PhaseMode::NotApplicable,
        });
        assert!(check_wire_eligible(&meta, Phase::Keygen).is_ok());
        assert!(check_wire_eligible(&meta, Phase::Presign).is_ok());
        assert!(check_wire_eligible(&meta, Phase::Sign).is_ok());
    }

    #[test]
    fn simulation_wrapper_not_wire_eligible() {
        let meta = make_meta(PhaseModes {
            keygen: PhaseMode::Interactive,
            aux: PhaseMode::NotApplicable,
            presign: PhaseMode::SimulationWrapper,
            sign: PhaseMode::Interactive,
            refresh: PhaseMode::NotApplicable,
        });
        assert!(check_wire_eligible(&meta, Phase::Presign).is_err());
        assert!(check_wire_eligible(&meta, Phase::Keygen).is_ok());
    }

    #[test]
    fn local_not_wire_eligible() {
        let meta = make_meta(PhaseModes {
            keygen: PhaseMode::Interactive,
            aux: PhaseMode::NotApplicable,
            presign: PhaseMode::NotApplicable,
            sign: PhaseMode::Local,
            refresh: PhaseMode::NotApplicable,
        });
        assert!(check_wire_eligible(&meta, Phase::Sign).is_err());
    }

    #[test]
    fn local_is_main_table_eligible() {
        let meta = make_meta(PhaseModes {
            keygen: PhaseMode::Interactive,
            aux: PhaseMode::NotApplicable,
            presign: PhaseMode::NotApplicable,
            sign: PhaseMode::Local,
            refresh: PhaseMode::NotApplicable,
        });
        assert!(Phase::Sign.is_main_table_eligible(&meta));
    }

    #[test]
    fn derived_split_is_main_but_not_wire() {
        let meta = make_meta(PhaseModes {
            keygen: PhaseMode::Interactive,
            aux: PhaseMode::NotApplicable,
            presign: PhaseMode::DerivedSplit,
            sign: PhaseMode::Interactive,
            refresh: PhaseMode::NotApplicable,
        });
        assert!(Phase::Presign.is_main_table_eligible(&meta));
        assert!(!Phase::Presign.is_wire_eligible(&meta));
    }

    #[test]
    fn not_applicable_excluded_from_both() {
        let meta = make_meta(PhaseModes {
            keygen: PhaseMode::Interactive,
            aux: PhaseMode::NotApplicable,
            presign: PhaseMode::NotApplicable,
            sign: PhaseMode::Interactive,
            refresh: PhaseMode::NotApplicable,
        });
        assert!(!Phase::Presign.is_main_table_eligible(&meta));
        assert!(!Phase::Presign.is_wire_eligible(&meta));
    }
}
