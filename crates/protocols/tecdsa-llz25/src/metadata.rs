use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "LLZ25",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 2,
    signing_rounds_impl: 2,
    security_model: "DEUF (Doubly-Enhanced Existential Unforgeability)",
    presign_rounds: 1,
    online_sign_rounds: 1,
    keygen_rounds: 3,
    mta_variant: "NIM (Non-Interactive Multiplication, class groups)",
    has_refresh: false,
    phase_modes: PhaseModes {
        keygen: PhaseMode::Interactive,
        aux: PhaseMode::NotApplicable,
        presign: PhaseMode::Interactive,
        sign: PhaseMode::Interactive,
        refresh: PhaseMode::NotApplicable,
    },
    main_table: PhaseEligibility {
        keygen: true,
        presign: true,
        sign: true,
    },
    wire_table: PhaseEligibility {
        keygen: true,
        presign: true,
        sign: true,
    },
};
