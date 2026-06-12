use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "Lin17",
    version: "1.0",
    primitive: "Two-Party ECDSA",
    signing_rounds_paper: 4,
    signing_rounds_impl: 4,
    security_model: "Game-based (sequential composition)",
    presign_rounds: 0,
    online_sign_rounds: 4,
    keygen_rounds: 5,
    mta_variant: "Paillier homomorphic (multiplicative sharing)",
    has_refresh: false,
    phase_modes: PhaseModes {
        keygen: PhaseMode::Interactive,
        aux: PhaseMode::NotApplicable,
        presign: PhaseMode::NotApplicable,
        sign: PhaseMode::Local,
        refresh: PhaseMode::NotApplicable,
    },
    main_table: PhaseEligibility {
        keygen: true,
        presign: false,
        sign: true,
    },
    wire_table: PhaseEligibility {
        keygen: true,
        presign: false,
        sign: false,
    },
};
