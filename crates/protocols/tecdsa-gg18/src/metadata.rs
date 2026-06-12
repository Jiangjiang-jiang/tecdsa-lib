use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "GG18",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 8,
    signing_rounds_impl: 8,
    security_model: "Malicious with dishonest majority",
    presign_rounds: 3,
    online_sign_rounds: 5,
    keygen_rounds: 4,
    mta_variant: "Paillier",
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
