use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "JTX25-Robust",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 3,
    signing_rounds_impl: 3,
    security_model: "UC, static corruption, threshold CL (t-IND-CPA)",
    presign_rounds: 2,
    online_sign_rounds: 1,
    keygen_rounds: 3,
    mta_variant: "Threshold CL (homomorphic scalar multiply)",
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
