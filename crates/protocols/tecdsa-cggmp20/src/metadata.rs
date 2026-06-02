// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "CGGMP20",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 4,
    signing_rounds_impl: 4,
    security_model: "UC-security with identifiable abort",
    presign_rounds: 3,
    online_sign_rounds: 1,
    keygen_rounds: 3,
    mta_variant: "Paillier",
    has_refresh: false,
    phase_modes: PhaseModes {
        keygen: PhaseMode::Interactive,
        aux: PhaseMode::Interactive,
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
