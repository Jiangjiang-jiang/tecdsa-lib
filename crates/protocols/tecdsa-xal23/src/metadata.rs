// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "XAL23",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 5,
    signing_rounds_impl: 5,
    security_model: "Malicious, static corruption",
    presign_rounds: 4,
    online_sign_rounds: 1,
    keygen_rounds: 2,
    mta_variant: "JL (Joye-Libert encryption)",
    has_refresh: false,
    phase_modes: PhaseModes {
        keygen: PhaseMode::Interactive,
        aux: PhaseMode::NotApplicable,
        presign: PhaseMode::SimulationWrapper,
        sign: PhaseMode::Interactive,
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
        sign: true,
    },
};
