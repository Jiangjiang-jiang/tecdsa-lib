// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "DKLs23",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 3,
    signing_rounds_impl: 4,
    security_model: "Statistical UC, dishonest majority (t-1 of n corrupted)",
    presign_rounds: 3,
    online_sign_rounds: 1,
    keygen_rounds: 3,
    mta_variant: "OT/VOLE",
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
