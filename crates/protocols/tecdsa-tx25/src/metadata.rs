// SPDX-License-Identifier: MIT OR Apache-2.0
//! TX25 protocol metadata constant.

use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

/// TX25 protocol metadata.
pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "TX25",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 3,
    signing_rounds_impl: 3,
    security_model: "UC, static corruption, honest majority (n >= 2t-1)",
    presign_rounds: 2,
    online_sign_rounds: 1,
    keygen_rounds: 3,
    mta_variant: "CL (public-checked MtA)",
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
