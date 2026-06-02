// SPDX-License-Identifier: MIT OR Apache-2.0
//! LN18 protocol metadata constant.

use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

/// LN18 protocol metadata.
pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "LN18",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 8,
    signing_rounds_impl: 8,
    security_model: "Simulation-based, malicious, dishonest majority",
    presign_rounds: 0,
    online_sign_rounds: 8,
    keygen_rounds: 5,
    mta_variant: "Paillier+OT",
    has_refresh: false,
    phase_modes: PhaseModes {
        keygen: PhaseMode::Interactive,
        aux: PhaseMode::NotApplicable,
        presign: PhaseMode::DerivedSplit,
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
        presign: false,
        sign: true,
    },
};
