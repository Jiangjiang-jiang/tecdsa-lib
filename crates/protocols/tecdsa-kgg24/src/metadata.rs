// SPDX-License-Identifier: MIT OR Apache-2.0

use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "KGG24",
    version: "1.0",
    primitive: "Two-Party ECDSA",
    signing_rounds_paper: 3,
    signing_rounds_impl: 3,
    security_model: "Proactive (Paillier-EC-Refresh assumption)",
    presign_rounds: 0,
    online_sign_rounds: 3,
    keygen_rounds: 3,
    mta_variant: "Paillier homomorphic (additive sharing + noise)",
    has_refresh: true,
    phase_modes: PhaseModes {
        keygen: PhaseMode::Interactive,
        aux: PhaseMode::NotApplicable,
        presign: PhaseMode::NotApplicable,
        sign: PhaseMode::Local,
        refresh: PhaseMode::Interactive,
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
