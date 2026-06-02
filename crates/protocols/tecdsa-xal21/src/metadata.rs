// SPDX-License-Identifier: MIT OR Apache-2.0

use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "XAL+21",
    version: "1.0",
    primitive: "Two-Party ECDSA",
    signing_rounds_paper: 4,
    signing_rounds_impl: 4,
    security_model: "Malicious, static corruption (real/ideal simulation)",
    presign_rounds: 3,
    online_sign_rounds: 1,
    keygen_rounds: 3,
    mta_variant: "Paillier/CL/OT (re-sharing + linear nonce)",
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
