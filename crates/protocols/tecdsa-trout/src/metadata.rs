// SPDX-License-Identifier: GPL-3.0-or-later
use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "Trout",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 2,
    signing_rounds_impl: 2,
    security_model: "IA (Identifiable Abort), HSM + ARSA assumptions",
    presign_rounds: 1,
    online_sign_rounds: 1,
    keygen_rounds: 3,
    mta_variant: "CL scaled decryption + eVRF",
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
