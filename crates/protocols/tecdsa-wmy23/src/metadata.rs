// SPDX-License-Identifier: GPL-3.0-or-later
use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "WMY23",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 5,
    signing_rounds_impl: 5,
    security_model: "Game-based, self-healing + cheater ID, dishonest minority",
    presign_rounds: 4,
    online_sign_rounds: 1,
    keygen_rounds: 4,
    mta_variant: "CL (MtAwc)",
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
