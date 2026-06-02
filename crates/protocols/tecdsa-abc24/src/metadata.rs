// SPDX-License-Identifier: MIT OR Apache-2.0

use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "ABC+24",
    version: "1.0",
    primitive: "Two-Party ECDSA",
    signing_rounds_paper: 2,
    signing_rounds_impl: 2,
    security_model: "GGM + ROM (doubly-enhanced unforgeability)",
    presign_rounds: 0,
    online_sign_rounds: 2,
    keygen_rounds: 4,
    mta_variant: "Paillier OLE (additive sharing, 1 OLE per signature)",
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
