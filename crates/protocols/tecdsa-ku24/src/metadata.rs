// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_protocol::{PhaseEligibility, PhaseMode, PhaseModes, ProtocolMetadata};

pub const METADATA: ProtocolMetadata = ProtocolMetadata {
    name: "KU24",
    version: "1.0",
    primitive: "Threshold ECDSA",
    signing_rounds_paper: 5,
    signing_rounds_impl: 5,
    security_model: "UC, static corruption, honest majority (n >= 2t+1), security with abort",
    // Pi_triple: 1 round per F_wmult call (x2) + 1 round for the batch check T,
    // then 1 round of Pi_ECDSA to open w_i and R_i.  Amortized over a batch of m.
    presign_rounds: 4,
    online_sign_rounds: 1,
    // The paper leaves DKG out of scope; we supply the natural 1-round PRSS DKG.
    keygen_rounds: 1,
    mta_variant: "PRSS + degree-reduction (Beaver triples, no MtA)",
    has_refresh: false,
    phase_modes: PhaseModes {
        keygen: PhaseMode::Interactive,
        // PRSS key distribution (F_rss `Init`) is a one-time, key-independent setup.
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
