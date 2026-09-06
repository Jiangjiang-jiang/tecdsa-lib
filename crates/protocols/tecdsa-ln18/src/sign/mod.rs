// SPDX-License-Identifier: MIT OR Apache-2.0
//! LN18 threshold ECDSA signing (Protocol 5.1), split into Presign + OnlineSign.
//!
//! See [`rounds`] for the legacy simulation logic, [`state_rounds`] for the real
//! round state structs, and [`machine`] for StateMachine implementations.

pub mod machine;
pub mod msg;
pub mod mta_hybrid;
pub mod rounds;
pub mod setup;
pub(crate) mod state_rounds;

// --- New real StateMachine path exports ---
// --- Legacy wrapper exports (backward compatibility) ---
pub use machine::{
    Ln18FullSignMachine, Ln18OfflineSignMachine, Ln18OnlineSignMachine, Ln18PresignMachine,
    Ln18SignMachine,
};
pub use msg::{
    Ln18FullSignMsg, Ln18OfflineSignMsg, Ln18OnlineSignMsg, Ln18PresignMsg, Ln18SignMsg,
};
pub use mta_hybrid::{Ln18MtaBackend, Ln18MtaHybrid};
// --- Legacy simulation helper exports ---
pub use rounds::{
    ln18_full_sign_parallel, ln18_online_sign_parallel, ln18_presign_parallel, ln18_sign_parallel,
    Ln18OnlineSignParams as Ln18LegacyOnlineSignParams, Ln18PresignParams, Ln18SignParams,
};
#[cfg(feature = "mta-ot")]
pub use rounds::{
    ln18_full_sign_parallel_ot, ln18_online_sign_parallel_ot, ln18_presign_parallel_ot,
    ln18_sign_parallel_ot, Ln18OtOnlineSignParams, Ln18OtPresignParams, Ln18OtSignParams,
};
pub use setup::{build_signing_setup, build_signing_setup_with_ntilde_bits, NTILDE_PRIME_BITS};
pub use state_rounds::{Ln18OfflineSignParams, Ln18OnlineSignParams};
