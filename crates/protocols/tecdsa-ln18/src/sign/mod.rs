// SPDX-License-Identifier: MIT OR Apache-2.0
//! LN18 threshold ECDSA signing (Protocol 5.1), split into Presign + OnlineSign.
//!
//! See [`rounds`] for the protocol logic and [`machine`] for StateMachine wrappers.

pub mod machine;
pub mod msg;
pub mod rounds;

// Re-export public types from submodules for backward compatibility.
pub use machine::{
    Ln18FullSignMachine, Ln18OnlineSignMachine, Ln18PresignMachine, Ln18SignMachine,
};
pub use msg::{Ln18FullSignMsg, Ln18OnlineSignMsg, Ln18PresignMsg, Ln18SignMsg};
pub use rounds::{
    ln18_full_sign_parallel, ln18_online_sign_parallel, ln18_presign_parallel, ln18_sign_parallel,
    Ln18OnlineSignParams, Ln18PresignParams, Ln18SignParams,
};

#[cfg(feature = "mta-ot")]
pub use rounds::{
    ln18_full_sign_parallel_ot, ln18_online_sign_parallel_ot, ln18_presign_parallel_ot,
    ln18_sign_parallel_ot, Ln18OtOnlineSignParams, Ln18OtPresignParams, Ln18OtSignParams,
};
