// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    non_snake_case
)]

//! WMC24 online signing protocol (1 round).
//!
//! Consumes a [`Wmc24Presignature`](crate::presign::Wmc24Presignature) and a
//! message to produce a threshold ECDSA signature via threshold CL partial
//! decryption.

pub mod machine;
pub mod msg;
pub(crate) mod rounds;

pub use machine::Wmc24OnlineSignMachine;
pub use msg::Wmc24OnlineSignMsg;
