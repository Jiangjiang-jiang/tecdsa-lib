// SPDX-License-Identifier: MIT OR Apache-2.0
mod codec;
mod envelope;

pub use codec::{decode, encode};
pub use envelope::{Header, PREAMBLE, WIRE_VERSION};
