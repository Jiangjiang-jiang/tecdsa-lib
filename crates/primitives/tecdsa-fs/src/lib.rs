// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fiat-Shamir transcripts and Sigma protocol framework for threshold ECDSA.
//!
//! Provides:
//! - [`TranscriptProtocol`] — trait abstracting over transcript primitives
//! - [`MerlinTranscript`] — STROBE-based transcript wrapping the `merlin` crate
//! - [`SigmaRelation`] — trait for three-move Sigma protocol relations
//! - [`FiatShamirProof`] — non-interactive proof via the Fiat-Shamir transform

mod fiat_shamir;
mod sigma;
mod transcript;

pub use fiat_shamir::FiatShamirProof;
pub use sigma::SigmaRelation;
pub use transcript::{MerlinTranscript, TranscriptProtocol};
