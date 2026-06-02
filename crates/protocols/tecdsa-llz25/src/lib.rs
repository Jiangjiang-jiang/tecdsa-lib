// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
//! LLZ25 Two-Round Threshold ECDSA protocol.
//!
//! Implements the Lyu-Li-Zhou-Deng 2025 protocol from
//! "Threshold ECDSA in Two Rounds" (CCS 2025).  This protocol uses
//! NIM (Non-Interactive Multiplication) over class groups:
//!
//! - **1-round presign (offline):** each party NIM-encodes nonce and mask
//!   shares, broadcasts CL ciphertexts with ZK proofs.
//! - **1-round sign (online):** NIM decoding (local), compute partial
//!   signatures $(w_i, u_i)$, broadcast + combine.
//! - **3-round keygen:** interactive Feldman VSS DKG + NIM encoding + `R_{CL-DL-EC}` proof.
//!
//! ## ECDSA Form
//!
//! The signature uses a re-randomized nonce:
//! $R = K^z \cdot g^y$ where $z = H_1(X, msg, \{pm_j\})$, $y = H_2(z)$.
//! $\sigma = (zk + y)^{-1}(m + rx)$.
//!
//! ## Security
//!
//! DEUF (Doubly-Enhanced Existential Unforgeability) under the HSM
//! assumption over class groups.
//!
//! # License
//!
//! This crate is **GPL-3.0-or-later** due to the `tecdsa-class-group`
//! dependency (which wraps the BICYCL C library).

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;

use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata, Signature};

/// LLZ25 threshold ECDSA protocol descriptor.
///
/// Uses NIM (Non-Interactive Multiplication) over class groups for
/// achieving 2-round signing (1 presign + 1 online).
///
/// LLZ25 types are NOT generic over `C: TecdsaCurve` because the
/// underlying CL-HSM encryption (bicycl-rs) is parameterized by a fixed
/// curve order `q` at setup time.  The current implementation uses
/// secp256k1 exclusively.
///
/// ## Protocol phases
///
/// The protocol provides both pure round functions and `StateMachine`
/// trait implementations:
///
/// ### Pure functions (simulation mode)
/// 1. `presign::presign_round1` -> `(PresignMessage, PresignState)`
/// 2. `sign::compute_partial_signature` -> `(PartialSignature, r)`
/// 3. `sign::combine_signatures` -> `Signature`
///
/// ### StateMachine (orchestrator-compatible)
/// - `presign::machine::Llz25PresignMachine` -- collects broadcasts, verifies
///   ZK proofs (`R_{CL-DL-EC}`, `R_{Ped-EC}`), produces `Llz25Presignature`
/// - `sign::machine::Llz25SignMachine` -- broadcasts partial signatures
///   `(w_i, u_i)`, combines into final ECDSA `Signature`
///
/// ## MtA backend
///
/// LLZ25 uses NIM (Non-Interactive Multiplication) for its MtA sub-protocol.
/// The NIM backend implements [`tecdsa_protocol::MtABroadcast`] via
/// [`tecdsa_class_group::NimMtA`].  The protocol modules call the
/// lower-level [`tecdsa_class_group::nim::Nim`] API directly because
/// NIM's asymmetric A/B role usage is deeply embedded in the protocol
/// flow (each party uses both roles simultaneously).  See the module-level
/// docs in [`presign`] and [`sign`] for details.
///
/// Reference: Lyu, Li, Zhou, Deng. "Threshold ECDSA in Two Rounds." CCS 2025.
pub struct Llz25;

impl Protocol for Llz25 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Llz25KeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::machine::Llz25Presignature;
    type Signature = Signature<k256::Secp256k1>;

    type KeyGen = keygen::Llz25KeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::machine::Llz25PresignMachine;
    type Sign = sign::machine::Llz25SignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = metadata::METADATA;
}
