// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
//! Trout: Two-Round Threshold ECDSA from Class Groups.
//!
//! Implements the Trout protocol (Dahari-Garbian, Nof, Parker) for
//! threshold ECDSA signing using CL encryption, eVRF, and scaled decryption.
//!
//! - **2-round signing**: 1-round presign (offline) + 1-round online sign.
//! - **O(1) communication** per party.
//! - **Identifiable abort** via R_{affCom} proofs in scaled decryption.
//! - **CL-based**: uses class-group encryption and Pedersen-style commitments.
//!
//! # Protocol Flow
//!
//! 1. **KeyGen** (3-round DKG or trusted dealer): Feldman VSS + CL coin-toss
//!    + eVRF key generation.
//! 2. **Round 1 (Presign)**: eVRF eval -> nonce shares, CL-encrypt nonces,
//!    CL-commit blinding factors, prove consistency.
//! 3. **Round 2 (Sign)**: verify proofs, two scaled decryptions to get
//!    u*k and u*(H(m)+r*x), compute s = (u*k)^{-1} * u*(H(m)+r*x).
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

use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

/// Trout two-round threshold ECDSA protocol descriptor.
///
/// Uses CL encryption + eVRF + scaled decryption for 2-round signing
/// with O(1) communication and identifiable abort.
///
/// Trout types are NOT generic over `C: TecdsaCurve` because the underlying
/// CL-HSM encryption (bicycl-rs) is parameterized by a fixed curve order `q`
/// at setup time. The current implementation uses secp256k1 exclusively.
///
/// The protocol provides both pure round functions and `StateMachine`
/// trait implementations:
///
/// ## Pure functions (simulation mode)
/// 1. `keygen::trusted_dealer_keygen` -> `Vec<TroutKeyShare>`
/// 2. `presign::presign_round1` -> `(TroutRound1State, TroutRound1Broadcast)`
/// 3. `sign::sign_round2` -> `Signature`
///
/// ## StateMachine (orchestrator-compatible)
/// - `keygen::TroutKeygenMachine` -- 3-round interactive DKG (Protocol 3.1)
/// - `presign::machine::TroutPresignMachine` -- collects broadcasts, verifies
///   ZK proofs (R_CL-EC, R_ComKwlg), produces `TroutPresignOutput`
/// - `sign::machine::TroutSignMachine` -- wraps `sign_round2`, produces
///   `Signature`
///
/// ## Identifiable Abort (IA)
/// The IA variant uses `scaled_decrypt::compute_f_share_with_proof` to generate
/// R_affCom proofs for each scaled decryption share. If ECDSA verification
/// fails, `sign::identify_cheater` verifies individual proofs to identify the
/// cheating party.
///
/// ## MtA backend
///
/// Trout uses CL scaled decryption for its MtA sub-protocol.  The scaled
/// decryption backend implements [`tecdsa_protocol::MtABroadcast`] via
/// [`tecdsa_class_group::ScaledDecryptMtA`].  The protocol modules call
/// the lower-level CL primitives directly (via `scaled_decrypt`) because
/// Trout runs two distinct scaled decryption instances with different
/// effective encryption randomness, reuses intermediate `Qfi` elements
/// across both, and the IA variant requires `R_{affCom}` proofs not
/// modelled by the trait.  See module-level docs in [`presign`],
/// [`sign`], and `scaled_decrypt` for the correspondence table.
///
/// Reference: Dahari-Garbian, Nof, Parker. "Trout: Two-Round Threshold
/// ECDSA from Class Groups."
pub struct Trout;

impl Protocol for Trout {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::TroutKeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::TroutPresignOutput;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::TroutKeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::machine::TroutPresignMachine;
    type Sign = sign::machine::TroutSignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = metadata::METADATA;
}
