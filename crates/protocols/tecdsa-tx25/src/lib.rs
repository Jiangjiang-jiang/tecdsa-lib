// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! TX25 Robust Threshold ECDSA protocol.
//!
//! Implements the Tang-Xue 2025 robust threshold ECDSA protocol from
//! "Robust Threshold ECDSA" (S&P 2025). This protocol uses CL-based
//! encryption with public-checked MtA and provides:
//!
//! - **2-round presign (offline):** message-independent preprocessing
//!   using CL-based public-checked MtA for multiplicative-to-additive
//!   conversion.
//! - **1-round sign (online):** partial signature broadcast + assembly.
//! - **3-round keygen:** PVSS + CL-HSM key distribution.
//! - **Robustness + identifiable abort:** honest majority security
//!   ($n \ge 2t - 1$), UC-secure under static corruption.

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod mpmta;
pub mod presign;
pub mod pvss;
pub mod sign;

pub use key_share::Tx25KeyShare;
use tecdsa_protocol::{NoOpMachine, Protocol};

/// TX25 robust threshold ECDSA protocol descriptor.
///
/// Uses CL-based public-checked MtA for the presigning phase and provides
/// UC security with robustness and identifiable abort under an honest
/// majority assumption ($n \ge 2t - 1$).
///
/// TX25 types are NOT generic over `C: TecdsaCurve` because the underlying
/// CL-HSM encryption (bicycl-rs) is parameterized by a fixed curve order `q`
/// at setup time. The current implementation uses secp256k1 exclusively.
/// Generalizing would require `ClSetup` to be parameterized by the curve,
/// which is not supported by the bicycl-rs API.
///
/// Reference: Tang & Xue. "Robust Threshold ECDSA." S&P 2025.
pub struct Tx25;

impl Protocol for Tx25 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Tx25KeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Tx25Presignature;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Tx25KeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::Tx25PresignMachine;
    type Sign = sign::Tx25OnlineSignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: tecdsa_protocol::ProtocolMetadata = crate::metadata::METADATA;
}
