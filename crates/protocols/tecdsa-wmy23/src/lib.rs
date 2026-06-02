// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
//! WMY23 Real Threshold ECDSA protocol.
//!
//! Implements the Wang-Mei-Yu 2023 threshold ECDSA protocol from
//! "Real Threshold ECDSA" (NDSS 2023). This protocol uses CL-based
//! encryption for MtA (MtAwc) and provides:
//!
//! - **4-round presign (offline):** message-independent preprocessing
//!   using CL-based MtAwc for multiplicative-to-additive conversion.
//! - **1-round sign (online):** partial signature broadcast + assembly.
//! - **4-round keygen:** Feldman VSS + CL-HSM key distribution.
//! - **Self-healing + cheater identification:** dishonest minority security.
//!
//! # Security Warning
//!
//! The robustness claim of WMY23 is challenged by Tang and Xue (TX25,
//! Section 5), who present a concrete attack exploiting the "concurrent
//! exclusion" gap in the share-revelation phase (Figure 5, Phase 3).
//! A malicious party can cause an honest party to output an incorrect
//! presignature without being detected. **Do not rely on this protocol's
//! robustness property in production.** Use TX25 for robust threshold
//! ECDSA instead. The keygen and non-robust signing phases are unaffected.
//!
//! # License
//!
//! This crate is **GPL-3.0-or-later** due to the `tecdsa-class-group`
//! dependency (which wraps the BICYCL C library).

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod mtawc;
pub mod presign;
pub mod sign;

use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

/// WMY23 threshold ECDSA protocol descriptor.
///
/// Uses CL-based MtA (MtAwc) for the presigning phase and provides
/// game-based security with self-healing and cheater identification
/// under a dishonest minority assumption.
///
/// WMY23 types are NOT generic over `C: TecdsaCurve` because the underlying
/// CL-HSM encryption (bicycl-rs) is parameterized by a fixed curve order `q`
/// at setup time. The current implementation uses secp256k1 exclusively.
/// Generalizing would require `ClSetup` to be parameterized by the curve,
/// which is not supported by the bicycl-rs API.
///
/// Reference: Wang, Mei, Yu. "Real Threshold ECDSA." NDSS 2023.
pub struct Wmy23;

impl Protocol for Wmy23 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Wmy23KeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Wmy23Presignature;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Wmy23KeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::Wmy23PresignMachine;
    type Sign = sign::Wmy23OnlineSignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}
