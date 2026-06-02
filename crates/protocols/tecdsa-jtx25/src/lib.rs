// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
//! JTX25 Threshold ECDSA from Threshold CL Encryption.
//!
//! Implements the Jiang-Tang-Xue 2025 protocol:
//! - **3-round keygen:** PVSS for ECDSA key + threshold CL DKG
//! - **2-round presign (offline):** threshold CL homomorphic operations
//! - **1-round sign (online):** threshold CL partial decryption + assembly
//! - **Normal variant:** additive nonce sharing among signing set (no DRG)
//! - **Robust variant** (`robust` feature): DRG for k_i, tolerates dropouts after presign
//!
//! # License
//!
//! GPL-3.0-or-later (tecdsa-class-group dependency).

pub(crate) mod cl_wire;
pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;

use tecdsa_protocol::{NoOpMachine, Protocol};

pub use key_share::Jtx25KeyShare;

/// JTX25 robust threshold ECDSA protocol descriptor.
///
/// JTX25 is NOT generic over `C: TecdsaCurve` because the underlying
/// CL-HSM encryption (bicycl-rs) is parameterized by a fixed curve
/// order `q` at setup time; secp256k1 only.
pub struct Jtx25;

impl Protocol for Jtx25 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Jtx25KeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Jtx25Presignature;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Jtx25KeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::Jtx25PresignMachine;
    type Sign = sign::Jtx25OnlineSignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: tecdsa_protocol::ProtocolMetadata = crate::metadata::METADATA;
}
