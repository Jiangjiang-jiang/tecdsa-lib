// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! WMY23 Real Threshold ECDSA protocol.
//!
//! Implements the Wang-Mei-Yu 2023 threshold ECDSA protocol from
//! "Real Threshold ECDSA" (NDSS 2023). This protocol uses CL-based
//! encryption for MtA (MtAwc) and provides:
//!
//! - **4-round presign (offline):** DRG (Pedersen VSS + CL verifiable
//!   encryption + R_Enc-PC proofs), CL-based MtAwc for
//!   multiplicative-to-additive conversion, and share revelation. The MtAwc
//!   receiver ciphertext is the bound `DRG.Comb` output `c_{k_j}` (reused for
//!   both the `k*gamma` and `k*x` conversions), and each decryption is
//!   checked algebraically (Fig. 1 Step 3) after `DRG.CombVf`/`ExpVf`. The
//!   MtAwc material `{c_alpha, B, c_mu, N}` is **broadcast** (WMY23 Fig. 5),
//!   and in the share-revelation phase each party broadcasts `D_i` with a
//!   `pi_{D_i}` proof and *every* party cross-verifies *every* party's share
//!   via Equation (2) — so a malformed pseudo-nonce share is detected and
//!   attributed (O(n^2) communication, as in the paper).
//! - **1-round sign (online):** each party broadcasts its partial signature
//!   together with the MtAwc shares-in-exponent `M_{ij}`/`N_{ij}` and a
//!   NIZKDL-2PC proof (`R_DL-2PC`, Fig. 13); every party verifies the proofs
//!   and the share-consistency Equation (3) before assembly, so a faulty
//!   signer is identified (WMY23 Figs 7-9, Sec. V-D) rather than silently
//!   producing an invalid signature.
//! - **4-round keygen:** DRG-based Pedersen VSS + CL-HSM key distribution.
//! - **Self-healing + cheater identification:** dishonest minority security.
//!
//! # Security Warning
//!
//! The share-revelation phase now implements the paper's identifiable
//! cross-verification (broadcast MtAwc material + per-party `pi_{D_i}` and
//! Equation (2) checks), so a malformed revealed pseudo-nonce share is
//! detected and the offending party is reported via [`IaReport`] rather than
//! being silently accepted. This matches WMY23 Figure 5 / Section V-D.
//!
//! However, the *broader robustness/self-healing* claim of WMY23 is still
//! challenged by Tang and Xue (TX25, Section 5), whose "concurrent exclusion"
//! analysis targets the protocol's recovery behaviour after exclusion (not
//! merely the absence of the Phase-3 check). **Do not rely on this protocol's
//! self-healing robustness property in production**; use TX25 for robust
//! threshold ECDSA. Identifiable abort (detect-and-blame) is provided.
//!
//! [`IaReport`]: tecdsa_protocol::IaReport

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod mtawc;
pub mod nizk;
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
