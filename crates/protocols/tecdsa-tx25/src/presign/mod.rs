// SPDX-License-Identifier: MIT OR Apache-2.0
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
    clippy::module_name_repetitions,
    non_snake_case
)]

//! TX25 presigning protocol (2 rounds + offline output computation).
//!
//! Produces a message-independent [`Tx25Presignature`] using CL-based
//! public-checked MtA (MPMtA) and Cascudo-David PVSS for distributed
//! randomness generation.
//!
//! ## Protocol Rounds (TX25 Section 4.2)
//!
//! 1. **Round 1 (MPMtA1 + DRG ShareDist):** each party samples gamma_i,
//!    encrypts it via MPMtA1 (R_Enc proof), and distributes k_i shares
//!    via PVSS (R_Sh proof). Broadcast all data.
//! 2. **Round 2 (ShareComb + MPMtA2):** verify Round 1 proofs, decrypt
//!    own PVSS share to get k_i (ShareComb + R_Dec_DL proof), then run
//!    MPMtA2 for both k*gamma and x*gamma products. Broadcast results.
//! 3. **Offline output:** verify Round 2 proofs, decrypt alpha values,
//!    reconstruct R via Lagrange interpolation, store presignature.
//!
//! ## CL Type Serialization
//!
//! CL ciphertexts and QFI elements in messages are serialised using compact
//! binary encoding via `Qfi::to_bytes`/`from_bytes` (bicycl-rs v0.2.3).
//! Internal state stores CL types directly (`Send` since bicycl-rs v0.2.2).
//!
//! Reference: Tang & Xue. "Robust Threshold ECDSA." S&P 2025, Section 4.2.

pub mod machine;
pub mod msg;
pub mod rounds;

use std::collections::BTreeMap;

pub use machine::Tx25PresignMachine;
pub use msg::Tx25PresignMsg;
use tecdsa_class_group::cl::ClPublicKey;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Presignature output
// ---------------------------------------------------------------------------

/// Presignature produced by the TX25 presign protocol.
///
/// Contains the nonce point $R$, nonce share $k_i$, and the party's
/// sigma share $\sigma_i$ needed for the online signing phase.
///
/// Additionally stores the per-pair additive shares $\delta_{i,j}$ and
/// $\zeta_{i,j}$ from MPMtA, the party's gamma share $\gamma_i$, and the
/// public beta commitment points $B_{j,\nu}$ / $\hat{B}_{j,\nu}$ needed
/// for cheater identification in the online phase.
#[derive(Clone)]
pub struct Tx25Presignature {
    /// The nonce point $R = \sum \lambda_{j,S} \cdot R_j = k \cdot G$ (TX25 convention).
    pub r_point: k256::ProjectivePoint,
    /// The x-coordinate of R reduced mod q.
    pub r_x: k256::Scalar,
    /// This party's nonce share $k_i$.
    pub k_share: k256::Scalar,
    /// This party's gamma share $\gamma_i$ (used in MPMtA for $k_i \cdot \gamma_j$).
    pub gamma_i: k256::Scalar,
    /// This party's sigma share $\sigma_i = k_i \cdot x_i + \text{MtA correction}$.
    pub sigma_share: k256::Scalar,
    /// Pairwise additive shares $\delta_{i,j} = \alpha_{i,j} + \beta_{j,i}$
    /// from the $k \cdot \gamma$ MPMtA, keyed by counterparty id.
    pub delta_shares: BTreeMap<u16, k256::Scalar>,
    /// Pairwise additive shares $\zeta_{i,j} = \alpha'_{i,j} + \beta'_{j,i}$
    /// from the $k \cdot x$ MPMtA, keyed by counterparty id.
    pub zeta_shares: BTreeMap<u16, k256::Scalar>,
    /// Public beta commitment points $B_{j,\nu} = \beta_{j,\nu} \cdot G$
    /// from the $k \cdot \gamma$ MPMtA (all parties), keyed by (j, nu).
    pub b_points: BTreeMap<(u16, u16), k256::ProjectivePoint>,
    /// Public beta commitment points $\hat{B}_{j,\nu} = \hat\beta_{j,\nu} \cdot G$
    /// from the $k \cdot x$ MPMtA (all parties), keyed by (j, nu).
    pub b_hat_points: BTreeMap<(u16, u16), k256::ProjectivePoint>,
    /// This party's index (1-based).
    pub party_index: u16,
    /// Reconstruction threshold $t$ ($t$ parties needed to sign).
    pub threshold: u16,
}

impl Zeroize for Tx25Presignature {
    fn zeroize(&mut self) {
        self.k_share.zeroize();
        self.gamma_i.zeroize();
        self.sigma_share.zeroize();
        for v in self.delta_shares.values_mut() {
            v.zeroize();
        }
        for v in self.zeta_shares.values_mut() {
            v.zeroize();
        }
    }
}

impl Drop for Tx25Presignature {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Tx25Presignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tx25Presignature")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Key material extracted from Tx25KeyShare
// ---------------------------------------------------------------------------

/// Key material extracted from `Tx25KeyShare` for use across rounds.
///
/// Avoids needing to clone the full key share (which contains non-Clone
/// CL secret key types) by extracting owned values.
pub(crate) struct KeyMaterial {
    /// This party's CL secret key as decimal string.
    pub(crate) sk_decimal: Vec<u8>,
    /// All parties' raw CL public keys (same order as all_parties).
    pub(crate) raw_pks: Vec<ClPublicKey>,
    /// This party's signing key share x_i.
    pub(crate) x_i: k256::Scalar,
    /// Joint public key (used in future proof verification).
    #[allow(dead_code)]
    pub(crate) public_key: k256::ProjectivePoint,
    /// All parties' public shares X_j = x_j * G (same order as all_parties).
    pub(crate) public_shares: Vec<k256::ProjectivePoint>,
    /// Threshold.
    pub(crate) threshold: u16,
}

impl Zeroize for KeyMaterial {
    fn zeroize(&mut self) {
        self.sk_decimal.zeroize();
        self.x_i.zeroize();
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}
