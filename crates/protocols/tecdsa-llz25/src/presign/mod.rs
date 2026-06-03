// SPDX-License-Identifier: MIT OR Apache-2.0
//! LLZ25 presigning protocol (Round 1).
//!
//! ## Protocol (LLZ25, Section 4.2 -- Presign)
//!
//! Each party $i$:
//! 1. Sample $k_i, \gamma_i \gets \mathbb{Z}_q$.
//! 2. Compute:
//!    - $K_i = k_i \cdot G$
//!    - $(pe_{k,i}, st_{k,i}) \gets \text{NIM.Encode\_B}(crs, k_i)$
//!    - $(pe_{\gamma,i}, st_{\gamma,i}) \gets \text{NIM.Encode\_A}(crs, \gamma_i)$
//! 3. Prove $\pi_i$: `R_{CL-DL}` on $(pe_{k,i}, K_i)$ and `R_{Ped}` on
//!    $(pe_{\gamma,i}, \Gamma_i = \gamma_i \cdot G)$.
//! 4. Broadcast $pm_i^{(1)} = (K_i, \Gamma_i, pe_{k,i}, pe_{\gamma,i}, \pi_i)$.
//! 5. Store $pst_i = (k_i, \gamma_i, st_{k,i}, st_{\gamma,i})$.
//!
//! ## Relationship to `MtABroadcast` trait
//!
//! The NIM encode/decode pattern implements the [`tecdsa_protocol::MtABroadcast`]
//! trait via [`tecdsa_class_group::NimMtA`].  However, this module calls the
//! underlying [`Nim`] API directly for two reasons:
//!
//! 1. **Dual-role usage**: LLZ25 uses NIM with both roles in the same party
//!    (`Encode_B` for $k_i$, `Encode_A` for $\gamma_i$).  The `NimMtA`
//!    wrapper expects each setup to be bound to a single `NimRole`, so each
//!    party would need two distinct setup instances.
//!
//! 2. **ZK proof integration**: The `R_{CL-DL-EC}` and `R_{Ped-EC}` proofs
//!    require access to the raw NIM state fields (`s_decimal`, `r_decimal`),
//!    which the `MtABroadcast` trait's opaque `State` type hides.
//!
//! The trait-level API is available at [`tecdsa_class_group::NimMtA`] for
//! use cases where the full NIM state is not needed.

#![allow(non_snake_case)]

pub mod machine;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use tecdsa_class_group::{
    cl::{ClCiphertext as ClHsmqkCiphertext, ClPublicKey as ClHsmqkPublicKey, ClSetup, Qfi},
    nim::{Nim, NimEncodeAOutput, NimEncodeBOutput},
    zk::{r_cl_dl_ec::RClDlEcProof, r_ped_ec::RPedEcProof},
};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

use crate::error::Llz25Error;

/// Presign broadcast message from party $i$: $pm_i^{(1)}$.
pub struct PresignMessage {
    /// $K_i = k_i \cdot G$.
    pub big_k: k256::ProjectivePoint,
    /// $\Gamma_i = \gamma_i \cdot G$ (simplified -- no EC Pedersen blinding).
    pub big_gamma: k256::ProjectivePoint,
    /// NIM `Encode_B` ciphertext of $k_i$.
    pub pe_k: ClHsmqkCiphertext,
    /// NIM `Encode_A` commitment of $\gamma_i$ (QFI in CL group).
    pub pe_gamma: Qfi,
    /// ZK proof: $pe_{k,i}$ encrypts the dlog of $K_i$.
    pub proof_cl: RClDlEcProof,
    /// ZK proof: $pe_{\gamma,i}$ commits to the dlog of $\Gamma_i$.
    pub proof_ped: RPedEcProof,
}

/// Presign secret state kept by party $i$: $pst_i$.
pub struct PresignState {
    /// $k_i$.
    pub k_i: k256::Scalar,
    /// $\gamma_i$.
    pub gamma_i: k256::Scalar,
    /// NIM state for $pe_{k,i}$ (Encode_B randomness).
    pub st_k_bytes: Vec<u8>,
    /// NIM state for $pe_{\gamma,i}$ (Encode_A randomness).
    pub st_gamma_r_bytes: Vec<u8>,
    /// NIM state for $pe_{\gamma,i}$ (Encode_A input).
    pub st_gamma_x_bytes: Vec<u8>,
}

impl Zeroize for PresignState {
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.gamma_i.zeroize();
        self.st_k_bytes.zeroize();
        self.st_gamma_r_bytes.zeroize();
        self.st_gamma_x_bytes.zeroize();
    }
}

impl Drop for PresignState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Execute presign Round 1 for a single party.
///
/// Returns the broadcast message and secret state.
pub fn presign_round1(
    setup: &mut ClSetup,
    pk_crs: &ClHsmqkPublicKey,
) -> Result<(PresignMessage, PresignState), Llz25Error> {
    let mut rng = rand::thread_rng();

    // 1. Sample k_i, gamma_i.
    let k_i = k256::Secp256k1::random_scalar(&mut rng);
    let gamma_i = k256::Secp256k1::random_scalar(&mut rng);

    // 2. Compute K_i and Gamma_i.
    let big_k = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * k_i;
    let big_gamma = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * gamma_i;

    let k_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&k_i);
    let gamma_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&gamma_i);

    // 3a. NIM.Encode_B(crs, k_i) -- CL encryption.
    let mut nim = Nim::new(setup);
    let NimEncodeBOutput {
        pe_b: pe_k,
        state: st_k,
    } = nim
        .encode_b(&k_bytes, pk_crs)
        .map_err(|e| Llz25Error::ClassGroup(format!("NIM.Encode_B(k_i) failed: {e}")))?;

    // 3b. NIM.Encode_A(crs, gamma_i) -- Pedersen CL commitment.
    let NimEncodeAOutput {
        pe_a: pe_gamma,
        state: st_gamma,
    } = nim
        .encode_a(&gamma_bytes, pk_crs)
        .map_err(|e| Llz25Error::ClassGroup(format!("NIM.Encode_A(gamma_i) failed: {e}")))?;

    // 4a. ZK proof: R_{CL-DL-EC} for (pe_k, K_i).
    let big_k_bytes = big_k.to_bytes().to_vec();
    let proof_cl = RClDlEcProof::prove(setup, pk_crs, &pe_k, &big_k_bytes, &k_bytes, &st_k.s_bytes)
        .map_err(|e| Llz25Error::ClassGroup(format!("R_CL_DL_EC prove failed: {e}")))?;

    // 4b. ZK proof: R_{Ped-EC} for (pe_gamma, Gamma_i).
    let big_gamma_bytes = big_gamma.to_bytes().to_vec();
    let proof_ped = RPedEcProof::prove(
        setup,
        pk_crs,
        &pe_gamma,
        &big_gamma_bytes,
        &gamma_bytes,
        &st_gamma.r_bytes,
    )
    .map_err(|e| Llz25Error::ClassGroup(format!("R_Ped_EC prove failed: {e}")))?;

    let message = PresignMessage {
        big_k,
        big_gamma,
        pe_k,
        pe_gamma,
        proof_cl,
        proof_ped,
    };

    let state = PresignState {
        k_i,
        gamma_i,
        st_k_bytes: st_k.s_bytes,
        st_gamma_r_bytes: st_gamma.r_bytes,
        st_gamma_x_bytes: st_gamma.x_bytes,
    };

    Ok((message, state))
}

/// Verify a presign message from another party.
///
/// Checks the two ZK proofs embedded in the presign message.
pub fn verify_presign_message(
    setup: &ClSetup,
    pk_crs: &ClHsmqkPublicKey,
    msg: &PresignMessage,
) -> Result<bool, Llz25Error> {
    let big_k_bytes = msg.big_k.to_bytes().to_vec();
    let big_gamma_bytes = msg.big_gamma.to_bytes().to_vec();

    // Verify R_{CL-DL-EC} proof.
    let cl_ok = msg
        .proof_cl
        .verify(setup, pk_crs, &msg.pe_k, &big_k_bytes)
        .map_err(|e| Llz25Error::ClassGroup(format!("R_CL_DL_EC verify failed: {e}")))?;

    // Verify R_{Ped-EC} proof.
    let ped_ok = msg
        .proof_ped
        .verify(setup, pk_crs, &msg.pe_gamma, &big_gamma_bytes)
        .map_err(|e| Llz25Error::ClassGroup(format!("R_Ped_EC verify failed: {e}")))?;

    Ok(cl_ok && ped_ok)
}

impl std::fmt::Debug for PresignMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresignMessage").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PresignState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresignState").finish_non_exhaustive()
    }
}
