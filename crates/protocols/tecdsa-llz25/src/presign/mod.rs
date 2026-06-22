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
//! ## Offline NIM decoding (end of presign)
//!
//! Once the quorum's presign messages $\{pm_j^{(1)}\}$ are collected, party
//! $i$ performs **all NIM decoding** via [`compute_presign_coefficients`].
//! These decodes recover the additive MtA shares of $k\gamma$ and $x\gamma$,
//! and depend only on presign material and key shares -- **not on the
//! message**.  They are therefore part of the offline phase: the online sign
//! phase consumes the resulting [`PresignCoefficients`] and never touches the
//! class group.
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
    nim::{Nim, NimEncodeAOutput, NimEncodeBOutput, NimStateA, NimStateB},
    zk::{r_cl_dl_ec::RClDlEcProof, r_ped_ec::RPedEcProof},
};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

use crate::{error::Llz25Error, key_share::Llz25KeyShare};

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

/// Message-independent signing coefficients, computed at the end of presign.
///
/// These fold in every NIM-decoded MtA share so that the online sign phase
/// reduces to a few hashes, one EC double-scalar multiplication for $R$, and
/// two scalar combinations.  They contain secret material and must be
/// protected like the rest of the presignature.
pub struct PresignCoefficients {
    /// $\gamma_i$ (carried over from the presign state for the online phase).
    pub gamma_i: k256::Scalar,
    /// $u$-coefficient: $k_i \gamma_i + \sum_{j \neq i}(\alpha_{i,j} + \beta_{j,i})$,
    /// party $i$'s additive share of $k\gamma$.
    pub u_coeff: k256::Scalar,
    /// $w$-coefficient: $\lambda_i x_i \gamma_i + \sum_{j \neq i}(\mu_{i,j} + \nu_{j,i})$,
    /// party $i$'s additive share of $x\gamma$.
    pub w_coeff: k256::Scalar,
}

impl Zeroize for PresignCoefficients {
    fn zeroize(&mut self) {
        self.gamma_i.zeroize();
        self.u_coeff.zeroize();
        self.w_coeff.zeroize();
    }
}

impl Drop for PresignCoefficients {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for PresignCoefficients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresignCoefficients")
            .finish_non_exhaustive()
    }
}

/// Compute the Lagrange coefficient $\lambda_{i,P}$ for the party at `my_pos`
/// among the 1-based `indices`, evaluated at $x = 0$.
fn lagrange_coefficient(indices: &[u16], my_pos: usize) -> k256::Scalar {
    let xi = k256::Scalar::from(u64::from(indices[my_pos]));
    let mut result = k256::Scalar::ONE;
    for (j, &idx) in indices.iter().enumerate() {
        if j == my_pos {
            continue;
        }
        let xj = k256::Scalar::from(u64::from(idx));
        let diff_inv = (xj - xi)
            .invert()
            .expect("distinct indices guarantee non-zero denominator");
        result *= xj * diff_inv;
    }
    result
}

/// Perform all offline NIM decoding and build the [`PresignCoefficients`].
///
/// This is the **offline** counterpart to online signing: it does every
/// class-group operation needed for the MtA products, none of which depend on
/// the message.  It runs once the quorum's presign messages are available
/// (e.g. at the end of the presign state machine).
///
/// For each other quorum member $j$ (at position `j` in the quorum):
/// - $\alpha_{i,j} = \mathrm{NIM.Decode\_B}(pe_{\gamma,j}, st_{k,i})$ -- share of $k_i \gamma_j$
/// - $\beta_{j,i} = \mathrm{NIM.Decode\_A}(pe_{k,j}, st_{\gamma,i})$ -- share of $\gamma_i k_j$
/// - $\mu_{i,j} = \lambda_i \cdot \mathrm{NIM.Decode\_B}(pe_{\gamma,j}, st_{x,i})$ -- share of $\lambda_i x_i \gamma_j$
/// - $\nu_{j,i} = \lambda_j \cdot \mathrm{NIM.Decode\_A}(pe_{x,j}, st_{\gamma,i})$ -- share of $\lambda_j x_j \gamma_i$
///
/// # Arguments
/// - `setup`: mutable CL setup (needed by the NIM decode methods).
/// - `key_share`: this party's key share from keygen (for $x_i$ and $st_{x,i}$).
/// - `presign_state`: this party's presign state from Round 1.
/// - `presign_messages`: presign messages from ALL parties in the quorum.
/// - `pe_x_list`: $pe_{x,j}$ ciphertexts from keygen for each quorum party.
/// - `quorum_indices`: 1-based party indices in the quorum.
/// - `my_pos`: this party's position in the quorum (0-based).
#[allow(clippy::too_many_arguments)]
pub fn compute_presign_coefficients(
    setup: &mut ClSetup,
    key_share: &Llz25KeyShare,
    presign_state: &PresignState,
    presign_messages: &[PresignMessage],
    pe_x_list: &[ClHsmqkCiphertext],
    quorum_indices: &[u16],
    my_pos: usize,
) -> Result<PresignCoefficients, Llz25Error> {
    let n_quorum = quorum_indices.len();

    // Lagrange coefficient for this party within the quorum.
    let my_lambda = lagrange_coefficient(quorum_indices, my_pos);

    let pst = presign_state;

    // Accumulate the cross-party MtA shares.
    let mut alpha_beta_sum = k256::Scalar::ZERO;
    let mut mu_nu_sum = k256::Scalar::ZERO;

    // Create NIM context for decoding.
    let nim = Nim::new(setup);

    // Reconstruct NIM states.
    let st_k = NimStateB {
        s_bytes: pst.st_k_bytes.clone(),
    };
    let st_gamma = NimStateA {
        r_bytes: pst.st_gamma_r_bytes.clone(),
        x_bytes: pst.st_gamma_x_bytes.clone(),
    };
    let st_x = NimStateB {
        s_bytes: key_share.st_x_bytes.clone(),
    };

    for j in 0..n_quorum {
        if j == my_pos {
            continue;
        }

        let pm_j = &presign_messages[j];

        // alpha_{i,j} = NIM.Decode_B(pe_{gamma,j}, st_{k,i})
        let alpha_bytes = nim
            .decode_b(&pm_j.pe_gamma, &st_k)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_b alpha: {e}")))?;
        let alpha_ij = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_bytes);

        // beta_{j,i} = NIM.Decode_A(pe_{k,j}, st_{gamma,i})
        let beta_bytes = nim
            .decode_a(&pm_j.pe_k, &st_gamma)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_a beta: {e}")))?;
        let beta_ji = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&beta_bytes);

        alpha_beta_sum += alpha_ij + beta_ji;

        // mu_{i,j} = lambda_i * NIM.Decode_B(pe_{gamma,j}, st_{x,i})
        let mu_bytes = nim
            .decode_b(&pm_j.pe_gamma, &st_x)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_b mu: {e}")))?;
        let mu_ij = my_lambda * tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&mu_bytes);

        // nu_{j,i} = lambda_j * NIM.Decode_A(pe_{x,j}, st_{gamma,i})
        let lambda_j = lagrange_coefficient(quorum_indices, j);
        let nu_bytes = nim
            .decode_a(&pe_x_list[j], &st_gamma)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_a nu: {e}")))?;
        let nu_ji = lambda_j * tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&nu_bytes);

        mu_nu_sum += mu_ij + nu_ji;
    }

    // Self-product terms.
    let k_i_gamma_i = pst.k_i * pst.gamma_i;
    let lambda_i_x_i_gamma_i = my_lambda * key_share.secret_share * pst.gamma_i;

    Ok(PresignCoefficients {
        gamma_i: pst.gamma_i,
        u_coeff: k_i_gamma_i + alpha_beta_sum,
        w_coeff: lambda_i_x_i_gamma_i + mu_nu_sum,
    })
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
