// SPDX-License-Identifier: GPL-3.0-or-later
//! Types for the Trout presigning protocol.

use tecdsa_class_group::zk::r_cl_dl_ec::RClDlEcProof;
use tecdsa_class_group::zk::r_com_kwlg::RComKwlgProof;
use tecdsa_evrf::{EvrfOutput, EvrfProof};
use zeroize::Zeroize;

/// Internal state preserved across rounds for a single party.
pub struct TroutRound1State {
    /// 1-based party index.
    pub party_index: u16,
    /// eVRF-derived nonce share k_i.
    pub k_i: k256::Scalar,
    /// Random blinding factor u_i.
    pub u_i: k256::Scalar,
    /// CL encryption randomness for K_tilde_i (decimal).
    pub alpha_i: Vec<u8>,
    /// CL commitment randomness for U_i (decimal).
    pub beta_i: Vec<u8>,
    /// Lagrange coefficient l_i for this party.
    pub l_i: k256::Scalar,
    /// l_i * delta_i (scaled encryption randomness, decimal).
    pub l_i_delta_i: Vec<u8>,
}

impl Zeroize for TroutRound1State {
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.u_i.zeroize();
        self.alpha_i.zeroize();
        self.beta_i.zeroize();
        self.l_i.zeroize();
        self.l_i_delta_i.zeroize();
    }
}

impl Drop for TroutRound1State {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Round 1 broadcast message.
pub struct TroutRound1Broadcast {
    /// 1-based party index.
    pub party_index: u16,
    /// R_i = k_i * H(nonce), compressed EC point bytes.
    pub r_i_bytes: Vec<u8>,
    /// eVRF output (Y = sk * H(input)).
    pub evrf_output: EvrfOutput<k256::Secp256k1>,
    /// eVRF DLEQ proof.
    pub evrf_proof: EvrfProof<k256::Secp256k1>,
    /// K_tilde_i component c1 as (a, b, c) decimal strings.
    pub kt_c1_abc: (String, String, String),
    /// K_tilde_i component c2 as (a, b, c) decimal strings.
    pub kt_c2_abc: (String, String, String),
    /// U_i commitment as (a, b, c) decimal strings.
    pub u_com_abc: (String, String, String),
    /// Lagrange-scaled C_tilde_i c1 as (a, b, c) decimal strings.
    pub ct_scaled_c1_abc: (String, String, String),
    /// Lagrange-scaled C_tilde_i c2 as (a, b, c) decimal strings.
    pub ct_scaled_c2_abc: (String, String, String),
    /// R_{CL-EC} proof: K_tilde_i encrypts same k_i as R_i.
    pub pi_cl_ec: RClDlEcProof,
    /// R_{ComKwlg} proof: knowledge of (u_i, beta_i) in U_i = Com(beta_i, u_i).
    pub pi_com_kwlg: RComKwlgProof,
}

/// Output of the presigning phase, consumed by the signing phase.
pub struct TroutPresignOutput {
    /// This party's 1-based index.
    pub party_index: u16,
    /// The aggregated nonce point R = sum(R_j).
    pub big_r: k256::ProjectivePoint,
    /// r = x-coordinate of R mod q.
    pub r_scalar: k256::Scalar,
    /// This party's nonce share k_i.
    pub k_i: k256::Scalar,
    /// This party's blinding factor u_i.
    pub u_i: k256::Scalar,
    /// This party's CL encryption randomness alpha_i (decimal).
    pub alpha_i: Vec<u8>,
    /// This party's CL commitment randomness beta_i (decimal).
    pub beta_i: Vec<u8>,
    /// Lagrange coefficient l_i.
    pub l_i: k256::Scalar,
    /// l_i * delta_i (scaled encryption randomness, decimal).
    pub l_i_delta_i: Vec<u8>,
    /// All parties' Round 1 broadcasts (needed for scaled decryption).
    pub all_broadcasts: Vec<TroutRound1Broadcast>,
}

impl Zeroize for TroutPresignOutput {
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.u_i.zeroize();
        self.alpha_i.zeroize();
        self.beta_i.zeroize();
        self.l_i.zeroize();
        self.l_i_delta_i.zeroize();
    }
}

impl Drop for TroutPresignOutput {
    fn drop(&mut self) {
        self.zeroize();
    }
}
