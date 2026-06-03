// SPDX-License-Identifier: GPL-3.0-or-later
//! TX25 presign message types and serialization helpers.

use serde::{Deserialize, Serialize};
use tecdsa_class_group::{
    cl::{ClCiphertext, Qfi},
    zk::{r_dec_dl::RDecDlProof, r_enc::REncProof, r_m_aff_dl_ec::RMAffDlEcProof, r_sh::RShProof},
};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Messages exchanged during TX25 presigning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Tx25PresignMsg {
    /// Round 1: C_gamma, R_Enc proof, PVSS (c1, {c2_j}, R_Sh proof).
    Round1(Vec<u8>),
    /// Round 2: {C_alpha, C_alpha_hat, B, B_hat}, R_i, R_Dec_DL proof,
    /// R_m_AffDL_Ec proofs.
    Round2(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Serialised CL types for messages
// ---------------------------------------------------------------------------

/// A CL ciphertext serialised as two binary QFI blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedClCt {
    pub(crate) c1: Vec<u8>,
    pub(crate) c2: Vec<u8>,
}

impl SerializedClCt {
    pub(crate) fn from_bicycl_ct(ct: &ClCiphertext) -> Result<Self, String> {
        Ok(Self {
            c1: ct.c1().to_bytes(),
            c2: ct.c2().to_bytes(),
        })
    }

    pub(crate) fn to_bicycl_ct(&self) -> Result<ClCiphertext, String> {
        let c1 = Qfi::from_bytes(&self.c1);
        let c2 = Qfi::from_bytes(&self.c2);
        Ok(ClCiphertext::new(c1, c2))
    }
}

/// A single QFI element serialised as compact binary bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedQfi {
    pub(crate) data: Vec<u8>,
}

impl SerializedQfi {
    pub(crate) fn from_qfi(qfi: &Qfi) -> Result<Self, String> {
        let data = qfi.to_bytes();
        Ok(Self { data })
    }

    pub(crate) fn to_qfi(&self) -> Result<Qfi, String> {
        Ok(Qfi::from_bytes(&self.data))
    }
}

// ---------------------------------------------------------------------------
// Serialised ZK proofs for messages
// ---------------------------------------------------------------------------

/// Serialised R_Enc proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerREncProof {
    pub(crate) t1: SerializedQfi,
    pub(crate) t2: SerializedQfi,
    pub(crate) u1: Vec<u8>,
    pub(crate) u2: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl SerREncProof {
    pub(crate) fn from_proof(proof: &REncProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(&proof.t1)?,
            t2: SerializedQfi::from_qfi(&proof.t2)?,
            u1: proof.u1.clone(),
            u2: proof.u2.clone(),
            e: proof.e.clone(),
        })
    }

    pub(crate) fn to_proof(&self) -> Result<REncProof, String> {
        Ok(REncProof {
            t1: self.t1.to_qfi()?,
            t2: self.t2.to_qfi()?,
            u1: self.u1.clone(),
            u2: self.u2.clone(),
            e: self.e.clone(),
        })
    }
}

/// Serialised R_Sh proof (already has pub fields: k, rho_response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRShProof {
    pub(crate) k: Vec<u8>,
    pub(crate) rho_response: Vec<u8>,
}

impl SerRShProof {
    pub(crate) fn from_proof(proof: &RShProof) -> Self {
        Self {
            k: proof.k.clone(),
            rho_response: proof.rho_response.clone(),
        }
    }

    pub(crate) fn to_proof(&self) -> RShProof {
        RShProof {
            k: self.k.clone(),
            rho_response: self.rho_response.clone(),
        }
    }
}

/// Serialised R_Dec_DL proof (pub fields: t1, t2, z, e).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRDecDlProof {
    pub(crate) t1: SerializedQfi,
    pub(crate) t2: SerializedQfi,
    pub(crate) z: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl SerRDecDlProof {
    pub(crate) fn from_proof(proof: &RDecDlProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(&proof.t1)?,
            t2: SerializedQfi::from_qfi(&proof.t2)?,
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }

    pub(crate) fn to_proof(&self) -> Result<RDecDlProof, String> {
        Ok(RDecDlProof {
            t1: self.t1.to_qfi()?,
            t2: self.t2.to_qfi()?,
            z: self.z.clone(),
            e: self.e.clone(),
        })
    }
}

/// Serialised R_m_AffDL_Ec proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRMAffDlEcProof {
    pub(crate) d_prime_1: SerializedQfi,
    pub(crate) d_prime_2: SerializedQfi,
    pub(crate) b0_bytes: Vec<u8>,
    pub(crate) r0_bytes: Vec<u8>,
    pub(crate) k_hat: Vec<u8>,
    pub(crate) beta_hat: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl SerRMAffDlEcProof {
    pub(crate) fn from_proof(proof: &RMAffDlEcProof) -> Result<Self, String> {
        Ok(Self {
            d_prime_1: SerializedQfi::from_qfi(&proof.d_prime_1)?,
            d_prime_2: SerializedQfi::from_qfi(&proof.d_prime_2)?,
            b0_bytes: proof.b0_bytes.clone(),
            r0_bytes: proof.r0_bytes.clone(),
            k_hat: proof.k_hat.clone(),
            beta_hat: proof.beta_hat.clone(),
            e: proof.e.clone(),
        })
    }

    pub(crate) fn to_proof(&self) -> Result<RMAffDlEcProof, String> {
        Ok(RMAffDlEcProof {
            d_prime_1: self.d_prime_1.to_qfi()?,
            d_prime_2: self.d_prime_2.to_qfi()?,
            b0_bytes: self.b0_bytes.clone(),
            r0_bytes: self.r0_bytes.clone(),
            k_hat: self.k_hat.clone(),
            beta_hat: self.beta_hat.clone(),
            e: self.e.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Round 1 message payload
// ---------------------------------------------------------------------------

/// Serialised Round 1 message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R1Payload {
    /// MPMtA Round 1: encrypted gamma_i.
    pub(crate) c_gamma: SerializedClCt,
    /// MPMtA Round 1: R_Enc proof for c_gamma.
    pub(crate) r_enc_proof: SerREncProof,
    /// PVSS c1 = h^rho (shared across all parties).
    pub(crate) pvss_c1: SerializedQfi,
    /// PVSS c2_j for each party j (encrypted shares).
    pub(crate) pvss_c2s: Vec<SerializedQfi>,
    /// PVSS R_Sh proof.
    pub(crate) pvss_proof: SerRShProof,
}

// ---------------------------------------------------------------------------
// Round 2 message payload
// ---------------------------------------------------------------------------

/// Per-party MtA output in Round 2 (for one counterparty j).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R2PerPartyMtA {
    /// C_alpha_{j,i} for k*gamma MtA.
    pub(crate) c_alpha: SerializedClCt,
    /// C_alpha_hat_{j,i} for x*gamma MtA.
    pub(crate) c_alpha_hat: SerializedClCt,
    /// B_{i,j} = beta_{i,j} * G (compressed bytes).
    pub(crate) b_point_bytes: Vec<u8>,
    /// B_hat_{i,j} = beta_hat_{i,j} * G (compressed bytes).
    pub(crate) b_hat_point_bytes: Vec<u8>,
}

/// Serialised Round 2 message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R2Payload {
    /// Per-counterparty MtA outputs (indexed by party position in all_parties).
    pub(crate) mta_outputs: Vec<R2PerPartyMtA>,
    /// R_i = k_i * G (compressed bytes).
    pub(crate) r_point_bytes: Vec<u8>,
    /// Partial decryption pd = c1^{sk} for R_Dec_DL verification.
    pub(crate) pd: SerializedQfi,
    /// The c1 that was used to compute pd (identifies which PVSS distribution).
    pub(crate) pd_c1: SerializedQfi,
    /// R_Dec_DL proof for ShareComb.
    pub(crate) dec_dl_proof: SerRDecDlProof,
    /// R_m_AffDL_Ec proof for k*gamma MPMtA2.
    pub(crate) kg_proof: SerRMAffDlEcProof,
    /// R_m_AffDL_Ec proof for x*gamma MPMtA2.
    pub(crate) xg_proof: SerRMAffDlEcProof,
}
