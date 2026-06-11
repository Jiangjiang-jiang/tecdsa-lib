// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::module_name_repetitions)]

//! Shared CL serialization types and helpers for JTX25 protocol messages.
//!
//! Eliminates duplication across presign, sign, and their robust variants.

use elliptic_curve::group::GroupEncoding;
use serde::{Deserialize, Serialize};
#[cfg(feature = "robust")]
use tecdsa_class_group::zk::r_enc_pc::REncPcProof;
#[cfg(feature = "robust")]
use tecdsa_class_group::zk::r_pc_dl::RPcDlProof;
use tecdsa_class_group::{
    cl::{ClCiphertext, ClSetup, Qfi},
    zk::{r_dl_cl::RDlClProof, r_enc::REncProof, r_part_dec::RPartDecProof},
};

use crate::error::Jtx25Error;

// ---------------------------------------------------------------------------
// Serialized class-group element (compact binary `Qfi::to_bytes`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedQfi {
    pub data: Vec<u8>,
}

impl SerializedQfi {
    pub fn from_qfi(qfi: &Qfi) -> Result<Self, String> {
        let data = qfi.to_bytes();
        Ok(Self { data })
    }

    pub fn to_qfi(&self) -> Result<Qfi, String> {
        Ok(Qfi::from_bytes(&self.data))
    }
}

// ---------------------------------------------------------------------------
// Serialized CL ciphertext (pair of Qfi)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedClCt {
    pub c1: SerializedQfi,
    pub c2: SerializedQfi,
}

impl SerializedClCt {
    pub fn from_bicycl_ct(ct: &ClCiphertext) -> Result<Self, String> {
        Ok(Self {
            c1: SerializedQfi::from_qfi(ct.c1())?,
            c2: SerializedQfi::from_qfi(ct.c2())?,
        })
    }

    pub fn to_bicycl_ct(&self) -> Result<ClCiphertext, String> {
        let c1 = self.c1.to_qfi()?;
        let c2 = self.c2.to_qfi()?;
        Ok(ClCiphertext::new(c1, c2))
    }
}

// ---------------------------------------------------------------------------
// Serialized ZK proofs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerREncProof {
    pub t1: SerializedQfi,
    pub t2: SerializedQfi,
    pub u1: Vec<u8>,
    pub u2: Vec<u8>,
    pub e: Vec<u8>,
}

impl SerREncProof {
    pub fn from_proof(proof: &REncProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(&proof.t1)?,
            t2: SerializedQfi::from_qfi(&proof.t2)?,
            u1: proof.u1.clone(),
            u2: proof.u2.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self) -> Result<REncProof, String> {
        Ok(REncProof {
            t1: self.t1.to_qfi()?,
            t2: self.t2.to_qfi()?,
            u1: self.u1.clone(),
            u2: self.u2.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRDlClProof {
    pub t1: SerializedQfi,
    pub t2: SerializedQfi,
    pub t_ec_bytes: Vec<u8>,
    pub z: Vec<u8>,
    pub e: Vec<u8>,
}

impl SerRDlClProof {
    pub fn from_proof(proof: &RDlClProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(&proof.t1)?,
            t2: SerializedQfi::from_qfi(&proof.t2)?,
            t_ec_bytes: proof.t_ec_bytes.clone(),
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self) -> Result<RDlClProof, String> {
        Ok(RDlClProof {
            t1: self.t1.to_qfi()?,
            t2: self.t2.to_qfi()?,
            t_ec_bytes: self.t_ec_bytes.clone(),
            z: self.z.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRPartDecProof {
    pub t1: SerializedQfi,
    pub t2: SerializedQfi,
    pub z: Vec<u8>,
    pub e: Vec<u8>,
}

impl SerRPartDecProof {
    pub fn from_proof(proof: &RPartDecProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(&proof.t1)?,
            t2: SerializedQfi::from_qfi(&proof.t2)?,
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self) -> Result<RPartDecProof, String> {
        Ok(RPartDecProof {
            t1: self.t1.to_qfi()?,
            t2: self.t2.to_qfi()?,
            z: self.z.clone(),
            e: self.e.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn point_from_bytes(bytes: &[u8], label: &str) -> Result<k256::ProjectivePoint, String> {
    let repr = k256::CompressedPoint::try_from(bytes)
        .map_err(|e| format!("invalid point bytes ({label}): {e}"))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| format!("invalid EC point: {label}"))
}

pub(crate) fn scalar_mul_ct(
    setup: &ClSetup,
    ct: &ClCiphertext,
    x_bytes: &[u8],
) -> Result<ClCiphertext, Jtx25Error> {
    let (c1, c2) = setup.ct_components(ct)?;
    let c1_x = setup.exp_bytes(&c1, x_bytes)?;
    let c2_x = setup.exp_bytes(&c2, x_bytes)?;
    let result = setup.ct_from_components(&c1_x, &c2_x)?;
    Ok(result)
}

pub(crate) fn add_ct_components(
    setup: &ClSetup,
    ct_a: &ClCiphertext,
    ct_b: &ClCiphertext,
) -> Result<ClCiphertext, Jtx25Error> {
    let (a1, a2) = setup.ct_components(ct_a)?;
    let (b1, b2) = setup.ct_components(ct_b)?;
    let c1 = setup.compose(&a1, &b1)?;
    let c2 = setup.compose(&a2, &b2)?;
    Ok(setup.ct_from_components(&c1, &c2)?)
}

pub(crate) fn copy_ct(setup: &ClSetup, ct: &ClCiphertext) -> Result<ClCiphertext, Jtx25Error> {
    let (c1, c2) = setup.ct_components(ct)?;
    Ok(setup.ct_from_components(&c1, &c2)?)
}

// ---------------------------------------------------------------------------
// DRG proof serialization (robust only)
// ---------------------------------------------------------------------------

#[cfg(feature = "robust")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerREncPcProof {
    /// Compressed EC Pedersen commitment randomness R_PC (33 bytes).
    pub r_pc_bytes: Vec<u8>,
    /// CL commitment R_c0 = h^{a3}.
    pub r_c0: SerializedQfi,
    /// CL commitment R_c1 = f^{a1} * ek^{a3}.
    pub r_c1: SerializedQfi,
    /// Response z1 for chi (shared between EC and CL checks).
    pub z1: Vec<u8>,
    /// Response z2 for chi'.
    pub z2: Vec<u8>,
    /// Response z3 for r (unbounded).
    pub z3: Vec<u8>,
    /// Fiat-Shamir challenge.
    pub e: Vec<u8>,
}

#[cfg(feature = "robust")]
impl SerREncPcProof {
    pub fn from_proof(proof: &REncPcProof) -> Result<Self, String> {
        Ok(Self {
            r_pc_bytes: proof.r_pc_bytes.clone(),
            r_c0: SerializedQfi::from_qfi(&proof.r_c0)?,
            r_c1: SerializedQfi::from_qfi(&proof.r_c1)?,
            z1: proof.z1.clone(),
            z2: proof.z2.clone(),
            z3: proof.z3.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self) -> Result<REncPcProof, String> {
        Ok(REncPcProof {
            r_pc_bytes: self.r_pc_bytes.clone(),
            r_c0: self.r_c0.to_qfi()?,
            r_c1: self.r_c1.to_qfi()?,
            z1: self.z1.clone(),
            z2: self.z2.clone(),
            z3: self.z3.clone(),
            e: self.e.clone(),
        })
    }
}

#[cfg(feature = "robust")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRPcDlProof {
    pub t: SerializedQfi,
    pub z: Vec<u8>,
    pub e: Vec<u8>,
}

#[cfg(feature = "robust")]
impl SerRPcDlProof {
    pub fn from_proof(proof: &RPcDlProof) -> Result<Self, String> {
        Ok(Self {
            t: SerializedQfi::from_qfi(&proof.t)?,
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self) -> Result<RPcDlProof, String> {
        Ok(RPcDlProof {
            t: self.t.to_qfi()?,
            z: self.z.clone(),
            e: self.e.clone(),
        })
    }
}
