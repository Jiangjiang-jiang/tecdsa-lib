// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(clippy::module_name_repetitions)]

//! Shared CL serialization types and helpers for JTX25 protocol messages.
//!
//! Eliminates duplication across presign, sign, and their robust variants.

use elliptic_curve::group::GroupEncoding;
use serde::{Deserialize, Serialize};

use tecdsa_class_group::bicycl_glue::{BicyclCiphertext, BicyclQfi, ClSetup};
use tecdsa_class_group::zk::r_dl_cl::RDlClProof;
use tecdsa_class_group::zk::r_enc::REncProof;
#[cfg(feature = "robust")]
use tecdsa_class_group::zk::r_enc_pc::REncPcProof;
use tecdsa_class_group::zk::r_part_dec::RPartDecProof;
#[cfg(feature = "robust")]
use tecdsa_class_group::zk::r_pc_dl::RPcDlProof;

use crate::error::Jtx25Error;

// ---------------------------------------------------------------------------
// Serialized class-group element (abc triplet)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedQfi {
    pub data: Vec<u8>,
}

impl SerializedQfi {
    pub fn from_qfi(setup: &ClSetup, qfi: &BicyclQfi) -> Result<Self, String> {
        let ctx = setup.ctx();
        let data = qfi.to_bytes(ctx).map_err(|e| format!("to_bytes: {e}"))?;
        Ok(Self { data })
    }

    pub fn to_qfi(&self, setup: &ClSetup) -> Result<BicyclQfi, String> {
        let ctx = setup.ctx();
        BicyclQfi::from_bytes(ctx, &self.data).map_err(|e| format!("from_bytes: {e}"))
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
    pub fn from_bicycl_ct(setup: &ClSetup, ct: &BicyclCiphertext) -> Result<Self, String> {
        let (c1, c2) = setup
            .ct_components(ct)
            .map_err(|e| format!("ct_comp: {e}"))?;
        Ok(Self {
            c1: SerializedQfi::from_qfi(setup, &c1)?,
            c2: SerializedQfi::from_qfi(setup, &c2)?,
        })
    }

    pub fn to_bicycl_ct(&self, setup: &ClSetup) -> Result<BicyclCiphertext, String> {
        let c1 = self.c1.to_qfi(setup)?;
        let c2 = self.c2.to_qfi(setup)?;
        setup
            .ct_from_components(&c1, &c2)
            .map_err(|e| format!("ct_from: {e}"))
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
    pub fn from_proof(setup: &ClSetup, proof: &REncProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(setup, &proof.t1)?,
            t2: SerializedQfi::from_qfi(setup, &proof.t2)?,
            u1: proof.u1.clone(),
            u2: proof.u2.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self, setup: &ClSetup) -> Result<REncProof, String> {
        Ok(REncProof {
            t1: self.t1.to_qfi(setup)?,
            t2: self.t2.to_qfi(setup)?,
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
    pub fn from_proof(setup: &ClSetup, proof: &RDlClProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(setup, &proof.t1)?,
            t2: SerializedQfi::from_qfi(setup, &proof.t2)?,
            t_ec_bytes: proof.t_ec_bytes.clone(),
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self, setup: &ClSetup) -> Result<RDlClProof, String> {
        Ok(RDlClProof {
            t1: self.t1.to_qfi(setup)?,
            t2: self.t2.to_qfi(setup)?,
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
    pub fn from_proof(setup: &ClSetup, proof: &RPartDecProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(setup, &proof.t1)?,
            t2: SerializedQfi::from_qfi(setup, &proof.t2)?,
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self, setup: &ClSetup) -> Result<RPartDecProof, String> {
        Ok(RPartDecProof {
            t1: self.t1.to_qfi(setup)?,
            t2: self.t2.to_qfi(setup)?,
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
    ct: &BicyclCiphertext,
    x_bytes: &[u8],
) -> Result<BicyclCiphertext, Jtx25Error> {
    let (c1, c2) = setup.ct_components(ct)?;
    let c1_x = setup.exp_bytes(&c1, x_bytes)?;
    let c2_x = setup.exp_bytes(&c2, x_bytes)?;
    let result = setup.ct_from_components(&c1_x, &c2_x)?;
    Ok(result)
}

pub(crate) fn add_ct_components(
    setup: &ClSetup,
    ct_a: &BicyclCiphertext,
    ct_b: &BicyclCiphertext,
) -> Result<BicyclCiphertext, Jtx25Error> {
    let (a1, a2) = setup.ct_components(ct_a)?;
    let (b1, b2) = setup.ct_components(ct_b)?;
    let c1 = setup.compose(&a1, &b1)?;
    let c2 = setup.compose(&a2, &b2)?;
    Ok(setup.ct_from_components(&c1, &c2)?)
}

pub(crate) fn copy_ct(
    setup: &ClSetup,
    ct: &BicyclCiphertext,
) -> Result<BicyclCiphertext, Jtx25Error> {
    let (c1, c2) = setup.ct_components(ct)?;
    Ok(setup.ct_from_components(&c1, &c2)?)
}

// ---------------------------------------------------------------------------
// DRG proof serialization (robust only)
// ---------------------------------------------------------------------------

#[cfg(feature = "robust")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerREncPcProof {
    pub t1: SerializedQfi,
    pub t2: SerializedQfi,
    pub s: SerializedQfi,
    pub u1: Vec<u8>,
    pub u2: Vec<u8>,
    pub e: Vec<u8>,
}

#[cfg(feature = "robust")]
impl SerREncPcProof {
    pub fn from_proof(setup: &ClSetup, proof: &REncPcProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(setup, &proof.t1)?,
            t2: SerializedQfi::from_qfi(setup, &proof.t2)?,
            s: SerializedQfi::from_qfi(setup, &proof.s)?,
            u1: proof.u1.clone(),
            u2: proof.u2.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self, setup: &ClSetup) -> Result<REncPcProof, String> {
        Ok(REncPcProof {
            t1: self.t1.to_qfi(setup)?,
            t2: self.t2.to_qfi(setup)?,
            s: self.s.to_qfi(setup)?,
            u1: self.u1.clone(),
            u2: self.u2.clone(),
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
    pub fn from_proof(setup: &ClSetup, proof: &RPcDlProof) -> Result<Self, String> {
        Ok(Self {
            t: SerializedQfi::from_qfi(setup, &proof.t)?,
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub fn to_proof(&self, setup: &ClSetup) -> Result<RPcDlProof, String> {
        Ok(RPcDlProof {
            t: self.t.to_qfi(setup)?,
            z: self.z.clone(),
            e: self.e.clone(),
        })
    }
}
