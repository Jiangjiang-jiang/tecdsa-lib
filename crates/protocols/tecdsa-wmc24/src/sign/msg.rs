// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMC24 online sign message types and serialization helpers.

use serde::{Deserialize, Serialize};
use tecdsa_class_group::{cl::Qfi, zk::r_part_dec::RPartDecProof};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wmc24OnlineSignMsg {
    Round4(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Serialized types
// ---------------------------------------------------------------------------

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRPartDecProof {
    pub(crate) t1: SerializedQfi,
    pub(crate) t2: SerializedQfi,
    pub(crate) z: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl SerRPartDecProof {
    pub(crate) fn from_proof(proof: &RPartDecProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(&proof.t1)?,
            t2: SerializedQfi::from_qfi(&proof.t2)?,
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub(crate) fn to_proof(&self) -> Result<RPartDecProof, String> {
        Ok(RPartDecProof {
            t1: self.t1.to_qfi()?,
            t2: self.t2.to_qfi()?,
            z: self.z.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R4Payload {
    pub(crate) pc: SerializedQfi,
    pub(crate) pi: SerRPartDecProof,
    pub(crate) party_index: usize,
}
