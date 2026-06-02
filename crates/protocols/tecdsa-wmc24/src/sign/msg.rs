// SPDX-License-Identifier: GPL-3.0-or-later
//! WMC24 online sign message types and serialization helpers.

use serde::{Deserialize, Serialize};

use tecdsa_class_group::bicycl_glue::{BicyclQfi, ClSetup};
use tecdsa_class_group::zk::r_part_dec::RPartDecProof;

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
    pub(crate) fn from_qfi(setup: &ClSetup, qfi: &BicyclQfi) -> Result<Self, String> {
        let ctx = setup.ctx();
        let data = qfi.to_bytes(ctx).map_err(|e| format!("to_bytes: {e}"))?;
        Ok(Self { data })
    }
    pub(crate) fn to_qfi(&self, setup: &ClSetup) -> Result<BicyclQfi, String> {
        let ctx = setup.ctx();
        BicyclQfi::from_bytes(ctx, &self.data).map_err(|e| format!("from_bytes: {e}"))
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
    pub(crate) fn from_proof(setup: &ClSetup, proof: &RPartDecProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(setup, &proof.t1)?,
            t2: SerializedQfi::from_qfi(setup, &proof.t2)?,
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub(crate) fn to_proof(&self, setup: &ClSetup) -> Result<RPartDecProof, String> {
        Ok(RPartDecProof {
            t1: self.t1.to_qfi(setup)?,
            t2: self.t2.to_qfi(setup)?,
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
