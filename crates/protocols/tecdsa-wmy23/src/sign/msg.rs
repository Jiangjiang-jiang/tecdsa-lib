// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 online signing message types and wire (de)serialization.

#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, PrimeField};
use serde::{Deserialize, Serialize};
use tecdsa_curve::conv::scalar_to_bytes;

use crate::{nizk::RDl2PcProof, sign::rounds::SignContribution};

/// Messages exchanged during WMY23 identifiable online signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wmy23SignMsg {
    /// Round 5 (Phase 1a): the party's partial signature plus its MtAwc
    /// shares-in-exponent and NIZKDL-2PC proofs (serialised
    /// [`WireContribution`]).
    Round5(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireProof {
    t1: Vec<u8>,
    t2: Vec<u8>,
    t3: Vec<u8>,
    u1: Vec<u8>,
    u2: Vec<u8>,
    u3: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireEntry {
    j: u16,
    m_ij: Vec<u8>,
    n_ij: Vec<u8>,
    proof: WireProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireContribution {
    index: u16,
    s_i: Vec<u8>,
    entries: Vec<WireEntry>,
}

fn point_bytes(p: &k256::ProjectivePoint) -> Vec<u8> {
    p.to_bytes().to_vec()
}

fn point_from(bytes: &[u8], label: &str) -> Result<k256::ProjectivePoint, String> {
    let repr = k256::CompressedPoint::try_from(bytes)
        .map_err(|e| format!("invalid point bytes ({label}): {e}"))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| format!("invalid EC point: {label}"))
}

fn scalar_from(bytes: &[u8], label: &str) -> Result<k256::Scalar, String> {
    if bytes.len() != 32 {
        return Err(format!("invalid scalar length for {label}"));
    }
    let mut repr = k256::FieldBytes::default();
    repr.copy_from_slice(bytes);
    Option::from(k256::Scalar::from_repr(repr)).ok_or_else(|| format!("invalid scalar: {label}"))
}

fn proof_to_wire(p: &RDl2PcProof) -> WireProof {
    WireProof {
        t1: point_bytes(&p.t1),
        t2: point_bytes(&p.t2),
        t3: point_bytes(&p.t3),
        u1: scalar_to_bytes(&p.u1),
        u2: scalar_to_bytes(&p.u2),
        u3: scalar_to_bytes(&p.u3),
    }
}

fn proof_from_wire(w: &WireProof) -> Result<RDl2PcProof, String> {
    Ok(RDl2PcProof {
        t1: point_from(&w.t1, "proof.t1")?,
        t2: point_from(&w.t2, "proof.t2")?,
        t3: point_from(&w.t3, "proof.t3")?,
        u1: scalar_from(&w.u1, "proof.u1")?,
        u2: scalar_from(&w.u2, "proof.u2")?,
        u3: scalar_from(&w.u3, "proof.u3")?,
    })
}

/// Serialize a [`SignContribution`] for broadcast.
///
/// # Errors
///
/// Returns an error if `bincode` encoding fails.
pub fn serialize_contribution(c: &SignContribution) -> Result<Vec<u8>, String> {
    let mut entries = Vec::new();
    for j in 0..c.m_row.len() {
        if j == c.index {
            continue;
        }
        if let (Some(m_ij), Some(n_ij), Some(proof)) =
            (c.m_row[j], c.n_row[j], c.proofs[j].as_ref())
        {
            entries.push(WireEntry {
                j: j as u16,
                m_ij: point_bytes(&m_ij),
                n_ij: point_bytes(&n_ij),
                proof: proof_to_wire(proof),
            });
        }
    }
    let wire = WireContribution {
        index: c.index as u16,
        s_i: scalar_to_bytes(&c.s_i),
        entries,
    };
    bincode::serde::encode_to_vec(&wire, bincode::config::standard())
        .map_err(|e| format!("serialize contribution: {e}"))
}

/// Deserialize a [`SignContribution`] received from a peer.
///
/// `n` is the quorum size, used to size the per-counterparty vectors.
///
/// # Errors
///
/// Returns an error if decoding fails or any index/point/scalar is invalid.
pub fn deserialize_contribution(data: &[u8], n: usize) -> Result<SignContribution, String> {
    let (wire, _): (WireContribution, _) =
        bincode::serde::decode_from_slice(data, bincode::config::standard())
            .map_err(|e| format!("deserialize contribution: {e}"))?;
    let index = wire.index as usize;
    if index >= n {
        return Err("contribution index out of range".into());
    }
    let mut m_row = vec![None; n];
    let mut n_row = vec![None; n];
    let mut proofs = vec![None; n];
    for e in &wire.entries {
        let j = e.j as usize;
        if j >= n || j == index {
            return Err("contribution entry index out of range".into());
        }
        m_row[j] = Some(point_from(&e.m_ij, "M_ij")?);
        n_row[j] = Some(point_from(&e.n_ij, "N_ij")?);
        proofs[j] = Some(proof_from_wire(&e.proof)?);
    }
    Ok(SignContribution {
        index,
        s_i: scalar_from(&wire.s_i, "s_i")?,
        m_row,
        n_row,
        proofs,
    })
}
