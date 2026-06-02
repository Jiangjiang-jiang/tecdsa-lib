// SPDX-License-Identifier: GPL-3.0-or-later
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
    non_snake_case
)]

//! Round states, helpers, and transition functions for LLZ25 interactive DKG.

use std::collections::BTreeMap;

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::PrimeField;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use tecdsa_class_group::bicycl_glue::ClSetup;
use tecdsa_class_group::nim::{Nim, NimEncodeBOutput};
use tecdsa_class_group::zk::r_cl_dl_ec::RClDlEcProof;
use tecdsa_core::TecdsaError;
use tecdsa_curve::zk::dlog::DlogProof;
use tecdsa_protocol::PartyId;

use crate::error::{qfi_from_abc, qfi_to_abc};
use crate::key_share::Llz25KeyShare;

use tecdsa_class_group::bicycl_glue::BicyclPublicKey as ClHsmqkPublicKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn proj_to_bytes(p: &k256::ProjectivePoint) -> Vec<u8> {
    let encoded = p.to_bytes();
    let slice: &[u8] = encoded.as_ref();
    slice.to_vec()
}

pub(crate) fn scalar_to_bytes(s: &k256::Scalar) -> Vec<u8> {
    let repr = s.to_repr();
    let slice: &[u8] = repr.as_ref();
    slice.to_vec()
}

pub(crate) fn proj_from_bytes(bytes: &[u8]) -> tecdsa_core::Result<k256::ProjectivePoint> {
    let mut repr = <k256::ProjectivePoint as GroupEncoding>::Repr::default();
    let repr_slice: &mut [u8] = repr.as_mut();
    if bytes.len() != repr_slice.len() {
        return Err(TecdsaError::Other(format!(
            "invalid point length: expected {}, got {}",
            repr_slice.len(),
            bytes.len()
        )));
    }
    repr_slice.copy_from_slice(bytes);
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| TecdsaError::Other("invalid EC point".into()))
}

// ---------------------------------------------------------------------------
// Serialized types for wire messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerQfi {
    pub a: String,
    pub b: String,
    pub c: String,
}

impl SerQfi {
    pub fn from_abc(abc: &(String, String, String)) -> Self {
        Self {
            a: abc.0.clone(),
            b: abc.1.clone(),
            c: abc.2.clone(),
        }
    }
    pub fn to_abc(&self) -> (String, String, String) {
        (self.a.clone(), self.b.clone(), self.c.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRClDlEcProof {
    pub t1: SerQfi,
    pub t2: SerQfi,
    pub v_tilde_bytes: Vec<u8>,
    pub u1: Vec<u8>,
    pub u2: Vec<u8>,
    pub e: Vec<u8>,
}

impl SerRClDlEcProof {
    pub fn from_proof(setup: &ClSetup, proof: &RClDlEcProof) -> Result<Self, String> {
        Ok(Self {
            t1: {
                let abc = qfi_to_abc(setup.ctx(), &proof.t1).map_err(|e| format!("{e}"))?;
                SerQfi::from_abc(&abc)
            },
            t2: {
                let abc = qfi_to_abc(setup.ctx(), &proof.t2).map_err(|e| format!("{e}"))?;
                SerQfi::from_abc(&abc)
            },
            v_tilde_bytes: proof.v_tilde_bytes.clone(),
            u1: proof.u1.clone(),
            u2: proof.u2.clone(),
            e: proof.e.clone(),
        })
    }

    pub fn to_proof(&self, setup: &ClSetup) -> Result<RClDlEcProof, String> {
        Ok(RClDlEcProof {
            t1: qfi_from_abc(setup.ctx(), &self.t1.a, &self.t1.b, &self.t1.c)
                .map_err(|e| format!("{e}"))?,
            t2: qfi_from_abc(setup.ctx(), &self.t2.a, &self.t2.b, &self.t2.c)
                .map_err(|e| format!("{e}"))?,
            v_tilde_bytes: self.v_tilde_bytes.clone(),
            u1: self.u1.clone(),
            u2: self.u2.clone(),
            e: self.e.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Serialized DlogProof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerDlogProof {
    pub commitment_bytes: Vec<u8>,
    pub response_bytes: Vec<u8>,
}

impl SerDlogProof {
    pub fn from_proof(proof: &DlogProof<k256::Secp256k1>) -> Self {
        Self {
            commitment_bytes: proj_to_bytes(&proof.commitment),
            response_bytes: scalar_to_bytes(&proof.response),
        }
    }

    pub fn to_proof(&self) -> tecdsa_core::Result<DlogProof<k256::Secp256k1>> {
        let commitment = proj_from_bytes(&self.commitment_bytes)?;
        let mut fb = k256::FieldBytes::default();
        if self.response_bytes.len() != fb.len() {
            return Err(TecdsaError::Other("invalid scalar length".into()));
        }
        fb.copy_from_slice(&self.response_bytes);
        let response = Option::from(k256::Scalar::from_repr(fb))
            .ok_or_else(|| TecdsaError::Other("invalid scalar".into()))?;
        Ok(DlogProof {
            commitment,
            response,
        })
    }
}

// ---------------------------------------------------------------------------
// R2 broadcast payload
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R2BcastPayload {
    pub nonce: Vec<u8>,
    pub vss_commitment_points: Vec<Vec<u8>>,
    pub dlog_proof: SerDlogProof,
}

// ---------------------------------------------------------------------------
// R3 broadcast payload
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R3Payload {
    pub x_i_bytes: Vec<u8>,
    pub pe_x_c1_abc: SerQfi,
    pub pe_x_c2_abc: SerQfi,
    pub proof: SerRClDlEcProof,
}

// ---------------------------------------------------------------------------
// Internal state types
// ---------------------------------------------------------------------------

pub(crate) struct R1LocalState {
    pub x_i: k256::Scalar,
    pub vss_shares: Vec<tecdsa_vss::shamir::Share<k256::Secp256k1>>,
    pub vss_commitments: Vec<k256::ProjectivePoint>,
    pub dlog_proof: DlogProof<k256::Secp256k1>,
    pub nonce: [u8; 32],
}

impl Drop for R1LocalState {
    fn drop(&mut self) {
        self.x_i.zeroize();
        for share in &mut self.vss_shares {
            share.value.zeroize();
        }
    }
}

pub(crate) struct R2ReceivedBcast {
    pub nonce: [u8; 32],
    pub vss_commitments: Vec<k256::ProjectivePoint>,
    pub dlog_proof: DlogProof<k256::Secp256k1>,
}

pub(crate) struct R3ReceivedData {
    pub x_i_point: k256::ProjectivePoint,
    pub pe_x_c1_abc: (String, String, String),
    pub pe_x_c2_abc: (String, String, String),
    pub proof: RClDlEcProof,
}

// ---------------------------------------------------------------------------
// compute_commitment
// ---------------------------------------------------------------------------

/// Compute the hash commitment over Round 1 public data.
pub(crate) fn compute_commitment(
    nonce: &[u8; 32],
    vss_commitments: &[k256::ProjectivePoint],
    dlog_proof: &DlogProof<k256::Secp256k1>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    for com in vss_commitments {
        hasher.update(proj_to_bytes(com));
    }
    hasher.update(proj_to_bytes(&dlog_proof.commitment));
    hasher.update(scalar_to_bytes(&dlog_proof.response));
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Round transition functions
// ---------------------------------------------------------------------------

/// Transition from R2 -> R3: verify commitments, VSS, compute combined
/// share, NIM.Encode_B, prove R_CL_DL_EC.
///
/// This is called by the machine when all R2 data has been collected.
#[allow(clippy::type_complexity)]
pub(crate) fn transition_to_r3(
    my_id: PartyId,
    all_parties: &[PartyId],
    my_1based: u16,
    r1_commitments: &BTreeMap<PartyId, [u8; 32]>,
    r2_bcasts: &BTreeMap<PartyId, R2ReceivedBcast>,
    r2_shares: &BTreeMap<PartyId, k256::Scalar>,
    setup: &mut ClSetup,
    pk_crs: &ClHsmqkPublicKey,
    r3_data: &mut BTreeMap<PartyId, R3ReceivedData>,
) -> tecdsa_core::Result<(
    k256::Scalar,               // combined_share
    Vec<u8>,                    // st_x_bytes
    k256::ProjectivePoint,      // public_key
    Vec<k256::ProjectivePoint>, // public_shares
    Vec<u8>,                    // r3_bytes to broadcast
)> {
    let n = all_parties.len();

    // 1. Verify all hash commitments match decommitments
    for (&pid, r2) in r2_bcasts {
        let stored_commitment = r1_commitments
            .get(&pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R1 commitment for {pid}")))?;

        let recomputed = compute_commitment(&r2.nonce, &r2.vss_commitments, &r2.dlog_proof);

        if recomputed != *stored_commitment {
            return Err(TecdsaError::Other(format!(
                "commitment mismatch for party {pid}"
            )));
        }
    }

    // 2. Verify all DLog proofs for A_{k,0}
    for (&pid, r2) in r2_bcasts {
        let a_k_0 = r2.vss_commitments[0];
        if !r2.dlog_proof.verify(&a_k_0, b"llz25-dkg-dlog") {
            return Err(TecdsaError::Other(format!(
                "DLog proof failed for party {pid}"
            )));
        }
    }

    // 3. Verify all received VSS shares
    for (&pid, &share_val) in r2_shares {
        let sender_r2 = r2_bcasts
            .get(&pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R2 bcast from {pid}")))?;
        if !tecdsa_vss::feldman::verify::<k256::Secp256k1>(
            &share_val,
            my_1based,
            &sender_r2.vss_commitments,
        ) {
            return Err(TecdsaError::Other(format!(
                "VSS share verification failed for party {pid}"
            )));
        }
    }

    // 4. Compute combined share: x_i = sum_k s_{k,i}
    let mut combined_share = k256::Scalar::ZERO;
    for &share_val in r2_shares.values() {
        combined_share += share_val;
    }

    // 5. Compute combined public key: X = sum_k A_{k,0}
    let mut public_key = k256::ProjectivePoint::IDENTITY;
    for r2 in r2_bcasts.values() {
        public_key += r2.vss_commitments[0];
    }

    // 6. Compute X_j for all parties: X_j = sum_k(sum_l A_{k,l} * j^l)
    let mut public_shares = Vec::with_capacity(n);
    for party_j_0based in 0..n {
        let j = (party_j_0based + 1) as u64;
        let mut x_j = k256::ProjectivePoint::IDENTITY;
        for r2 in r2_bcasts.values() {
            let mut j_pow = k256::Scalar::ONE;
            let j_scalar = k256::Scalar::from(j);
            for com in &r2.vss_commitments {
                x_j += *com * j_pow;
                j_pow *= j_scalar;
            }
        }
        public_shares.push(x_j);
    }

    // Our own X_i
    let my_0based = (my_1based - 1) as usize;
    let my_x_i_point = public_shares[my_0based];
    let my_x_i_bytes = proj_to_bytes(&my_x_i_point);

    // 7. NIM.Encode_B(crs, x_i) -> (pe_{x,i}, st_{x,i})
    let x_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&combined_share);

    let mut nim = Nim::new(setup);
    let NimEncodeBOutput { pe_b, state: st_b } = nim
        .encode_b(&x_i_bytes, pk_crs)
        .map_err(|e| TecdsaError::Other(format!("NIM.Encode_B failed: {e}")))?;

    // Get pe_x ciphertext components for serialization
    let (c1, c2) = setup
        .ct_components(&pe_b)
        .map_err(|e| TecdsaError::Other(format!("ct_components: {e}")))?;
    let pe_x_c1_abc =
        qfi_to_abc(setup.ctx(), &c1).map_err(|e| TecdsaError::Other(format!("{e}")))?;
    let pe_x_c2_abc =
        qfi_to_abc(setup.ctx(), &c2).map_err(|e| TecdsaError::Other(format!("{e}")))?;

    // 8. R_CL_DL_EC proof: proves pe_{x,i} encrypts dlog of X_i
    let proof = RClDlEcProof::prove(
        setup,
        pk_crs,
        &pe_b,
        &my_x_i_bytes,
        &x_i_bytes,
        &st_b.s_bytes,
    )
    .map_err(|e| TecdsaError::Other(format!("RClDlEcProof::prove: {e}")))?;

    let ser_proof = SerRClDlEcProof::from_proof(setup, &proof)
        .map_err(|e| TecdsaError::Other(format!("serialize proof: {e}")))?;

    let r3_payload = R3Payload {
        x_i_bytes: my_x_i_bytes,
        pe_x_c1_abc: SerQfi::from_abc(&pe_x_c1_abc),
        pe_x_c2_abc: SerQfi::from_abc(&pe_x_c2_abc),
        proof: ser_proof,
    };

    let r3_bytes = bincode::serde::encode_to_vec(&r3_payload, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("serialize R3: {e}")))?;

    // Store our own R3 data
    r3_data.insert(
        my_id,
        R3ReceivedData {
            x_i_point: my_x_i_point,
            pe_x_c1_abc,
            pe_x_c2_abc,
            proof,
        },
    );

    Ok((
        combined_share,
        st_b.s_bytes,
        public_key,
        public_shares,
        r3_bytes,
    ))
}

/// Finalize: verify all R3 proofs and construct `Llz25KeyShare`.
pub(crate) fn finalize(
    my_id: PartyId,
    all_parties: &[PartyId],
    my_1based: u16,
    r3_data: &BTreeMap<PartyId, R3ReceivedData>,
    setup: &mut ClSetup,
    pk_crs: &ClHsmqkPublicKey,
    combined_share: k256::Scalar,
    st_x_bytes: Vec<u8>,
    public_key: k256::ProjectivePoint,
    public_shares: &[k256::ProjectivePoint],
    cl_setup_seed: &str,
    use_128bit: bool,
    threshold: u16,
) -> tecdsa_core::Result<Llz25KeyShare> {
    let n = all_parties.len();

    // 1. Verify all R_CL_DL_EC proofs + X_i consistency
    for (&pid, r3) in r3_data {
        if pid == my_id {
            continue;
        }
        let j_0based = all_parties
            .iter()
            .position(|p| *p == pid)
            .ok_or_else(|| TecdsaError::Other(format!("party {pid} not found")))?;
        if r3.x_i_point != public_shares[j_0based] {
            return Err(TecdsaError::Other(format!(
                "X_i mismatch for party {pid}: received point differs from VSS-derived share"
            )));
        }
        let c1 = qfi_from_abc(
            setup.ctx(),
            &r3.pe_x_c1_abc.0,
            &r3.pe_x_c1_abc.1,
            &r3.pe_x_c1_abc.2,
        )
        .map_err(|e| TecdsaError::Other(format!("qfi: {e}")))?;
        let c2 = qfi_from_abc(
            setup.ctx(),
            &r3.pe_x_c2_abc.0,
            &r3.pe_x_c2_abc.1,
            &r3.pe_x_c2_abc.2,
        )
        .map_err(|e| TecdsaError::Other(format!("qfi: {e}")))?;
        let ct = setup
            .ct_from_components(&c1, &c2)
            .map_err(|e| TecdsaError::Other(format!("ct: {e}")))?;
        let x_i_bytes = proj_to_bytes(&r3.x_i_point);
        let ok = r3
            .proof
            .verify(setup, pk_crs, &ct, &x_i_bytes)
            .map_err(|e| TecdsaError::Other(format!("R_CL_DL_EC verify: {e}")))?;
        if !ok {
            return Err(TecdsaError::Other(format!(
                "R_CL_DL_EC proof failed for party {pid}"
            )));
        }
    }

    // 2. Collect all pe_x components in party order
    let mut all_pe_x_components = Vec::with_capacity(n);
    for &pid in all_parties {
        let r3 = r3_data
            .get(&pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R3 data for party {pid}")))?;
        all_pe_x_components.push((
            r3.pe_x_c1_abc.0.clone(),
            r3.pe_x_c1_abc.1.clone(),
            r3.pe_x_c1_abc.2.clone(),
            r3.pe_x_c2_abc.0.clone(),
            r3.pe_x_c2_abc.1.clone(),
            r3.pe_x_c2_abc.2.clone(),
        ));
    }

    let my_0based = (my_1based - 1) as usize;
    let my_pe_x = all_pe_x_components[my_0based].clone();

    let key_share = Llz25KeyShare {
        party_index: my_1based,
        secret_share: combined_share,
        public_key,
        public_shares: public_shares.to_vec(),
        st_x_bytes,
        pe_x_components: my_pe_x,
        all_pe_x_components,
        cl_setup_seed: cl_setup_seed.to_string(),
        use_128bit_security: use_128bit,
        threshold,
        total: n as u16,
    };

    Ok(key_share)
}
