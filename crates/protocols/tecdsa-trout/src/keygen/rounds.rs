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

//! Round states, helpers, and transition functions for Trout interactive DKG.

use std::collections::BTreeMap;

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::PrimeField;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use tecdsa_class_group::bicycl_glue::ClSetup;
use tecdsa_class_group::zk::r_cl_dl_ec::RClDlEcProof;
use tecdsa_core::TecdsaError;
use tecdsa_curve::zk::dlog::DlogProof;
use tecdsa_curve::TecdsaCurve;
use tecdsa_evrf::{EvrfPublicKey, EvrfSecretKey};
use tecdsa_protocol::PartyId;

use crate::error::{qfi_from_abc, qfi_to_abc};
use crate::key_share::TroutKeyShare;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serialize a `ProjectivePoint` to bytes (33 bytes compressed).
pub(crate) fn proj_to_bytes(p: &k256::ProjectivePoint) -> Vec<u8> {
    let encoded = p.to_bytes();
    let slice: &[u8] = encoded.as_ref();
    slice.to_vec()
}

/// Serialize a `Scalar` to 32-byte big-endian representation.
pub(crate) fn scalar_to_bytes(s: &k256::Scalar) -> Vec<u8> {
    let repr = s.to_repr();
    let slice: &[u8] = repr.as_ref();
    slice.to_vec()
}

/// Deserialize a `ProjectivePoint` from compressed bytes.
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
// Serialized DlogProof (avoids Debug bound on DlogProof<C>)
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
    pub evrf_pk_bytes: Vec<u8>,
    pub vss_commitment_points: Vec<Vec<u8>>,
    pub cl_contribution_abc: SerQfi,
    pub dlog_proof: SerDlogProof,
}

// ---------------------------------------------------------------------------
// R3 broadcast payload
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R3Payload {
    pub x_i_bytes: Vec<u8>,
    pub ct_c1_abc: SerQfi,
    pub ct_c2_abc: SerQfi,
    pub proof: SerRClDlEcProof,
}

// ---------------------------------------------------------------------------
// Internal state types
// ---------------------------------------------------------------------------

pub(crate) struct R1LocalState {
    pub evrf_sk: EvrfSecretKey<k256::Secp256k1>,
    pub evrf_pk: EvrfPublicKey<k256::Secp256k1>,
    pub cl_contribution_abc: (String, String, String),
    #[allow(dead_code)]
    pub x_i: k256::Scalar,
    pub vss_shares: Vec<tecdsa_vss::shamir::Share<k256::Secp256k1>>,
    pub vss_commitments: Vec<k256::ProjectivePoint>,
    pub dlog_proof: DlogProof<k256::Secp256k1>,
    pub nonce: [u8; 32],
    #[allow(dead_code)]
    pub commitment: [u8; 32],
}

impl R1LocalState {
    pub fn zeroize_secrets(&mut self) {
        self.x_i.zeroize();
        for share in &mut self.vss_shares {
            share.value.zeroize();
        }
    }
}

pub(crate) struct R2ReceivedBcast {
    pub nonce: [u8; 32],
    pub evrf_pk: EvrfPublicKey<k256::Secp256k1>,
    pub vss_commitments: Vec<k256::ProjectivePoint>,
    pub cl_contribution_abc: (String, String, String),
    pub dlog_proof: DlogProof<k256::Secp256k1>,
}

pub(crate) struct R3ReceivedData {
    pub x_i_point: k256::ProjectivePoint,
    pub ct_components: (String, String, String, String, String, String),
    pub proof: RClDlEcProof,
}

// ---------------------------------------------------------------------------
// compute_commitment
// ---------------------------------------------------------------------------

/// Compute the hash commitment over Round 1 public data.
pub(crate) fn compute_commitment(
    nonce: &[u8; 32],
    evrf_pk_bytes: &[u8],
    vss_commitments: &[k256::ProjectivePoint],
    cl_abc: &(String, String, String),
    dlog_proof: &DlogProof<k256::Secp256k1>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(evrf_pk_bytes);
    for com in vss_commitments {
        hasher.update(proj_to_bytes(com));
    }
    hasher.update(cl_abc.0.as_bytes());
    hasher.update(cl_abc.1.as_bytes());
    hasher.update(cl_abc.2.as_bytes());
    hasher.update(proj_to_bytes(&dlog_proof.commitment));
    hasher.update(scalar_to_bytes(&dlog_proof.response));
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Round transition functions
// ---------------------------------------------------------------------------

/// Transition from R2 -> R3: verify commitments, CL, VSS, compute combined
/// share, CL-encrypt, prove R_CL-EC.
#[allow(clippy::type_complexity)]
pub(crate) fn transition_to_r3(
    my_id: PartyId,
    all_parties: &[PartyId],
    my_1based: u16,
    r1_commitments: &BTreeMap<PartyId, [u8; 32]>,
    r2_bcasts: &BTreeMap<PartyId, R2ReceivedBcast>,
    r2_shares: &BTreeMap<PartyId, k256::Scalar>,
    setup: &mut ClSetup,
    r3_data: &mut BTreeMap<PartyId, R3ReceivedData>,
) -> tecdsa_core::Result<(
    k256::Scalar,                                     // combined_share
    Vec<u8>,                                          // delta_i
    k256::ProjectivePoint,                            // public_key
    Vec<k256::ProjectivePoint>,                       // public_shares
    (String, String, String),                         // cl_pk_abc
    (String, String, String, String, String, String), // my_ct_components
    Vec<u8>,                                          // r3_bytes to broadcast
)> {
    let n = all_parties.len();

    // 1. Verify all hash commitments match decommitments
    for (&pid, r2) in r2_bcasts {
        let stored_commitment = r1_commitments
            .get(&pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R1 commitment for {pid}")))?;

        let evrf_pk_bytes = <k256::Secp256k1 as TecdsaCurve>::point_to_bytes(&r2.evrf_pk.point);
        let recomputed = compute_commitment(
            &r2.nonce,
            &evrf_pk_bytes,
            &r2.vss_commitments,
            &r2.cl_contribution_abc,
            &r2.dlog_proof,
        );

        if recomputed != *stored_commitment {
            return Err(TecdsaError::Other(format!(
                "commitment mismatch for party {pid}"
            )));
        }
    }

    // 2. Verify all DLog proofs for A_{k,0}
    for (&pid, r2) in r2_bcasts {
        let a_k_0 = r2.vss_commitments[0];
        if !r2.dlog_proof.verify(&a_k_0, b"trout-dkg-dlog") {
            return Err(TecdsaError::Other(format!(
                "DLog proof failed for party {pid}"
            )));
        }
    }

    // 3. Combine CL key contributions: Y^cl = product of Y_k
    let party_ids: Vec<PartyId> = all_parties.to_vec();
    let first_pid = party_ids[0];
    let first_abc = &r2_bcasts[&first_pid].cl_contribution_abc;
    let mut y_cl = qfi_from_abc(setup.ctx(), &first_abc.0, &first_abc.1, &first_abc.2)
        .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
    for &pid in &party_ids[1..] {
        let abc = &r2_bcasts[&pid].cl_contribution_abc;
        let y_k = qfi_from_abc(setup.ctx(), &abc.0, &abc.1, &abc.2)
            .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
        y_cl = setup
            .compose(&y_cl, &y_k)
            .map_err(|e| TecdsaError::Other(format!("compose: {e}")))?;
    }
    let cl_pk = setup
        .pk_from_qfi(&y_cl)
        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;
    let cl_pk_abc =
        qfi_to_abc(setup.ctx(), &y_cl).map_err(|e| TecdsaError::Other(format!("{e}")))?;

    // 4. Verify all received VSS shares
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

    // 5. Compute combined share: x_i = sum_k s_{k,i}
    let mut combined_share = k256::Scalar::ZERO;
    for &share_val in r2_shares.values() {
        combined_share += share_val;
    }

    // 6. Compute combined public key: X = sum_k A_{k,0}
    let mut public_key = k256::ProjectivePoint::IDENTITY;
    for r2 in r2_bcasts.values() {
        public_key += r2.vss_commitments[0];
    }

    // 7. Compute X_j for all parties: X_j = sum_k(sum_l A_{k,l} * j^l)
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

    // 8. CL-encrypt combined share
    let x_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&combined_share);

    // Generate encryption randomness delta_i
    let (sk_tmp, _) = setup
        .keygen()
        .map_err(|e| TecdsaError::Other(format!("keygen for delta: {e}")))?;
    let delta_i = setup
        .sk_to_bytes(&sk_tmp)
        .map_err(|e| TecdsaError::Other(format!("sk_to_bytes: {e}")))?;

    let ct = setup
        .encrypt_with_r_bytes(&cl_pk, &x_i_bytes, &delta_i)
        .map_err(|e| TecdsaError::Other(format!("encrypt: {e}")))?;
    let (c1, c2) = setup
        .ct_components(&ct)
        .map_err(|e| TecdsaError::Other(format!("ct_components: {e}")))?;
    let ct_c1_abc = qfi_to_abc(setup.ctx(), &c1).map_err(|e| TecdsaError::Other(format!("{e}")))?;
    let ct_c2_abc = qfi_to_abc(setup.ctx(), &c2).map_err(|e| TecdsaError::Other(format!("{e}")))?;

    // 9. Generate R_CL-EC proof
    let proof = RClDlEcProof::prove(setup, &cl_pk, &ct, &my_x_i_bytes, &x_i_bytes, &delta_i)
        .map_err(|e| TecdsaError::Other(format!("RClDlEcProof::prove: {e}")))?;

    let ser_proof = SerRClDlEcProof::from_proof(setup, &proof)
        .map_err(|e| TecdsaError::Other(format!("serialize proof: {e}")))?;

    let r3_payload = R3Payload {
        x_i_bytes: my_x_i_bytes,
        ct_c1_abc: SerQfi::from_abc(&ct_c1_abc),
        ct_c2_abc: SerQfi::from_abc(&ct_c2_abc),
        proof: ser_proof,
    };

    let r3_bytes = bincode::serde::encode_to_vec(&r3_payload, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("serialize R3: {e}")))?;

    // Store our own R3 data
    r3_data.insert(
        my_id,
        R3ReceivedData {
            x_i_point: my_x_i_point,
            ct_components: (
                ct_c1_abc.0.clone(),
                ct_c1_abc.1.clone(),
                ct_c1_abc.2.clone(),
                ct_c2_abc.0.clone(),
                ct_c2_abc.1.clone(),
                ct_c2_abc.2.clone(),
            ),
            proof,
        },
    );

    let my_ct_components = (
        ct_c1_abc.0,
        ct_c1_abc.1,
        ct_c1_abc.2,
        ct_c2_abc.0,
        ct_c2_abc.1,
        ct_c2_abc.2,
    );

    Ok((
        combined_share,
        delta_i,
        public_key,
        public_shares,
        cl_pk_abc,
        my_ct_components,
        r3_bytes,
    ))
}

/// Finalize: verify all R3 proofs and construct TroutKeyShare.
pub(crate) fn finalize(
    my_id: PartyId,
    all_parties: &[PartyId],
    my_1based: u16,
    r3_data: &BTreeMap<PartyId, R3ReceivedData>,
    r2_bcasts: &BTreeMap<PartyId, R2ReceivedBcast>,
    r1_state: R1LocalState,
    setup: &mut ClSetup,
    combined_share: k256::Scalar,
    delta_i: Vec<u8>,
    public_key: k256::ProjectivePoint,
    public_shares: &[k256::ProjectivePoint],
    cl_pk_abc: (String, String, String),
    my_ct_components: (String, String, String, String, String, String),
    cl_setup_seed: &str,
    use_128bit: bool,
    threshold: u16,
) -> tecdsa_core::Result<TroutKeyShare> {
    let n = all_parties.len();

    let y_cl = qfi_from_abc(setup.ctx(), &cl_pk_abc.0, &cl_pk_abc.1, &cl_pk_abc.2)
        .map_err(|e| TecdsaError::Other(format!("qfi_from_abc: {e}")))?;
    let cl_pk = setup
        .pk_from_qfi(&y_cl)
        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

    // 1. Verify all R_CL-EC proofs + X_i consistency
    for (&pid, r3) in r3_data {
        if pid == my_id {
            continue;
        }
        // Check X_i matches locally computed public share
        let j_0based = all_parties
            .iter()
            .position(|p| *p == pid)
            .ok_or_else(|| TecdsaError::Other(format!("party {pid} not found")))?;
        if r3.x_i_point != public_shares[j_0based] {
            return Err(TecdsaError::Other(format!(
                "X_i mismatch for party {pid}: received point differs from VSS-derived share"
            )));
        }
        let (c1_a, c1_b, c1_c, c2_a, c2_b, c2_c) = &r3.ct_components;
        let c1 = qfi_from_abc(setup.ctx(), c1_a, c1_b, c1_c)
            .map_err(|e| TecdsaError::Other(format!("qfi: {e}")))?;
        let c2 = qfi_from_abc(setup.ctx(), c2_a, c2_b, c2_c)
            .map_err(|e| TecdsaError::Other(format!("qfi: {e}")))?;
        let ct = setup
            .ct_from_components(&c1, &c2)
            .map_err(|e| TecdsaError::Other(format!("ct: {e}")))?;
        let x_i_bytes = proj_to_bytes(&r3.x_i_point);
        let ok = r3
            .proof
            .verify(setup, &cl_pk, &ct, &x_i_bytes)
            .map_err(|e| TecdsaError::Other(format!("R_CL-EC verify: {e}")))?;
        if !ok {
            return Err(TecdsaError::Other(format!(
                "R_CL-EC proof failed for party {pid}"
            )));
        }
    }

    // 2. Collect all eVRF public keys in order
    let mut all_evrf_pks: Vec<EvrfPublicKey<k256::Secp256k1>> = Vec::with_capacity(n);
    for &pid in all_parties {
        if pid == my_id {
            all_evrf_pks.push(r1_state.evrf_pk.clone());
        } else {
            let r2 = r2_bcasts
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing R2 for {pid}")))?;
            all_evrf_pks.push(r2.evrf_pk.clone());
        }
    }

    // 3. Collect all ciphertext components in order
    let mut all_ct_components: Vec<(String, String, String, String, String, String)> =
        Vec::with_capacity(n);
    for &pid in all_parties {
        let r3 = r3_data
            .get(&pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R3 for {pid}")))?;
        all_ct_components.push(r3.ct_components.clone());
    }

    let key_share = TroutKeyShare {
        party_index: my_1based,
        secret_share: combined_share,
        delta_i,
        evrf_sk: r1_state.evrf_sk,
        evrf_pk: r1_state.evrf_pk,
        all_evrf_pks,
        public_key,
        public_shares: public_shares.to_vec(),
        ct_share_components: my_ct_components,
        all_ct_share_components: all_ct_components,
        cl_pk_abc,
        cl_setup_seed: cl_setup_seed.to_string(),
        use_128bit_security: use_128bit,
        threshold,
        total: n as u16,
    };

    Ok(key_share)
}
