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

use std::collections::BTreeMap;

use elliptic_curve::{group::GroupEncoding, PrimeField};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_class_group::{
    cl::{ClPublicKey as ClHsmqkPublicKey, ClSetup, Qfi},
    nim::{Nim, NimEncodeBOutput},
    zk::r_cl_dl_ec::RClDlEcProof,
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::zk::dlog::DlogProof;
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

use crate::key_share::Llz25KeyShare;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRClDlEcProof {
    pub t1: Vec<u8>,
    pub t2: Vec<u8>,
    pub v_tilde_bytes: Vec<u8>,
    pub u1: Vec<u8>,
    pub u2: Vec<u8>,
    pub e: Vec<u8>,
}

impl SerRClDlEcProof {
    pub fn from_proof(proof: &RClDlEcProof) -> Result<Self, String> {
        Ok(Self {
            t1: proof.t1.to_bytes(),
            t2: proof.t2.to_bytes(),
            v_tilde_bytes: proof.v_tilde_bytes.clone(),
            u1: proof.u1.clone(),
            u2: proof.u2.clone(),
            e: proof.e.clone(),
        })
    }

    pub fn to_proof(&self) -> Result<RClDlEcProof, String> {
        Ok(RClDlEcProof {
            t1: Qfi::from_bytes(&self.t1),
            t2: Qfi::from_bytes(&self.t2),
            v_tilde_bytes: self.v_tilde_bytes.clone(),
            u1: self.u1.clone(),
            u2: self.u2.clone(),
            e: self.e.clone(),
        })
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R2BcastPayload {
    pub nonce: Vec<u8>,
    pub vss_commitment_points: Vec<Vec<u8>>,
    pub dlog_proof: SerDlogProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R3Payload {
    pub x_i_bytes: Vec<u8>,
    pub pe_x_c1: Vec<u8>,
    pub pe_x_c2: Vec<u8>,
    pub proof: SerRClDlEcProof,
}

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
    pub pe_x_c1: Vec<u8>,
    pub pe_x_c2: Vec<u8>,
    pub proof: RClDlEcProof,
}

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
    k256::Scalar,
    Vec<u8>,
    k256::ProjectivePoint,
    Vec<k256::ProjectivePoint>,
    Vec<u8>,
)> {
    let n = all_parties.len();

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

    for (&pid, r2) in r2_bcasts {
        let a_k_0 = r2.vss_commitments[0];
        if !r2.dlog_proof.verify(&a_k_0, b"llz25-dkg-dlog") {
            return Err(TecdsaError::Other(format!(
                "DLog proof failed for party {pid}"
            )));
        }
    }

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

    let mut combined_share = k256::Scalar::ZERO;
    for &share_val in r2_shares.values() {
        combined_share += share_val;
    }

    let mut public_key = k256::ProjectivePoint::IDENTITY;
    for r2 in r2_bcasts.values() {
        public_key += r2.vss_commitments[0];
    }

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

    let my_0based = (my_1based - 1) as usize;
    let my_x_i_point = public_shares[my_0based];
    let my_x_i_bytes = proj_to_bytes(&my_x_i_point);

    let x_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&combined_share);

    let mut nim = Nim::new(setup);
    let NimEncodeBOutput { pe_b, state: st_b } = nim
        .encode_b(&x_i_bytes, pk_crs)
        .map_err(|e| TecdsaError::Other(format!("NIM.Encode_B failed: {e}")))?;

    let (c1, c2) = setup
        .ct_components(&pe_b)
        .map_err(|e| TecdsaError::Other(format!("ct_components: {e}")))?;
    let pe_x_c1_bytes = c1.to_bytes();
    let pe_x_c2_bytes = c2.to_bytes();

    let proof = RClDlEcProof::prove(
        setup,
        pk_crs,
        &pe_b,
        &my_x_i_bytes,
        &x_i_bytes,
        &st_b.s_bytes,
    )
    .map_err(|e| TecdsaError::Other(format!("RClDlEcProof::prove: {e}")))?;

    let ser_proof = SerRClDlEcProof::from_proof(&proof)
        .map_err(|e| TecdsaError::Other(format!("serialize proof: {e}")))?;

    let r3_payload = R3Payload {
        x_i_bytes: my_x_i_bytes,
        pe_x_c1: pe_x_c1_bytes.clone(),
        pe_x_c2: pe_x_c2_bytes.clone(),
        proof: ser_proof,
    };

    let r3_bytes = bincode::serde::encode_to_vec(&r3_payload, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("serialize R3: {e}")))?;

    r3_data.insert(
        my_id,
        R3ReceivedData {
            x_i_point: my_x_i_point,
            pe_x_c1: pe_x_c1_bytes,
            pe_x_c2: pe_x_c2_bytes,
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
        let c1 = Qfi::from_bytes(&r3.pe_x_c1);
        let c2 = Qfi::from_bytes(&r3.pe_x_c2);
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

    let mut all_pe_x_components = Vec::with_capacity(n);
    for &pid in all_parties {
        let r3 = r3_data
            .get(&pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R3 data for party {pid}")))?;
        all_pe_x_components.push((r3.pe_x_c1.clone(), r3.pe_x_c2.clone()));
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
