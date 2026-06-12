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

use elliptic_curve::{
    group::{Group, GroupEncoding},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_core::TecdsaError;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_joye_libert::{
    kgen::{JlPublicKey, JlSecretKey},
    zk::zkjlmod::ZkJlModProof,
};
use tecdsa_protocol::PartyId;

use crate::key_share::{VssSetup, Xal23KeyShare};

pub(crate) fn proj_to_bytes<C: TecdsaCurve>(p: &C::ProjectivePoint) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
{
    let encoded = p.to_bytes();
    let slice: &[u8] = encoded.as_ref();
    slice.to_vec()
}

pub(crate) fn scalar_to_bytes<C: TecdsaCurve>(s: &C::Scalar) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let repr = s.to_repr();
    let slice: &[u8] = repr.as_ref();
    slice.to_vec()
}

pub(crate) fn proj_from_bytes<C: TecdsaCurve>(
    bytes: &[u8],
) -> tecdsa_core::Result<C::ProjectivePoint>
where
    FieldBytesSize<C>: ModulusSize,
{
    let mut repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
    let repr_slice: &mut [u8] = repr.as_mut();
    if bytes.len() != repr_slice.len() {
        return Err(TecdsaError::Other(format!(
            "invalid point length: expected {}, got {}",
            repr_slice.len(),
            bytes.len()
        )));
    }
    repr_slice.copy_from_slice(bytes);
    Option::from(C::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| TecdsaError::Other("invalid EC point".into()))
}

pub(crate) fn scalar_from_bytes<C: TecdsaCurve>(bytes: &[u8]) -> tecdsa_core::Result<C::Scalar>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut fb = FieldBytes::<C>::default();
    if bytes.len() != fb.len() {
        return Err(TecdsaError::Other(format!(
            "invalid scalar length: expected {}, got {}",
            fb.len(),
            bytes.len()
        )));
    }
    fb.copy_from_slice(bytes);
    Option::from(<C::Scalar as PrimeField>::from_repr(fb))
        .ok_or_else(|| TecdsaError::Other("invalid scalar".into()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerDlogProof {
    pub commitment_bytes: Vec<u8>,
    pub response_bytes: Vec<u8>,
}

impl SerDlogProof {
    pub fn from_proof<C: TecdsaCurve>(proof: &DlogProof<C>) -> Self
    where
        FieldBytesSize<C>: ModulusSize,
        C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    {
        Self {
            commitment_bytes: proj_to_bytes::<C>(&proof.commitment),
            response_bytes: scalar_to_bytes::<C>(&proof.response),
        }
    }

    pub fn to_proof<C: TecdsaCurve>(&self) -> tecdsa_core::Result<DlogProof<C>>
    where
        FieldBytesSize<C>: ModulusSize,
        C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    {
        let commitment = proj_from_bytes::<C>(&self.commitment_bytes)?;
        let response = scalar_from_bytes::<C>(&self.response_bytes)?;
        Ok(DlogProof {
            commitment,
            response,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R2BcastPayload {
    pub nonce: Vec<u8>,
    pub jl_pk_json: Vec<u8>,
    pub vss_commitment_points: Vec<Vec<u8>>,
    pub dlog_proof: SerDlogProof,
    pub jl_mod_proof: ZkJlModProof,
}

pub(crate) struct R1LocalState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub jl_sk: Option<JlSecretKey>,
    pub jl_pk: JlPublicKey,
    #[allow(dead_code)]
    pub x_i: C::Scalar,
    pub vss_shares: Vec<tecdsa_vss::shamir::Share<C>>,
    pub vss_commitments: Vec<C::ProjectivePoint>,
    pub dlog_proof: DlogProof<C>,
    pub jl_mod_proof: ZkJlModProof,
    pub nonce: [u8; 32],
}

impl<C: TecdsaCurve> Drop for R1LocalState<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.x_i.zeroize();
        for share in &mut self.vss_shares {
            share.value.zeroize();
        }
    }
}

pub(crate) struct R2ReceivedBcast<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub nonce: [u8; 32],
    pub jl_pk: JlPublicKey,
    pub vss_commitments: Vec<C::ProjectivePoint>,
    pub dlog_proof: DlogProof<C>,
    pub jl_mod_proof: ZkJlModProof,
}

pub(crate) fn compute_commitment<C: TecdsaCurve>(
    nonce: &[u8; 32],
    jl_pk_bytes: &[u8],
    vss_commitments: &[C::ProjectivePoint],
    dlog_proof: &DlogProof<C>,
    jl_mod_proof_bytes: &[u8],
) -> [u8; 32]
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(jl_pk_bytes);
    for com in vss_commitments {
        hasher.update(proj_to_bytes::<C>(com));
    }
    hasher.update(proj_to_bytes::<C>(&dlog_proof.commitment));
    hasher.update(scalar_to_bytes::<C>(&dlog_proof.response));
    hasher.update(jl_mod_proof_bytes);
    hasher.finalize().into()
}

pub(crate) fn finalize<C: TecdsaCurve>(
    my_id: PartyId,
    all_parties: &[PartyId],
    my_1based: u16,
    threshold: u16,
    r1_commitments: &BTreeMap<PartyId, [u8; 32]>,
    r2_bcasts: &BTreeMap<PartyId, R2ReceivedBcast<C>>,
    r2_shares: &BTreeMap<PartyId, C::Scalar>,
    r1_state: &mut R1LocalState<C>,
) -> tecdsa_core::Result<Xal23KeyShare<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let n = all_parties.len();

    for (&pid, r2) in r2_bcasts {
        let stored_commitment = r1_commitments
            .get(&pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R1 commitment for {pid}")))?;

        let jl_pk_json = bincode::serde::encode_to_vec(&r2.jl_pk, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize JL pk for verify: {e}")))?;

        let jl_mod_proof_json =
            bincode::serde::encode_to_vec(&r2.jl_mod_proof, bincode::config::standard()).map_err(
                |e| TecdsaError::Other(format!("serialize JL mod proof for verify: {e}")),
            )?;

        let recomputed = compute_commitment::<C>(
            &r2.nonce,
            &jl_pk_json,
            &r2.vss_commitments,
            &r2.dlog_proof,
            &jl_mod_proof_json,
        );

        if recomputed != *stored_commitment {
            return Err(TecdsaError::Other(format!(
                "commitment mismatch for party {pid}"
            )));
        }
    }

    for (&pid, r2) in r2_bcasts {
        let a_k_0 = r2.vss_commitments[0];
        if !r2.dlog_proof.verify(&a_k_0, b"xal23-dkg-dlog") {
            return Err(TecdsaError::Other(format!(
                "DLog proof failed for party {pid}"
            )));
        }
    }

    for (&pid, r2) in r2_bcasts {
        if !r2.jl_mod_proof.verify_for_pk(&r2.jl_pk) {
            return Err(TecdsaError::Other(format!(
                "ZkJlMod proof failed for party {pid}"
            )));
        }
    }

    for (&pid, &share_val) in r2_shares {
        let sender_r2 = r2_bcasts
            .get(&pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R2 bcast from {pid}")))?;
        if !tecdsa_vss::feldman::verify::<C>(&share_val, my_1based, &sender_r2.vss_commitments) {
            return Err(TecdsaError::Other(format!(
                "VSS share verification failed for party {pid}"
            )));
        }
    }

    let mut combined_share = C::Scalar::ZERO;
    for &share_val in r2_shares.values() {
        combined_share += share_val;
    }

    let mut public_key = <C::ProjectivePoint as Group>::identity();
    for r2 in r2_bcasts.values() {
        public_key += r2.vss_commitments[0];
    }

    let mut public_shares = Vec::with_capacity(n);
    for party_j_0based in 0..n {
        let j = (party_j_0based + 1) as u64;
        let mut x_j = <C::ProjectivePoint as Group>::identity();
        for r2 in r2_bcasts.values() {
            let mut j_pow = C::Scalar::ONE;
            let j_scalar = C::Scalar::from(j);
            for com in &r2.vss_commitments {
                x_j += *com * j_pow;
                j_pow *= j_scalar;
            }
        }
        public_shares.push(x_j);
    }

    let jl_sk = r1_state
        .jl_sk
        .take()
        .ok_or_else(|| TecdsaError::Other("jl_sk already consumed".into()))?;

    let mut jl_pks: Vec<JlPublicKey> = Vec::with_capacity(n);
    for &pid in all_parties {
        if pid == my_id {
            jl_pks.push(r1_state.jl_pk.clone());
        } else {
            let r2 = r2_bcasts
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing R2 for {pid}")))?;
            jl_pks.push(r2.jl_pk.clone());
        }
    }

    let my_0based = my_1based - 1;

    let key_share = Xal23KeyShare {
        party_index: my_0based,
        secret_share: combined_share,
        public_key,
        public_shares,
        vss_setup: VssSetup {
            threshold,
            total: n as u16,
        },
        jl_sk,
        jl_pks,
    };

    Ok(key_share)
}
