use std::collections::BTreeMap;

use elliptic_curve::{group::GroupEncoding, PrimeField};
use serde::{Deserialize, Serialize};
use tecdsa_core::TecdsaError;
use tecdsa_curve::zk::ddh::DdhProof;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Tx25OnlineSignMsg {
    Online(Vec<u8>),
}

#[derive(Clone)]
pub(crate) struct OnlineRoundMsg {
    pub(crate) delta_shares: BTreeMap<u16, k256::Scalar>,
    pub(crate) chi_shares: BTreeMap<u16, k256::Scalar>,
    pub(crate) d_point: k256::ProjectivePoint,
    pub(crate) gamma_point: k256::ProjectivePoint,
    pub(crate) ddh_proof: DdhProof<k256::Secp256k1>,
}

pub(crate) fn serialize_online_msg(msg: &OnlineRoundMsg) -> Vec<u8> {
    let n = msg.delta_shares.len() as u16;
    let mut buf = Vec::with_capacity(2 + (n as usize) * 66 + 33 + 33 + 98);

    buf.extend_from_slice(&n.to_be_bytes());

    for (&pid, delta) in &msg.delta_shares {
        buf.extend_from_slice(&pid.to_be_bytes());
        buf.extend_from_slice(delta.to_repr().as_ref());
        let chi = msg
            .chi_shares
            .get(&pid)
            .expect("chi must exist for each delta party");
        buf.extend_from_slice(chi.to_repr().as_ref());
    }

    buf.extend_from_slice(msg.d_point.to_bytes().as_ref());
    buf.extend_from_slice(msg.gamma_point.to_bytes().as_ref());

    buf.extend_from_slice(msg.ddh_proof.g_r.to_bytes().as_ref());
    buf.extend_from_slice(msg.ddh_proof.a_r.to_bytes().as_ref());
    buf.extend_from_slice(msg.ddh_proof.z.to_repr().as_ref());

    buf
}

pub(crate) fn deserialize_online_msg(data: &[u8]) -> Result<OnlineRoundMsg, TecdsaError> {
    if data.len() < 2 {
        return Err(TecdsaError::Other("online msg too short".into()));
    }

    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;

    let shares_size = n * 66;
    let expected = 2 + shares_size + 66 + 98;
    if data.len() < expected {
        return Err(TecdsaError::Other(format!(
            "online msg too short: expected at least {expected} bytes, got {}",
            data.len()
        )));
    }

    let mut delta_shares = BTreeMap::new();
    let mut chi_shares = BTreeMap::new();

    for _ in 0..n {
        let pid = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let mut repr = k256::FieldBytes::default();
        repr.copy_from_slice(&data[offset..offset + 32]);
        let delta = k256::Scalar::from_repr(repr)
            .into_option()
            .ok_or_else(|| TecdsaError::Other("invalid delta scalar".into()))?;
        offset += 32;

        let mut repr2 = k256::FieldBytes::default();
        repr2.copy_from_slice(&data[offset..offset + 32]);
        let chi = k256::Scalar::from_repr(repr2)
            .into_option()
            .ok_or_else(|| TecdsaError::Other("invalid chi scalar".into()))?;
        offset += 32;

        delta_shares.insert(pid, delta);
        chi_shares.insert(pid, chi);
    }

    let d_bytes: [u8; 33] = data[offset..offset + 33]
        .try_into()
        .map_err(|_| TecdsaError::Other("invalid D point bytes".into()))?;
    let d_point = decompress_point(&d_bytes)?;
    offset += 33;

    let gamma_bytes: [u8; 33] = data[offset..offset + 33]
        .try_into()
        .map_err(|_| TecdsaError::Other("invalid Gamma point bytes".into()))?;
    let gamma_point = decompress_point(&gamma_bytes)?;
    offset += 33;

    let g_r_bytes: [u8; 33] = data[offset..offset + 33]
        .try_into()
        .map_err(|_| TecdsaError::Other("invalid g_r bytes".into()))?;
    let g_r = decompress_point(&g_r_bytes)?;
    offset += 33;

    let a_r_bytes: [u8; 33] = data[offset..offset + 33]
        .try_into()
        .map_err(|_| TecdsaError::Other("invalid a_r bytes".into()))?;
    let a_r = decompress_point(&a_r_bytes)?;
    offset += 33;

    let mut z_repr = k256::FieldBytes::default();
    z_repr.copy_from_slice(&data[offset..offset + 32]);
    let z = k256::Scalar::from_repr(z_repr)
        .into_option()
        .ok_or_else(|| TecdsaError::Other("invalid z scalar in DDH proof".into()))?;

    let ddh_proof = DdhProof { g_r, a_r, z };

    Ok(OnlineRoundMsg {
        delta_shares,
        chi_shares,
        d_point,
        gamma_point,
        ddh_proof,
    })
}

pub(crate) fn decompress_point(bytes: &[u8; 33]) -> Result<k256::ProjectivePoint, TecdsaError> {
    let repr = k256::CompressedPoint::try_from(bytes.as_slice())
        .map_err(|_| TecdsaError::Other("invalid compressed point length".into()))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| TecdsaError::Other("invalid compressed point".into()))
}
