#![allow(non_snake_case)]

pub mod machine;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic, PrimeField};
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    error::Llz25Error,
    presign::{PresignCoefficients, PresignMessage},
};

#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub w_i: k256::Scalar,
    pub u_i: k256::Scalar,
}

fn hash_with_prefix(prefix: &[u8], data: &[u8]) -> k256::Scalar {
    let hash = Sha256::new()
        .chain_update(prefix)
        .chain_update(data)
        .finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    use rug::{integer::Order, Integer};
    let val = Integer::from_digits(&bytes, Order::Msf);
    let q = Integer::from_str_radix(tecdsa_class_group::cl::SECP256K1_ORDER, 10).unwrap();
    let reduced = val % &q;
    tecdsa_curve::conv::integer_to_scalar::<k256::Secp256k1>(&reduced)
}

pub fn hash_sig(msg: &[u8]) -> k256::Scalar {
    hash_with_prefix(b"THRESHOLD_ECDSA_SIGNATURE", msg)
}

fn hash_h1(
    public_key: &k256::ProjectivePoint,
    msg: &[u8],
    presign_messages: &[PresignMessage],
) -> k256::Scalar {
    let mut data = Vec::new();
    data.extend_from_slice(&public_key.to_bytes());
    data.extend_from_slice(msg);
    for pm in presign_messages {
        data.extend_from_slice(&pm.big_k.to_bytes());
        data.extend_from_slice(&pm.big_gamma.to_bytes());
    }
    hash_with_prefix(b"THRESHOLD_ECDSA_H1", &data)
}

fn hash_h2(z: &k256::Scalar) -> k256::Scalar {
    let z_bytes = z.to_repr();
    hash_with_prefix(b"THRESHOLD_ECDSA_H2", z_bytes.as_ref())
}

pub fn compute_partial_signature(
    public_key: &k256::ProjectivePoint,
    presign_messages: &[PresignMessage],
    coeffs: &PresignCoefficients,
    msg: &[u8],
) -> (PartialSignature, k256::Scalar) {
    let big_k: k256::ProjectivePoint = presign_messages.iter().fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, pm| acc + pm.big_k,
    );

    let m = hash_sig(msg);
    let z = hash_h1(public_key, msg, presign_messages);
    let y = hash_h2(&z);

    let big_r = big_k * z + <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * y;
    let r = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine());

    let w_i = m * coeffs.gamma_i + r * coeffs.w_coeff;

    let u_i = y * coeffs.gamma_i + z * coeffs.u_coeff;

    (PartialSignature { w_i, u_i }, r)
}

pub fn combine_signatures(
    partials: &[PartialSignature],
    r: &k256::Scalar,
    public_key: &k256::ProjectivePoint,
    msg: &[u8],
) -> Result<Signature<k256::Secp256k1>, Llz25Error> {
    let w: k256::Scalar = partials.iter().map(|p| p.w_i).sum();
    let u: k256::Scalar = partials.iter().map(|p| p.u_i).sum();

    let u_inv = u
        .invert()
        .into_option()
        .ok_or_else(|| Llz25Error::Protocol("u is zero, cannot invert".into()))?;

    let sigma_raw = w * u_inv;

    let sigma = low_s_normalize::<k256::Secp256k1>(sigma_raw);

    let sig = Signature { r: *r, s: sigma };

    let m = hash_sig(msg);
    let data = DataToSign::from_digest(m);
    verify_ecdsa::<k256::Secp256k1>(&sig, public_key, &data).map_err(|e| {
        Llz25Error::SignatureVerification(format!("combined signature verification failed: {e}"))
    })?;

    Ok(sig)
}
