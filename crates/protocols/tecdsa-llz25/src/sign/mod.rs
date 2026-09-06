// SPDX-License-Identifier: MIT OR Apache-2.0
//! LLZ25 online signing protocol (Round 2).
//!
//! ## Protocol (LLZ25, Section 4.2 -- Sign)
//!
//! All NIM decoding is **message-independent** and is performed offline at the
//! end of presign (see [`crate::presign::compute_presign_coefficients`]),
//! yielding per-party [`PresignCoefficients`]:
//! - $u\text{-coeff} = k_i \gamma_i + \sum_{j \neq i}(\alpha_{i,j} + \beta_{j,i})$
//!   -- party $i$'s additive share of $k\gamma$.
//! - $w\text{-coeff} = \lambda_i x_i \gamma_i + \sum_{j \neq i}(\mu_{i,j} + \nu_{j,i})$
//!   -- party $i$'s additive share of $x\gamma$.
//!
//! The online phase therefore touches **no class-group operations**.  Upon
//! learning the message, each party in quorum $P$:
//!
//! 1. $K = \prod_{j \in P} K_j$.
//! 2. Compute:
//!    - $m = H_{sig}(msg)$
//!    - $z = H_1(X, msg, \{pm_j\})$
//!    - $y = H_2(z)$
//!    - $R = K^z \cdot g^y$, $r = x(R) \bmod q$
//! 3. Compute signature shares from the precomputed coefficients:
//!    - $w_i = m \gamma_i + r \cdot (w\text{-coeff})$
//!    - $u_i = y \gamma_i + z \cdot (u\text{-coeff})$
//! 4. Broadcast $(w_i, u_i)$.
//!
//! ## Combine
//!
//! $w = \sum w_i$, $u = \sum u_i$, $\sigma = w / u \bmod q$.
//! Verify $(r, \sigma)$ against $(X, msg)$.

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

/// Partial signature from one party: $(w_i, u_i)$.
#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub w_i: k256::Scalar,
    pub u_i: k256::Scalar,
}

/// Hash function with a domain-separation prefix.
fn hash_with_prefix(prefix: &[u8], data: &[u8]) -> k256::Scalar {
    let hash = Sha256::new()
        .chain_update(prefix)
        .chain_update(data)
        .finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    use rug::{integer::Order, Integer};
    let val = Integer::from_digits(&bytes, Order::Msf);
    let q = tecdsa_curve::conv::curve_order::<k256::Secp256k1>();
    let reduced = val % &q;
    tecdsa_curve::conv::integer_to_scalar::<k256::Secp256k1>(&reduced)
}

/// Compute the message hash $m = H_{sig}(msg)$.
pub fn hash_sig(msg: &[u8]) -> k256::Scalar {
    hash_with_prefix(b"THRESHOLD_ECDSA_SIGNATURE", msg)
}

/// Compute $z = H_1(X, msg, \{pm_j\})$.
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

/// Compute $y = H_2(z)$.
fn hash_h2(z: &k256::Scalar) -> k256::Scalar {
    let z_bytes = z.to_repr();
    hash_with_prefix(b"THRESHOLD_ECDSA_H2", z_bytes.as_ref())
}

/// Compute one party's partial signature in the LLZ25 online sign phase.
///
/// This is the core computation of Round 2 and is intentionally cheap: it
/// performs **no class-group / NIM operations**.  All NIM decoding was done
/// offline during presign and folded into `coeffs` (see
/// [`crate::presign::compute_presign_coefficients`]).  No new messages are
/// sent except $(w_i, u_i)$.
///
/// # Arguments
/// - `public_key`: the joint ECDSA public key $X$.
/// - `presign_messages`: presign messages from ALL parties in the quorum
///   (used to form $K$ and the transcript hash $z$).
/// - `coeffs`: this party's precomputed presign coefficients.
/// - `msg`: the message to sign.
///
/// # Returns
/// `(partial_signature, r)` where `r = x(R) mod q`.
pub fn compute_partial_signature(
    public_key: &k256::ProjectivePoint,
    presign_messages: &[PresignMessage],
    coeffs: &PresignCoefficients,
    msg: &[u8],
) -> (PartialSignature, k256::Scalar) {
    // Compute K = sum(K_j).
    let big_k: k256::ProjectivePoint = presign_messages.iter().fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, pm| acc + pm.big_k,
    );

    // Compute hash values.
    let m = hash_sig(msg);
    let z = hash_h1(public_key, msg, presign_messages);
    let y = hash_h2(&z);

    // Compute R = K^z * g^y.
    let big_r = big_k * z + <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * y;
    let r = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine());

    // w_i = m * gamma_i + r * (lambda_i * x_i * gamma_i + sum(mu + nu))
    let w_i = m * coeffs.gamma_i + r * coeffs.w_coeff;

    // u_i = y * gamma_i + z * (k_i * gamma_i + sum(alpha + beta))
    let u_i = y * coeffs.gamma_i + z * coeffs.u_coeff;

    (PartialSignature { w_i, u_i }, r)
}

/// Combine partial signatures into a final ECDSA signature.
///
/// $w = \sum w_i$, $u = \sum u_i$, $\sigma = w \cdot u^{-1} \bmod q$.
/// The signature is $(r, \sigma)$.
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

    // Low-S normalization (BIP-146).
    let sigma = low_s_normalize::<k256::Secp256k1>(sigma_raw);

    let sig = Signature { r: *r, s: sigma };

    // Verify the signature.
    let m = hash_sig(msg);
    let data = DataToSign::from_digest(m);
    verify_ecdsa::<k256::Secp256k1>(&sig, public_key, &data).map_err(|e| {
        Llz25Error::SignatureVerification(format!("combined signature verification failed: {e}"))
    })?;

    Ok(sig)
}
