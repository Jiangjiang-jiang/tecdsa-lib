// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 online signing round functions (1-round protocol).
//!
//! Each party computes a partial signature $s_i = m \cdot k_i + r \cdot \sigma_i$
//! where:
//! - $m$ is the message hash (scalar)
//! - $k_i$ is the nonce share from presigning
//! - $r = x(R) \bmod q$ from the presignature
//! - $\sigma_i$ is the party's share of $k \cdot x$ from presigning
//!
//! The final signature is $s = \sum s_i = k(m + rx)$, which is valid
//! for the nonce point $R = g^{1/k}$ under standard ECDSA verification.

#![allow(non_snake_case)]

use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::presign::Wmy23Presignature;

/// A partial signature from one party.
#[derive(Clone, Debug)]
pub struct PartialSignature {
    /// $s_i = m \cdot k_i + r \cdot \sigma_i$.
    pub s_i: k256::Scalar,
}

/// Compute this party's partial signature.
///
/// # Arguments
///
/// * `presig` - This party's presignature output.
/// * `message` - The message digest to sign.
///
/// # Returns
///
/// The partial signature $s_i$.
pub fn compute_partial_signature(
    presig: &Wmy23Presignature,
    message: &DataToSign<k256::Secp256k1>,
) -> PartialSignature {
    let m = *message.digest();
    let s_i = m * presig.k_i + presig.r_x * presig.sigma_i;
    PartialSignature { s_i }
}

/// Combine partial signatures into a final ECDSA signature.
///
/// # Arguments
///
/// * `partials` - All parties' partial signatures.
/// * `presig` - Any party's presignature (for R and r values, which are shared).
/// * `message` - The message digest.
/// * `public_key` - The ECDSA public key for verification.
///
/// # Errors
///
/// Returns an error if the combined signature fails ECDSA verification.
pub fn combine_signatures(
    partials: &[PartialSignature],
    presig: &Wmy23Presignature,
    message: &DataToSign<k256::Secp256k1>,
    public_key: &k256::ProjectivePoint,
) -> Result<Signature<k256::Secp256k1>, Box<dyn std::error::Error>> {
    // s = sum(s_i) = k(m + rx)
    let s_raw: k256::Scalar = partials.iter().map(|p| p.s_i).sum();

    // Low-S normalization (BIP-146)
    let s = low_s_normalize::<k256::Secp256k1>(s_raw);

    let sig = Signature { r: presig.r_x, s };

    // Verify the signature
    verify_ecdsa::<k256::Secp256k1>(&sig, public_key, message)?;

    Ok(sig)
}
