// SPDX-License-Identifier: MIT OR Apache-2.0
//! Online signing protocol for XAL+21 (1 message, optimal).
//!
//! The online phase uses the presignature from the offline phase to sign a
//! specific message. It is extremely efficient because it involves only
//! scalar arithmetic -- no Paillier operations, no EC scalar multiplications.
//!
//! ## Protocol
//!
//! Given message `m` with digest `h = H(m)`:
//!
//! 1. **P_2 computes and sends**: `s_2 = (k_2 + r_1)^{-1} * (h + r * x'_2) mod q`
//! 2. **P_1 computes**: `s = k_1^{-1} * (s_2 + r * x'_1) mod q`
//! 3. **P_1 verifies** the signature `(r, s)` against the public key and outputs it.
//!
//! ## Correctness
//!
//! ```text
//! s = k_1^{-1} * (s_2 + r * x'_1)
//!   = k_1^{-1} * ((k_2 + r_1)^{-1} * (h + r * x'_2) + r * x'_1)
//!   = k_1^{-1} * (k_2 + r_1)^{-1} * (h + r * x'_2 + r * x'_1 * (k_2 + r_1))
//!   = k^{-1} * (h + r * (x'_2 + x'_1 * (k_2 + r_1)))
//!   = k^{-1} * (h + r * x)
//! ```
//! which is the standard ECDSA equation.

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::error::Xal21Error;
use crate::key_share::Xal21Party1KeyShare;
use crate::offline_sign::{Party1Presignature, Party2Presignature};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Online phase message from P_2 to P_1.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party2OnlineMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Partial signature `s_2 = (k_2 + r_1)^{-1} * (h + r * x'_2) mod q`.
    pub s2: C::Scalar,
}

// ---------------------------------------------------------------------------
// Online signing functions
// ---------------------------------------------------------------------------

/// P_2, Online: compute partial signature `s_2`.
///
/// `s_2 = (k_2 + r_1)^{-1} * (h + r * x'_2) mod q`
///
/// This is pure scalar arithmetic -- no Paillier or EC operations.
pub fn party2_compute_s2<C: TecdsaCurve>(
    presig: &Party2Presignature<C>,
    message: &DataToSign<C>,
) -> Result<Party2OnlineMsg<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let h = *message.digest();

    // (k_2 + r_1)^{-1}
    let k2_plus_r1 = presig.k2 + presig.r1;
    let k2_plus_r1_inv = k2_plus_r1
        .invert()
        .into_option()
        .ok_or_else(|| Xal21Error::ProtocolState("k_2 + r_1 is zero, cannot invert".into()))?;

    // s_2 = (k_2 + r_1)^{-1} * (h + r * x'_2)
    let s2 = k2_plus_r1_inv * (h + presig.r * presig.x2_prime);

    Ok(Party2OnlineMsg { s2 })
}

/// P_1, Online: compute final ECDSA signature from P_2's partial signature.
///
/// `s = k_1^{-1} * (s_2 + r * x'_1) mod q`
///
/// Applies low-S normalization, verifies the signature, and outputs it.
pub fn party1_compute_signature<C: TecdsaCurve>(
    key_share: &Xal21Party1KeyShare<C>,
    presig: &Party1Presignature<C>,
    p2_msg: &Party2OnlineMsg<C>,
    message: &DataToSign<C>,
) -> Result<Signature<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    // k_1^{-1}
    let k1_inv = presig
        .k1
        .invert()
        .into_option()
        .ok_or_else(|| Xal21Error::ProtocolState("k_1 is zero, cannot invert".into()))?;

    // s = k_1^{-1} * (s_2 + r * x'_1) mod q
    let s_raw = k1_inv * (p2_msg.s2 + presig.r * presig.x1_prime);

    // Low-S normalization
    let s = low_s_normalize::<C>(s_raw);

    let signature = Signature { r: presig.r, s };

    // Verify the signature before outputting
    verify_ecdsa::<C>(&signature, &key_share.public_key, message).map_err(|e| {
        Xal21Error::EcdsaVerification(format!("final signature verification failed: {e}"))
    })?;

    Ok(signature)
}

// ---------------------------------------------------------------------------
// End-to-end convenience function
// ---------------------------------------------------------------------------

/// Run the complete online signing protocol given presignatures and a message.
///
/// This is a convenience function that runs both online steps sequentially.
pub fn online_sign<C: TecdsaCurve>(
    p1_key: &Xal21Party1KeyShare<C>,
    p1_presig: &Party1Presignature<C>,
    p2_presig: &Party2Presignature<C>,
    message: &DataToSign<C>,
) -> Result<Signature<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    // P_2 computes partial signature
    let p2_msg = party2_compute_s2::<C>(p2_presig, message)?;

    // P_1 computes and verifies final signature
    party1_compute_signature::<C>(p1_key, p1_presig, &p2_msg, message)
}
