// SPDX-License-Identifier: MIT OR Apache-2.0
//! XAL23 online signing (1 round).
//!
//! Each party computes a partial signature `s_i = m * k_i + r * sigma_i`
//! and broadcasts it. The final signature is `s = sum(s_i)`.
//!
//! ## API
//!
//! Two interfaces are available:
//! - **Free functions**: [`partial_sign`] and [`combine_signatures`] for
//!   orchestrated/simulation usage.
//! - **StateMachine**: [`Xal23SignMachine`] for interactive 1-round signing
//!   with proper message exchange.

#![allow(non_snake_case)]

pub mod machine;
pub mod msg;

pub use machine::Xal23SignMachine;
pub use msg::Xal23SignMsg;

use crate::presign::Xal23Presignature;
use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{low_s_normalize, DataToSign, Signature};

/// A partial signature from a single party.
#[derive(Clone, Debug)]
pub struct PartialSignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The partial signature value: s_i = m * k_i + r * sigma_i.
    pub s_i: <C as CurveArithmetic>::Scalar,
}

/// Compute a partial signature from a presignature and message.
///
/// Each party computes: `s_i = m * k_i + r * sigma_i`
pub fn partial_sign<C: TecdsaCurve>(
    presig: &Xal23Presignature<C>,
    data: &DataToSign<C>,
) -> PartialSignature<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let m = *data.digest();
    let s_i = m * presig.k_i + presig.r * presig.sigma_i;
    PartialSignature { s_i }
}

/// Combine partial signatures into a full ECDSA signature.
///
/// Computes `s = sum(s_i)` and normalizes to low-S form.
///
/// # Errors
///
/// Returns an error if the combined signature fails verification against
/// the public key and message (which indicates a malicious party).
pub fn combine_signatures<C: TecdsaCurve>(
    presig: &Xal23Presignature<C>,
    partials: &[PartialSignature<C>],
    data: &DataToSign<C>,
) -> tecdsa_core::Result<Signature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint:
        elliptic_curve::ops::LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    use elliptic_curve::Field;

    let s: C::Scalar = partials.iter().fold(C::Scalar::ZERO, |acc, p| acc + p.s_i);
    let s = low_s_normalize::<C>(s);

    let sig = Signature { r: presig.r, s };

    // Verify the combined signature
    tecdsa_protocol::verify_ecdsa(&sig, &presig.public_key, data)?;

    Ok(sig)
}
