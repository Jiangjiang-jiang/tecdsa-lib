// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared utility functions for the DKLs23 protocol crate.
//!
//! Centralizes common operations used across keygen, presign, and sign rounds:
//! - Sender validation
//! - Point and scalar (de)serialization

#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::PartyId;

/// Validate that the sender is not self, and is part of the protocol parties.
pub fn validate_sender(
    from: PartyId,
    my_id: PartyId,
    parties: &[PartyId],
) -> tecdsa_core::Result<()> {
    if from == my_id {
        return Err(TecdsaError::Other("received message from self".into()));
    }
    if !parties.contains(&from) {
        return Err(TecdsaError::UnknownSender(from.0));
    }
    Ok(())
}

/// Check for duplicate messages and validate the sender in one step.
///
/// Returns an error if the sender is invalid or a duplicate message is detected.
pub fn validate_sender_no_dup<V>(
    from: PartyId,
    my_id: PartyId,
    parties: &[PartyId],
    received_map: &BTreeMap<PartyId, V>,
) -> tecdsa_core::Result<()> {
    validate_sender(from, my_id, parties)?;
    if received_map.contains_key(&from) {
        return Err(TecdsaError::DuplicateMessage(from.0));
    }
    Ok(())
}

/// Parse a scalar from exact-width, canonical big-endian bytes.
///
/// Strict on purpose: unlike `TecdsaCurve::scalar_from_bytes`, this rejects
/// wrong-length or out-of-range input instead of reducing it, since these
/// bytes are Shamir shares / nonces that must round-trip exactly.
// Internal byte-decoding helper; the unit error ("malformed input") is intentional.
#[allow(clippy::result_unit_err)]
pub fn scalar_from_canonical_bytes<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::Scalar, ()>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let fb = FieldBytes::<C>::try_from(bytes).map_err(|_| ())?;
    Option::from(<C::Scalar as PrimeField>::from_repr(fb)).ok_or(())
}
