// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::envelope::{Header, PREAMBLE, WIRE_VERSION};
use serde::{Deserialize, Serialize};
use tecdsa_core::TecdsaError;

fn bincode_config() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_big_endian()
        .with_fixed_int_encoding()
}

/// Encode a header and payload into a wire-format byte vector.
///
/// # Errors
///
/// Returns [`tecdsa_core::TecdsaError::Serialization`] if bincode encoding fails
/// or if the serialized header exceeds `u32::MAX` bytes.
pub fn encode<T: Serialize>(header: &Header, payload: &T) -> tecdsa_core::Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(PREAMBLE);
    buf.extend_from_slice(&WIRE_VERSION.to_le_bytes());

    let header_bytes = bincode::serde::encode_to_vec(header, bincode_config())
        .map_err(|e| TecdsaError::Serialization(e.to_string()))?;
    let payload_bytes = bincode::serde::encode_to_vec(payload, bincode_config())
        .map_err(|e| TecdsaError::Serialization(e.to_string()))?;

    let header_len = u32::try_from(header_bytes.len())
        .map_err(|_| TecdsaError::Serialization("header too large for wire format".into()))?;

    buf.extend_from_slice(&header_len.to_be_bytes());
    buf.extend_from_slice(&header_bytes);
    buf.extend_from_slice(&payload_bytes);
    Ok(buf)
}

/// Decode a wire-format byte slice into a header and payload.
///
/// # Errors
///
/// Returns [`tecdsa_core::TecdsaError::Serialization`] if:
/// - the input is too short,
/// - the preamble is invalid,
/// - the wire version is not [`WIRE_VERSION`],
/// - header or payload data is truncated, or
/// - bincode decoding fails.
///
/// # Panics
///
/// Does not panic in practice; the internal `expect` calls are on fixed-width
/// slices whose lengths are verified by the preceding guards.
pub fn decode<T: for<'de> Deserialize<'de>>(data: &[u8]) -> tecdsa_core::Result<(Header, T)> {
    if data.len() < 8 {
        return Err(TecdsaError::Serialization("too short".into()));
    }
    if &data[..4] != PREAMBLE {
        return Err(TecdsaError::Serialization("invalid preamble".into()));
    }
    // SAFETY: length checked above; slice is exactly 4 bytes, infallible.
    let version = u32::from_le_bytes(data[4..8].try_into().expect("4-byte slice"));
    if version != WIRE_VERSION {
        return Err(TecdsaError::Serialization(format!(
            "unsupported wire version: {version}"
        )));
    }

    let rest = &data[8..];
    if rest.len() < 4 {
        return Err(TecdsaError::Serialization("missing header length".into()));
    }
    // SAFETY: slice is exactly 4 bytes, infallible.
    let header_len = u32::from_be_bytes(rest[..4].try_into().expect("4-byte slice")) as usize;
    if rest.len() < 4 + header_len {
        return Err(TecdsaError::Serialization("header data truncated".into()));
    }
    let header_data = &rest[4..4 + header_len];
    let payload_data = &rest[4 + header_len..];

    let (header, _): (Header, _) = bincode::serde::decode_from_slice(header_data, bincode_config())
        .map_err(|e| TecdsaError::Serialization(e.to_string()))?;
    let (payload, _): (T, _) = bincode::serde::decode_from_slice(payload_data, bincode_config())
        .map_err(|e| TecdsaError::Serialization(e.to_string()))?;

    Ok((header, payload))
}
