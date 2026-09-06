// SPDX-License-Identifier: MIT OR Apache-2.0
//! Compact binary serde adapter for [`rug::Integer`] wire fields.
//!
//! `rug`'s own serde implementation encodes integers as radix-string text,
//! which doubles the wire size of every ciphertext, Z_N element, and proof
//! component under binary codecs such as bincode. This module instead encodes
//! an integer as the tuple `(sign, magnitude)` where `sign` is `-1` for
//! negative values and `0` otherwise, and `magnitude` holds the absolute
//! value as big-endian (most-significant-first) base-256 digits (empty for
//! zero).
//!
//! Annotate wire-struct fields with:
//!
//! ```ignore
//! #[serde(with = "tecdsa_bigint::int_wire")]
//! pub n: rug::Integer,
//! // For vectors of integers:
//! #[serde(with = "tecdsa_bigint::int_wire::vec")]
//! pub zs: Vec<rug::Integer>,
//! ```

use rug::{integer::Order, Integer};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// Serialize an [`Integer`] as `(sign: i8, magnitude: bytes)`.
pub fn serialize<S: Serializer>(val: &Integer, serializer: S) -> Result<S::Ok, S::Error> {
    let sign: i8 = if val.cmp0() == core::cmp::Ordering::Less {
        -1
    } else {
        0
    };
    let magnitude = val.to_digits::<u8>(Order::MsfBe);
    (sign, serde_bytes::ByteBuf::from(magnitude)).serialize(serializer)
}

/// Deserialize an [`Integer`] from `(sign: i8, magnitude: bytes)`.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Integer, D::Error> {
    let (sign, magnitude) = <(i8, serde_bytes::ByteBuf)>::deserialize(deserializer)?;
    let val = Integer::from_digits(&magnitude, Order::MsfBe);
    match sign {
        0 => Ok(val),
        -1 => Ok(-val),
        _ => Err(D::Error::custom("invalid integer sign")),
    }
}

/// Adapter for `Vec<Integer>` fields: each element is `(sign, magnitude)`.
pub mod vec {
    use serde::de::Error as _;

    use super::{Deserialize, Deserializer, Integer, Order, Serialize, Serializer};

    /// Serialize a `Vec<Integer>` element-wise in the compact wire format.
    pub fn serialize<S: Serializer>(vals: &[Integer], serializer: S) -> Result<S::Ok, S::Error> {
        let wire: Vec<(i8, serde_bytes::ByteBuf)> = vals
            .iter()
            .map(|val| {
                let sign: i8 = if val.cmp0() == core::cmp::Ordering::Less {
                    -1
                } else {
                    0
                };
                (
                    sign,
                    serde_bytes::ByteBuf::from(val.to_digits::<u8>(Order::MsfBe)),
                )
            })
            .collect();
        wire.serialize(serializer)
    }

    /// Deserialize a `Vec<Integer>` from the compact wire format.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Integer>, D::Error> {
        let wire = <Vec<(i8, serde_bytes::ByteBuf)>>::deserialize(deserializer)?;
        wire.into_iter()
            .map(|(sign, magnitude)| {
                let val = Integer::from_digits(&magnitude, Order::MsfBe);
                match sign {
                    0 => Ok(val),
                    -1 => Ok(-val),
                    _ => Err(D::Error::custom("invalid integer sign")),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::Integer;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Wire {
        #[serde(with = "super")]
        x: Integer,
        #[serde(with = "super::vec")]
        v: Vec<Integer>,
    }

    #[test]
    fn roundtrip() {
        let w = Wire {
            x: -Integer::from(0x1122_3344_5566u64),
            v: vec![
                Integer::ZERO,
                Integer::from(1),
                Integer::from(-1),
                Integer::from(u128::MAX) * Integer::from(u128::MAX),
            ],
        };
        let bytes = bincode::serde::encode_to_vec(&w, bincode::config::standard()).unwrap();
        let (w2, _): (Wire, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn compact_size() {
        // A 3072-bit modulus must serialize to ~384 bytes plus a few bytes of
        // framing, not the ~770 bytes that the radix-16 string encoding costs.
        let n = <Integer as crate::BigIntExt>::two_pow(3072) - 1u8;
        let w = Wire { x: n, v: vec![] };
        let bytes = bincode::serde::encode_to_vec(&w, bincode::config::standard()).unwrap();
        assert!(
            bytes.len() < 384 + 16,
            "wire size {} too large",
            bytes.len()
        );
    }
}
