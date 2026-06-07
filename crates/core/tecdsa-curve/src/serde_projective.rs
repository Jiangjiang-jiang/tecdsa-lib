// SPDX-License-Identifier: MIT OR Apache-2.0
//! Serde helpers for `ProjectivePoint` types via `GroupEncoding`.
//!
//! # Usage in structs
//!
//! ```text
//! #[serde(with = "tecdsa_curve::serde_projective")]
//! pub field: C::ProjectivePoint,
//! ```
//!
//! For `Vec<C::ProjectivePoint>`, use the [`vec`](mod@vec) submodule:
//!
//! ```text
//! #[serde(with = "tecdsa_curve::serde_projective::vec")]
//! pub field: Vec<C::ProjectivePoint>,
//! ```

use elliptic_curve::group::GroupEncoding;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn repr_from_slice<T: GroupEncoding>(bytes: &[u8]) -> Option<T::Repr> {
    let mut repr = T::Repr::default();
    let buf = repr.as_mut();
    if bytes.len() != buf.len() {
        return None;
    }
    buf.copy_from_slice(bytes);
    Some(repr)
}

/// Serialize a `GroupEncoding` type as its canonical byte representation.
///
/// # Errors
///
/// Returns the serializer's error type on failure.
pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: GroupEncoding,
    S: Serializer,
{
    let bytes = value.to_bytes();
    bytes.as_ref().serialize(serializer)
}

/// Deserialize a `GroupEncoding` type from its canonical byte representation.
///
/// # Errors
///
/// Returns an error if the byte length is wrong or the encoding is invalid.
pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: GroupEncoding,
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    let repr = repr_from_slice::<T>(&bytes)
        .ok_or_else(|| serde::de::Error::custom("invalid byte length for projective point"))?;
    let ct_opt = T::from_bytes(&repr);
    Option::from(ct_opt)
        .ok_or_else(|| serde::de::Error::custom("invalid projective point encoding"))
}

/// Serde helpers for `Vec<ProjectivePoint>` via `GroupEncoding`.
pub mod vec {
    use elliptic_curve::group::GroupEncoding;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a `Vec<T>` where each `T: GroupEncoding`.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error type on failure.
    pub fn serialize<T, S>(values: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: GroupEncoding,
        S: Serializer,
    {
        let byte_vecs: Vec<Vec<u8>> = values
            .iter()
            .map(|v| v.to_bytes().as_ref().to_vec())
            .collect();
        byte_vecs.serialize(serializer)
    }

    /// Deserialize a `Vec<T>` where each `T: GroupEncoding`.
    ///
    /// # Errors
    ///
    /// Returns an error if any element has wrong byte length or invalid encoding.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: GroupEncoding,
        D: Deserializer<'de>,
    {
        let byte_vecs = Vec::<Vec<u8>>::deserialize(deserializer)?;
        byte_vecs
            .into_iter()
            .map(|bytes| {
                let repr = super::repr_from_slice::<T>(&bytes).ok_or_else(|| {
                    serde::de::Error::custom("invalid byte length for projective point")
                })?;
                let ct_opt = T::from_bytes(&repr);
                Option::from(ct_opt)
                    .ok_or_else(|| serde::de::Error::custom("invalid projective point encoding"))
            })
            .collect()
    }
}
