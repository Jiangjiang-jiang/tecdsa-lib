// SPDX-License-Identifier: MIT OR Apache-2.0
//! Serde helpers for scalar field elements via `PrimeField`.
//!
//! Scalars are encoded as their canonical big-endian `Repr` bytes.
//! Deserialisation rejects both wrong lengths and non-canonical values (those
//! at or above the group order), because `PrimeField::from_repr` does.
//!
//! # Usage in structs
//!
//! ```text
//! #[serde(with = "tecdsa_curve::serde_scalar")]
//! pub field: C::Scalar,
//!
//! #[serde(with = "tecdsa_curve::serde_scalar::vec")]
//! pub field: Vec<C::Scalar>,
//! ```

use elliptic_curve::PrimeField;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn from_slice<F: PrimeField>(bytes: &[u8]) -> Option<F> {
    let mut repr = F::Repr::default();
    if bytes.len() != repr.as_ref().len() {
        return None;
    }
    repr.as_mut().copy_from_slice(bytes);
    Option::from(F::from_repr(repr))
}

/// Serialize a scalar as its canonical big-endian bytes.
///
/// # Errors
/// Returns the serializer's error type on failure.
pub fn serialize<F, S>(value: &F, serializer: S) -> Result<S::Ok, S::Error>
where
    F: PrimeField,
    S: Serializer,
{
    value.to_repr().as_ref().serialize(serializer)
}

/// Deserialize a scalar from its canonical big-endian bytes.
///
/// # Errors
/// Returns an error if the length is wrong or the value is not canonical.
pub fn deserialize<'de, F, D>(deserializer: D) -> Result<F, D::Error>
where
    F: PrimeField,
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    from_slice::<F>(&bytes)
        .ok_or_else(|| serde::de::Error::custom("invalid or non-canonical scalar encoding"))
}

/// Serde helpers for `Vec<Scalar>`.
pub mod vec {
    use elliptic_curve::PrimeField;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a `Vec<F>` where each `F: PrimeField`.
    ///
    /// # Errors
    /// Returns the serializer's error type on failure.
    pub fn serialize<F, S>(values: &[F], serializer: S) -> Result<S::Ok, S::Error>
    where
        F: PrimeField,
        S: Serializer,
    {
        let byte_vecs: Vec<Vec<u8>> = values
            .iter()
            .map(|v| v.to_repr().as_ref().to_vec())
            .collect();
        byte_vecs.serialize(serializer)
    }

    /// Deserialize a `Vec<F>` where each `F: PrimeField`.
    ///
    /// # Errors
    /// Returns an error if any element is the wrong length or non-canonical.
    pub fn deserialize<'de, F, D>(deserializer: D) -> Result<Vec<F>, D::Error>
    where
        F: PrimeField,
        D: Deserializer<'de>,
    {
        Vec::<Vec<u8>>::deserialize(deserializer)?
            .into_iter()
            .map(|bytes| {
                super::from_slice::<F>(&bytes).ok_or_else(|| {
                    serde::de::Error::custom("invalid or non-canonical scalar encoding")
                })
            })
            .collect()
    }
}
