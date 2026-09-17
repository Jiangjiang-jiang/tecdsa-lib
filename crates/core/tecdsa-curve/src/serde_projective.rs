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

/// Decode a point, rejecting wrong-length, invalid, and non-canonical input.
///
/// Canonicity is enforced by re-encoding: `k256` 0.14 accepts a compressed
/// point whose SEC1 prefix is `0x05` and decodes it as `0x02`, so without this
/// check two distinct byte strings decode to the same point. Anything that
/// hashes the received bytes and separately hashes a re-encoding of the decoded
/// point would then disagree.
fn point_from_canonical_bytes<T: GroupEncoding>(bytes: &[u8]) -> Option<T> {
    let repr = repr_from_slice::<T>(bytes)?;
    let point: T = Option::from(T::from_bytes(&repr))?;
    (point.to_bytes().as_ref() == bytes).then_some(point)
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
/// Returns an error if the byte length is wrong, the encoding is invalid, or the
/// encoding is valid but not canonical.
pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: GroupEncoding,
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    point_from_canonical_bytes::<T>(&bytes)
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
    /// Returns an error if any element has wrong byte length, an invalid
    /// encoding, or a valid but non-canonical encoding.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: GroupEncoding,
        D: Deserializer<'de>,
    {
        let byte_vecs = Vec::<Vec<u8>>::deserialize(deserializer)?;
        byte_vecs
            .into_iter()
            .map(|bytes| {
                super::point_from_canonical_bytes::<T>(&bytes)
                    .ok_or_else(|| serde::de::Error::custom("invalid projective point encoding"))
            })
            .collect()
    }
}

#[cfg(all(test, feature = "secp256k1"))]
mod tests {
    use elliptic_curve::group::GroupEncoding;

    use super::point_from_canonical_bytes;
    use crate::TecdsaCurve;

    type P = k256::ProjectivePoint;

    #[test]
    fn point_decoding_rejects_bad_input() {
        let g = <k256::Secp256k1 as TecdsaCurve>::generator();
        let mut bytes = AsRef::<[u8]>::as_ref(&g.to_bytes()).to_vec();
        assert_eq!(point_from_canonical_bytes::<P>(&bytes), Some(g));
        // Wrong length.
        assert!(point_from_canonical_bytes::<P>(&bytes[..bytes.len() - 1]).is_none());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(point_from_canonical_bytes::<P>(&longer).is_none());
        // Right length, but a non-canonical SEC1 prefix. k256 itself decodes 0x05
        // as 0x02; `point_from_canonical_bytes` rejects it because it does not
        // re-encode to the input.
        bytes[0] = 0x05;
        assert!(point_from_canonical_bytes::<P>(&bytes).is_none());
        let mut repr = <P as GroupEncoding>::Repr::default();
        repr.copy_from_slice(&bytes);
        assert_eq!(
            Option::<P>::from(P::from_bytes(&repr)),
            Some(g),
            "this test is only meaningful while k256 itself accepts the 0x05 prefix"
        );

        // Right length and prefix, but an x that is not on the curve. Roughly half
        // of all x values have no square root, so a short scan is enough to prove
        // curve membership is actually checked.
        let rejected = (1u8..64).any(|i| {
            let mut b = AsRef::<[u8]>::as_ref(&g.to_bytes()).to_vec();
            b[0] = 0x02;
            b[1] = i;
            point_from_canonical_bytes::<P>(&b).is_none()
        });
        assert!(rejected, "no off-curve x was rejected");
    }
}
