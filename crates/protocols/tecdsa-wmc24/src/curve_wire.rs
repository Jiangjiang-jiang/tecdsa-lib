// SPDX-License-Identifier: GPL-3.0-or-later
use elliptic_curve::group::GroupEncoding;

/// Decode a compressed SEC1 point from a byte slice.
///
/// Shared helper used by both keygen and presign modules.
pub fn point_from_bytes(bytes: &[u8], label: &str) -> Result<k256::ProjectivePoint, String> {
    let repr = k256::CompressedPoint::try_from(bytes)
        .map_err(|e| format!("invalid point bytes ({label}): {e}"))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| format!("invalid EC point: {label}"))
}
