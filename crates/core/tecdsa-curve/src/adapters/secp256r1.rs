// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::TecdsaCurve;
use elliptic_curve::{
    ctutils::CtOption,
    ops::Reduce,
    point::AffineCoordinates,
    sec1::{FromSec1Point, Sec1Point},
};
use p256::{AffinePoint, NistP256, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};
use tecdsa_core::TecdsaError;

/// Adapter type re-exported for users who want to name it via `Secp256r1Adapter`.
///
/// This is a type alias — the actual `TecdsaCurve` impl is on `p256::NistP256` directly.
pub type Secp256r1Adapter = NistP256;

impl TecdsaCurve for NistP256 {
    const CURVE_NAME: &'static str = "secp256r1";
    const SCALAR_BYTES: usize = 32;
    const HASH_DST: &'static [u8] = b"tecdsa/secp256r1";

    fn generator() -> ProjectivePoint {
        ProjectivePoint::GENERATOR
    }

    fn xcoord_mod_q(p: &AffinePoint) -> Scalar {
        // AffineCoordinates::x() returns FieldBytes (32 big-endian bytes).
        let x_bytes = p.x();
        let x_uint = U256::from_be_slice(x_bytes.as_ref());
        Scalar::reduce(&x_uint)
    }

    fn point_to_bytes(p: &AffinePoint) -> Vec<u8> {
        use elliptic_curve::sec1::ToSec1Point;
        p.to_sec1_point(true).as_bytes().to_vec()
    }

    fn point_from_bytes(bytes: &[u8]) -> tecdsa_core::Result<AffinePoint> {
        let ep = Sec1Point::<NistP256>::from_bytes(bytes)
            .map_err(|e| TecdsaError::InvalidKey(format!("{e}")))?;
        let ct: CtOption<AffinePoint> = AffinePoint::from_sec1_point(&ep);
        Option::<AffinePoint>::from(ct)
            .ok_or_else(|| TecdsaError::InvalidKey("invalid point".into()))
    }

    fn nums_pedersen_h() -> ProjectivePoint {
        // Hash-to-try: increment the x-coordinate until we find a valid point.
        // Uses a fixed domain-separation tag so the DL w.r.t. G is unknown.
        let hash = Sha256::digest(b"tecdsa/secp256r1/pedersen-h/nums");
        let mut x_bytes = [0u8; 33];
        x_bytes[0] = 0x02; // compressed-even prefix
        x_bytes[1..].copy_from_slice(&hash);
        loop {
            if let Ok(ep) = Sec1Point::<NistP256>::from_bytes(&x_bytes) {
                let ct: CtOption<AffinePoint> = AffinePoint::from_sec1_point(&ep);
                if let Some(pt) = Option::<AffinePoint>::from(ct) {
                    return ProjectivePoint::from(pt);
                }
            }
            // Increment the x-candidate (big-endian carry-add starting from LSB).
            for byte in x_bytes[1..].iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
        }
    }
}
