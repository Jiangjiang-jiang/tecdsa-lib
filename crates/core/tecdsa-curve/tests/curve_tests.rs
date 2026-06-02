// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_curve::TecdsaCurve;

#[cfg(feature = "secp256k1")]
mod secp256k1_tests {
    use super::*;
    use elliptic_curve::group::Group;
    use k256::Secp256k1;

    #[test]
    fn generator_is_not_identity() {
        let g = Secp256k1::generator();
        assert!(!bool::from(g.is_identity()));
    }

    #[test]
    fn scalar_mul_basic() {
        let g = Secp256k1::generator();
        let point = g + g;
        assert!(!bool::from(point.is_identity()));
    }

    #[test]
    fn point_serialization_roundtrip() {
        let g = Secp256k1::generator();
        let affine: k256::AffinePoint = g.into();
        let bytes = Secp256k1::point_to_bytes(&affine);
        let recovered = Secp256k1::point_from_bytes(&bytes).unwrap();
        assert_eq!(affine, recovered);
    }

    #[test]
    fn nums_pedersen_h_differs_from_g() {
        let g: k256::AffinePoint = Secp256k1::generator().into();
        let h: k256::AffinePoint = Secp256k1::nums_pedersen_h().into();
        assert_ne!(g, h);
    }
}
