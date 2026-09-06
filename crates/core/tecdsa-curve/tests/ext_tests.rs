// SPDX-License-Identifier: MIT OR Apache-2.0
//! Behaviour of the scalar/point conversions that replaced `tecdsa_curve::conv`.

use elliptic_curve::{group::GroupEncoding, Curve};
use rug::{integer::Order, Integer};
use tecdsa_curve::{PointExt, ScalarExt, TecdsaCurve};

type K = k256::Secp256k1;
type P = p256::NistP256;

/// `order()` derives `q` from `-1`; it must agree with the curve's own constant.
#[test]
fn order_matches_curve_constant() {
    assert_eq!(
        K::order(),
        Integer::from_digits(K::ORDER.to_be_bytes().as_ref(), Order::Msf)
    );
    assert_eq!(
        P::order(),
        Integer::from_digits(P::ORDER.to_be_bytes().as_ref(), Order::Msf)
    );
    assert_eq!(K::order().significant_bits(), 256);
}

#[test]
fn scalar_bytes_round_trip() {
    let s = K::scalar_from_integer(&Integer::from(0xdead_beefu64));
    assert_eq!(s.to_bytes_vec().len(), 32);
    assert_eq!(K::scalar_from_bytes(&s.to_bytes_vec()), s);
    assert_eq!(s.to_integer(), Integer::from(0xdead_beefu64));
}

/// Reduction boundaries: `q` wraps to zero, `q + 1` to one.
#[test]
fn reduction_boundaries() {
    let q = K::order();
    assert_eq!(K::scalar_from_integer(&q), k256::Scalar::ZERO);
    assert_eq!(
        K::scalar_from_integer(&(q.clone() + 1u32)),
        k256::Scalar::ONE
    );
    assert_eq!(
        K::scalar_from_integer(&(q.clone() - 1u32)),
        -k256::Scalar::ONE
    );
    assert_eq!(K::scalar_from_bytes(&[]), k256::Scalar::ZERO);
    assert_eq!(K::scalar_from_bytes(&[0u8; 32]), k256::Scalar::ZERO);
}

/// Inputs wider than a scalar take the `rug` narrowing path; it must agree with
/// reducing the same value as an integer.
#[test]
fn over_length_input_reduces() {
    let wide = vec![0xffu8; 48];
    let as_int = Integer::from_digits(&wide, Order::Msf);
    assert_eq!(
        K::scalar_from_bytes(&wide),
        K::scalar_from_integer(&as_int.clone().modulo(&K::order()))
    );
    // 2^256 - 1 is above q, so the short and wide paths must still agree.
    let full = vec![0xffu8; 32];
    assert_eq!(
        K::scalar_from_bytes(&full),
        K::scalar_from_integer(&Integer::from_digits(&full, Order::Msf))
    );
}

/// Negative integers map to `q - |v|`; this is what the old `integer_to_scalar`
/// got wrong before it was fixed, so it is pinned here.
#[test]
fn negative_integers_negate_in_the_field() {
    for v in [1i64, 2, 12345, -1, -2, -12345] {
        let s = K::scalar_from_integer(&Integer::from(v));
        let expect = if v < 0 {
            -K::scalar_from_integer(&Integer::from(-v))
        } else {
            K::scalar_from_integer(&Integer::from(v))
        };
        assert_eq!(s, expect, "v = {v}");
    }
    assert_eq!(
        K::scalar_from_integer(&Integer::from(-1)),
        -k256::Scalar::ONE
    );
    // -q and q are both zero.
    assert_eq!(K::scalar_from_integer(&-K::order()), k256::Scalar::ZERO);
}

#[test]
fn to_integer_is_always_in_range() {
    let q = K::order();
    for v in [0i64, 1, -1, 7, -7] {
        let s = K::scalar_from_integer(&Integer::from(v));
        let i = s.to_integer();
        assert!(i >= 0 && i < q, "v = {v} gave {i}");
    }
}

#[test]
fn point_round_trip() {
    let g = K::generator();
    let bytes = g.to_bytes_vec();
    assert_eq!(k256::ProjectivePoint::from_bytes_slice(&bytes), Some(g));
}

#[test]
fn point_decoding_rejects_bad_input() {
    let g = K::generator();
    let mut bytes = g.to_bytes_vec();
    // Wrong length.
    assert!(k256::ProjectivePoint::from_bytes_slice(&bytes[..bytes.len() - 1]).is_none());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(k256::ProjectivePoint::from_bytes_slice(&longer).is_none());
    // Right length, but a non-canonical SEC1 prefix. k256 itself decodes 0x05
    // as 0x02; `from_bytes_slice` rejects it because it does not re-encode to
    // the input.
    bytes[0] = 0x05;
    assert!(k256::ProjectivePoint::from_bytes_slice(&bytes).is_none());
    let mut repr = <k256::ProjectivePoint as GroupEncoding>::Repr::default();
    repr.copy_from_slice(&bytes);
    assert_eq!(
        Option::<k256::ProjectivePoint>::from(k256::ProjectivePoint::from_bytes(&repr)),
        Some(g),
        "this test is only meaningful while k256 itself accepts the 0x05 prefix"
    );

    // Right length and prefix, but an x that is not on the curve. Roughly half
    // of all x values have no square root, so a short scan is enough to prove
    // curve membership is actually checked.
    let rejected = (1u8..64).any(|i| {
        let mut b = g.to_bytes_vec();
        b[0] = 0x02;
        b[1] = i;
        k256::ProjectivePoint::from_bytes_slice(&b).is_none()
    });
    assert!(rejected, "no off-curve x was rejected");
}

/// The traits are blanket impls, so they must work for a second curve too.
#[test]
fn works_for_p256() {
    let s = P::scalar_from_integer(&Integer::from(42u32));
    assert_eq!(s.to_integer(), Integer::from(42u32));
    assert_eq!(P::scalar_from_integer(&P::order()), p256::Scalar::ZERO);
    let g = P::generator();
    assert_eq!(
        p256::ProjectivePoint::from_bytes_slice(&g.to_bytes_vec()),
        Some(g)
    );
}
