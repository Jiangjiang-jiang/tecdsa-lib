// SPDX-License-Identifier: MIT OR Apache-2.0
//! Extension methods on curve scalars and points.
//!
//! These are the conversions the protocols need that `elliptic-curve` does not
//! provide inherently. Methods that need only the scalar live here; those that
//! need the curve (reducing into the scalar field, the group order) are
//! associated functions on [`crate::TecdsaCurve`], so call sites read
//! `C::order()` rather than `<C::Scalar as ScalarExt>::order()`.
//!
//! Both traits are blanket-implemented, so importing the trait is enough:
//!
//! ```rust
//! use elliptic_curve::Field;
//! use tecdsa_curve::ScalarExt;
//! assert_eq!(k256::Scalar::ONE.to_bytes_vec().len(), 32);
//! ```

use elliptic_curve::{group::GroupEncoding, PrimeField};
use rug::{integer::Order, Integer};

/// Byte and integer views of a prime-field scalar.
pub trait ScalarExt: PrimeField {
    /// Big-endian encoding, always [`PrimeField::Repr`] wide.
    ///
    /// Not named `to_bytes`: `k256::Scalar` and `p256::Scalar` both have an
    /// inherent `to_bytes` returning `FieldBytes`, which would shadow this for
    /// concrete types while the trait method won for generic ones -- the same
    /// method call would then return different types depending on context.
    fn to_bytes_vec(&self) -> Vec<u8>;

    /// The scalar as a non-negative integer in `[0, order)`.
    fn to_integer(&self) -> Integer;
}

impl<F: PrimeField> ScalarExt for F {
    fn to_bytes_vec(&self) -> Vec<u8> {
        self.to_repr().as_ref().to_vec()
    }

    fn to_integer(&self) -> Integer {
        Integer::from_digits(self.to_repr().as_ref(), Order::Msf)
    }
}

/// Length-checked byte conversions for group elements.
pub trait PointExt: GroupEncoding {
    /// The canonical encoding, as an owned vector.
    fn to_bytes_vec(&self) -> Vec<u8>;

    /// Decode a point, rejecting wrong-length, invalid, and non-canonical input.
    ///
    /// Canonicity is enforced by re-encoding: `k256` 0.14 accepts a compressed
    /// point whose SEC1 prefix is `0x05` and decodes it as `0x02`, so without
    /// this check two distinct byte strings decode to the same point. Anything
    /// that hashes the received bytes and separately hashes a re-encoding of the
    /// decoded point would then disagree.
    fn from_bytes_slice(bytes: &[u8]) -> Option<Self>;
}

impl<G: GroupEncoding> PointExt for G {
    fn to_bytes_vec(&self) -> Vec<u8> {
        self.to_bytes().as_ref().to_vec()
    }

    fn from_bytes_slice(bytes: &[u8]) -> Option<Self> {
        let mut repr = G::Repr::default();
        if bytes.len() != repr.as_ref().len() {
            return None;
        }
        repr.as_mut().copy_from_slice(bytes);
        let point: Self = Option::from(G::from_bytes(&repr))?;
        (point.to_bytes().as_ref() == bytes).then_some(point)
    }
}
