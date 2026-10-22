// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared utility functions for GGN16 protocol crates.
//!
//! Contains serialization helpers used by both the
//! presign and online-sign state machines.

#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, sec1::ModulusSize, FieldBytesSize};
use rug::Integer;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::BigIntExt;

/// Serialize data for commitment: concatenate u_i and v_i byte representations.
pub fn serialize_for_commit_r1(u_i: &Integer, v_i: &Integer) -> Vec<u8> {
    let u_bytes = u_i.to_bytes_msf();
    let v_bytes = v_i.to_bytes_msf();
    let mut data = Vec::with_capacity(8 + u_bytes.len() + v_bytes.len());
    data.extend_from_slice(&(u_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(&u_bytes);
    data.extend_from_slice(&(v_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(&v_bytes);
    data
}

/// Serialize data for commitment: concatenate r_i and w_i byte representations.
pub fn serialize_for_commit_r3(r_i_bytes: &[u8], w_i: &Integer) -> Vec<u8> {
    let w_bytes = w_i.to_bytes_msf();
    let mut data = Vec::with_capacity(8 + r_i_bytes.len() + w_bytes.len());
    data.extend_from_slice(&(r_i_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(r_i_bytes);
    data.extend_from_slice(&(w_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(&w_bytes);
    data
}

/// Deserialize a projective point from its compressed SEC1 byte encoding.
// Internal byte-decoding helper; the unit error ("malformed input") is intentional.
#[allow(clippy::result_unit_err)]
pub fn deserialize_point<C>(bytes: &[u8]) -> Result<C::ProjectivePoint, ()>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
{
    let repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
    let buf_len = repr.as_ref().len();
    if bytes.len() != buf_len {
        return Err(());
    }
    let mut repr = repr;
    repr.as_mut().copy_from_slice(bytes);
    Option::from(C::ProjectivePoint::from_bytes(&repr)).ok_or(())
}
