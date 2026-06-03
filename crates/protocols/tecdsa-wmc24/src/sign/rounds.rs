// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMC24 online sign round state types.

use tecdsa_class_group::cl::Qfi;

// ---------------------------------------------------------------------------
// Received data
// ---------------------------------------------------------------------------

pub(crate) struct ReceivedR4 {
    pub(crate) pc: Qfi,
    pub(crate) party_index: usize,
}

// ---------------------------------------------------------------------------
// Message hashing
// ---------------------------------------------------------------------------

pub(crate) fn hash_message_to_scalar(message: &[u8]) -> k256::Scalar {
    use elliptic_curve::PrimeField;
    use sha2::{Digest, Sha256};

    let hash: [u8; 32] = Sha256::digest(message).into();
    let mut repr = k256::FieldBytes::default();
    repr.copy_from_slice(&hash);
    if let Some(s) = Option::from(k256::Scalar::from_repr(repr)) {
        return s;
    }
    repr[0] &= 0x7F;
    Option::from(k256::Scalar::from_repr(repr))
        .expect("scalar reduction must succeed after clearing top bit")
}
