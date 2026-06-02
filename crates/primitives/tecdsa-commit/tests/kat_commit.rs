// SPDX-License-Identifier: MIT OR Apache-2.0
//! Known-Answer Tests for hash commitment.
//!
//! The commitment is H(nonce || message) with SHA-256. We freeze the
//! expected hash for a known (nonce, message) pair.

use sha2::{Digest, Sha256};

#[test]
fn kat_hash_commitment_sha256() {
    let nonce = [0u8; 32];
    let message = b"tecdsa-kat";

    let hash: [u8; 32] = Sha256::new()
        .chain_update(nonce)
        .chain_update(message)
        .finalize()
        .into();

    // The commitment scheme is H(nonce || message), so we verify the
    // hash commitment scheme produces a deterministic, frozen output.
    let actual_hex = hex::encode(hash);

    // Frozen expected value (generated once, never changes).
    let expected = "260d31dc13e577cfbbbeebd66ba09aa11d7bfd13157a2ffe76973aeca8f8e7da";
    assert_eq!(
        actual_hex, expected,
        "SHA-256(nonce || message) has changed"
    );
}
