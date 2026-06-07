// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! Coin-flip protocol for distributed random number generation.
//!
//! A 2-round commit-reveal protocol used in DKG-CL setup to jointly generate
//! random values (e.g., CL prime `q'` and base element `h`).
//!
//! ## Protocol
//!
//! 1. **Round 1 (Commit)**: Each party samples a random value `v` and nonce `r`,
//!    broadcasts `commitment = SHA-256(r || v)`.
//! 2. **Round 2 (Reveal)**: Each party reveals `(v, r)`.
//!    All parties verify commitments and combine revealed values via XOR.
//!
//! The XOR combination ensures that if at least one party is honest
//! (i.e., chose `v` uniformly at random), the combined output is uniform.

use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

/// Round 1 output broadcast to all parties.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinFlipCommitment {
    /// `SHA-256(nonce || value)`
    pub hash: [u8; 32],
}

/// Round 1 private state kept by the committer.
#[derive(Clone, Debug)]
pub struct CoinFlipState {
    /// The random value committed to.
    pub value: Vec<u8>,
    /// The nonce used in the commitment.
    pub nonce: [u8; 32],
}

/// Generate a coin-flip commitment.
///
/// Samples `value_len` random bytes as the contributed value and a 32-byte
/// nonce, then computes `commitment = SHA-256(nonce || value)`.
///
/// # Arguments
///
/// - `rng`: a cryptographic RNG.
/// - `value_len`: the length in bytes of the random value to generate.
///
/// # Returns
///
/// A tuple of (commitment to broadcast, private state to keep).
pub fn coin_flip_commit(
    rng: &mut impl CryptoRngCore,
    value_len: usize,
) -> (CoinFlipCommitment, CoinFlipState) {
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let mut value = vec![0u8; value_len];
    rng.fill_bytes(&mut value);

    let hash = compute_commitment_hash(&nonce, &value);

    (CoinFlipCommitment { hash }, CoinFlipState { value, nonce })
}

/// Verify a revealed value against its commitment.
///
/// Recomputes `SHA-256(nonce || value)` and checks equality with the
/// commitment hash.
///
/// # Arguments
///
/// - `commitment`: the commitment received in Round 1.
/// - `value`: the revealed value from Round 2.
/// - `nonce`: the revealed nonce from Round 2.
///
/// # Returns
///
/// `true` if the commitment is valid, `false` otherwise.
pub fn coin_flip_verify(commitment: &CoinFlipCommitment, value: &[u8], nonce: &[u8; 32]) -> bool {
    let expected = compute_commitment_hash(nonce, value);
    // Constant-time comparison to prevent timing attacks on the hash.
    use subtle::ConstantTimeEq;
    commitment.hash.ct_eq(&expected).into()
}

/// Combine all parties' revealed values by XOR.
///
/// Each byte position is XORed across all values. All values must have the
/// same length; this function panics if they differ.
///
/// # Arguments
///
/// - `values`: slice of byte-slice references, one per party.
///
/// # Panics
///
/// Panics if `values` is empty or if the values have different lengths.
pub fn coin_flip_combine(values: &[&[u8]]) -> Vec<u8> {
    assert!(!values.is_empty(), "at least one value required");
    let len = values[0].len();
    for v in &values[1..] {
        assert_eq!(v.len(), len, "all values must have the same length");
    }

    let mut result = vec![0u8; len];
    for v in values {
        for (r, b) in result.iter_mut().zip(v.iter()) {
            *r ^= b;
        }
    }
    result
}

/// Internal: compute `SHA-256(nonce || value)`.
fn compute_commitment_hash(nonce: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(value);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn commit_and_verify() {
        let (commitment, state) = coin_flip_commit(&mut OsRng, 32);
        assert!(coin_flip_verify(&commitment, &state.value, &state.nonce));
    }

    #[test]
    fn verify_fails_with_wrong_value() {
        let (commitment, state) = coin_flip_commit(&mut OsRng, 32);

        let mut wrong_value = state.value.clone();
        wrong_value[0] ^= 0xFF;
        assert!(!coin_flip_verify(&commitment, &wrong_value, &state.nonce));
    }

    #[test]
    fn verify_fails_with_wrong_nonce() {
        let (commitment, state) = coin_flip_commit(&mut OsRng, 32);

        let mut wrong_nonce = state.nonce;
        wrong_nonce[0] ^= 0xFF;
        assert!(!coin_flip_verify(&commitment, &state.value, &wrong_nonce));
    }

    #[test]
    fn combine_is_deterministic() {
        let v1: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        let v2: &[u8] = &[0x11, 0x22, 0x33, 0x44];
        let v3: &[u8] = &[0x55, 0x66, 0x77, 0x88];

        let result1 = coin_flip_combine(&[v1, v2, v3]);
        let result2 = coin_flip_combine(&[v1, v2, v3]);
        assert_eq!(result1, result2);
    }

    #[test]
    fn combine_xor_correctness() {
        let v1: &[u8] = &[0xFF, 0x00, 0xAA];
        let v2: &[u8] = &[0x00, 0xFF, 0x55];

        let result = coin_flip_combine(&[v1, v2]);
        assert_eq!(result, vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn combine_single_value() {
        let v: &[u8] = &[0x12, 0x34, 0x56];
        let result = coin_flip_combine(&[v]);
        assert_eq!(result, v);
    }

    #[test]
    fn full_protocol_three_parties() {
        let (c1, s1) = coin_flip_commit(&mut OsRng, 16);
        let (c2, s2) = coin_flip_commit(&mut OsRng, 16);
        let (c3, s3) = coin_flip_commit(&mut OsRng, 16);

        // All parties verify all commitments
        assert!(coin_flip_verify(&c1, &s1.value, &s1.nonce));
        assert!(coin_flip_verify(&c2, &s2.value, &s2.nonce));
        assert!(coin_flip_verify(&c3, &s3.value, &s3.nonce));

        // Combine
        let combined = coin_flip_combine(&[&s1.value, &s2.value, &s3.value]);
        assert_eq!(combined.len(), 16);

        // Result is deterministic regardless of combination order
        let combined2 = coin_flip_combine(&[&s3.value, &s1.value, &s2.value]);
        assert_eq!(combined, combined2);
    }

    #[test]
    #[should_panic(expected = "at least one value required")]
    fn combine_panics_on_empty() {
        let empty: &[&[u8]] = &[];
        coin_flip_combine(empty);
    }

    #[test]
    #[should_panic(expected = "all values must have the same length")]
    fn combine_panics_on_different_lengths() {
        let v1: &[u8] = &[0x01, 0x02];
        let v2: &[u8] = &[0x03, 0x04, 0x05];
        coin_flip_combine(&[v1, v2]);
    }
}
