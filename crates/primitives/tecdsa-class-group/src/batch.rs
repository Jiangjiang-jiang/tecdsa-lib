// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! Batch aggregator for CL-group ZK proofs.
//!
//! Combines multiple independent proofs of the same type using random
//! linear combination.  The verifier picks random weights, and checks
//! a single aggregated verification equation.
//!
//! This module provides a generic batch verification framework for
//! Schnorr-like Sigma protocols over CL groups.

use rug::{integer::Order, Integer};

use crate::{
    cl::{ClResult, ClSetup, Qfi},
    zk::challenge_from_qfi,
};

/// Converts big-endian bytes to an `Integer` (helper for wire-format proof fields).
fn int_from_bytes(bytes: &[u8]) -> Integer {
    Integer::from_digits(bytes, Order::Msf)
}

/// A single proof instance for batch verification.
///
/// Each instance represents a check of the form:
///   `base ^ response == commitment * target ^ challenge`
pub struct BatchInstance {
    /// The base element (e.g., `h` for key proofs).
    pub base: Qfi,
    /// The commitment from the proof.
    pub commitment: Qfi,
    /// The target (public statement, e.g., `pk`).
    pub target: Qfi,
    /// The response value (big-endian bytes).
    pub response: Vec<u8>,
    /// The challenge value (big-endian bytes).
    pub challenge: Vec<u8>,
}

/// Batch verifies `n` proof instances of a Schnorr-like relation.
///
/// The verifier picks random weights `w_1, ..., w_n` and checks:
///
/// ```text
/// product(base_i^{w_i * z_i}) == product(commit_i^{w_i} * target_i^{w_i * e_i})
/// ```
///
/// This is sound as long as the weights are sampled independently of
/// the proofs.
pub fn batch_verify(setup: &ClSetup, instances: &[BatchInstance]) -> ClResult<bool> {
    if instances.is_empty() {
        return Ok(true);
    }

    // Derive deterministic weights from hashing all instances together.
    let mut weight_qfi_refs: Vec<&Qfi> = Vec::new();
    let mut extra: Vec<Vec<u8>> = Vec::new();
    for inst in instances {
        weight_qfi_refs.push(&inst.base);
        weight_qfi_refs.push(&inst.commitment);
        weight_qfi_refs.push(&inst.target);
        extra.push(inst.response.clone());
        extra.push(inst.challenge.clone());
    }
    let extra_refs: Vec<&[u8]> = extra.iter().map(Vec::as_slice).collect();

    // For each instance, derive a weight by hashing with an index.
    let mut lhs = setup.identity()?;
    let mut rhs = setup.identity()?;

    for (idx, inst) in instances.iter().enumerate() {
        let idx_bytes = idx.to_string().into_bytes();
        let mut idx_extras: Vec<&[u8]> = extra_refs.clone();
        idx_extras.push(&idx_bytes);
        let w_bytes = challenge_from_qfi(setup, b"R_batch", &weight_qfi_refs, &idx_extras)?;
        let w = int_from_bytes(&w_bytes);

        // lhs += base^{w * z}
        let resp = int_from_bytes(&inst.response);
        let wz = Integer::from(&w * &resp);
        let base_wz = setup.exp(&inst.base, &wz)?;
        lhs = setup.compose(&lhs, &base_wz)?;

        // rhs += commit^w * target^{w*e}
        let commit_w = setup.exp(&inst.commitment, &w)?;
        let chal = int_from_bytes(&inst.challenge);
        let we = w * chal;
        let target_we = setup.exp(&inst.target, &we)?;
        let rhs_part = setup.compose(&commit_w, &target_we)?;
        rhs = setup.compose(&rhs, &rhs_part)?;
    }

    Ok(lhs == rhs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cl::ClSetup, zk::r_cl_kwlg::RClKwlgProof};

    #[test]
    fn batch_aggregator_n_proofs() {
        let mut setup = ClSetup::new_secp256k1(18001u64).expect("setup");

        // Generate 3 independent key-knowledge proofs and batch verify them.
        let mut instances = Vec::new();
        for _ in 0..3 {
            let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
            let sk = setup.sk_to_integer(&sk_raw);
            let pk_elt = pk_raw.elt().clone();

            let proof = RClKwlgProof::prove(&mut setup, &pk_raw, &sk).expect("prove");

            let h = setup.cl().h().clone();
            instances.push(BatchInstance {
                base: h,
                commitment: proof.t,
                target: pk_elt,
                response: proof.z,
                challenge: proof.e,
            });
        }

        assert!(batch_verify(&setup, &instances).expect("batch_verify"));
    }
}
