// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! Matrix-relation engine for class-group ZK proofs.
//!
//! A "matrix relation" describes a system of group equations:
//!
//! ```text
//! For each row i:
//!   product_j (base_{i,j} ^ witness_j) = target_i
//! ```
//!
//! The engine generates and verifies Sigma-protocol proofs for such
//! matrix relations.

use rug::{integer::Order, Integer};

use crate::{
    cl::{ClResult, ClSetup, Qfi},
    zk::{challenge_from_qfi, response_unbounded, sample_random},
};

/// A single row in the matrix relation: `product(bases[j]^witnesses[j]) = target`.
pub struct MatrixRow {
    /// Bases for this row (one per witness).
    pub bases: Vec<Qfi>,
    /// Expected product target.
    pub target: Qfi,
}

/// A matrix-relation proof.
pub struct MatrixRelationProof {
    /// Commitments: one per row, `t_i = product(bases[i,j]^{alpha_j})`.
    commitments: Vec<Qfi>,
    /// Responses: one per witness, `z_j = alpha_j + e * w_j` (big-endian bytes).
    responses: Vec<Vec<u8>>,
    /// Fiat-Shamir challenge (big-endian bytes).
    e: Vec<u8>,
}

/// Generates a matrix-relation proof.
///
/// - `rows`: the matrix of bases and targets.
/// - `witnesses`: the witness values, one per column.
pub fn prove_matrix(
    setup: &mut ClSetup,
    rows: &[MatrixRow],
    witnesses: &[&Integer],
) -> ClResult<MatrixRelationProof> {
    let num_witnesses = witnesses.len();

    // Sample random alpha_j for each witness.
    let mut alphas = Vec::with_capacity(num_witnesses);
    for _ in 0..num_witnesses {
        alphas.push(sample_random(setup)?);
    }

    // Compute commitments: t_i = product(bases[i,j]^{alpha_j}).
    let mut commitments = Vec::with_capacity(rows.len());
    for row in rows {
        if row.bases.len() != num_witnesses {
            return Err(crate::cl::ClError::InvalidParam(format!(
                "row bases length {} != witnesses length {}",
                row.bases.len(),
                num_witnesses
            )));
        }
        let t = setup.multiexp(&row.bases, &alphas)?;
        commitments.push(t);
    }

    // Build challenge hash input: all targets + all commitments.
    let mut qfi_refs: Vec<&Qfi> = Vec::new();
    for row in rows {
        qfi_refs.push(&row.target);
    }
    for c in &commitments {
        qfi_refs.push(c);
    }
    let e = challenge_from_qfi(setup, b"R_matrix", &qfi_refs, &[])?;

    // Compute responses: z_j = alpha_j + e * w_j.
    let mut responses = Vec::with_capacity(num_witnesses);
    for (j, alpha) in alphas.iter().enumerate() {
        let z = response_unbounded(alpha, &e, witnesses[j]);
        responses.push(z);
    }

    Ok(MatrixRelationProof {
        commitments,
        responses,
        e,
    })
}

/// Verifies a matrix-relation proof.
pub fn verify_matrix(
    setup: &ClSetup,
    rows: &[MatrixRow],
    proof: &MatrixRelationProof,
) -> ClResult<bool> {
    if proof.commitments.len() != rows.len() {
        return Ok(false);
    }

    // Recompute challenge.
    let mut qfi_refs: Vec<&Qfi> = Vec::new();
    for row in rows {
        qfi_refs.push(&row.target);
    }
    for c in &proof.commitments {
        qfi_refs.push(c);
    }
    let e_check = challenge_from_qfi(setup, b"R_matrix", &qfi_refs, &[])?;
    if e_check != proof.e {
        return Ok(false);
    }

    // For each row, check: product(bases[i,j]^{z_j}) == t_i * target_i^e.
    let responses: Vec<Integer> = proof
        .responses
        .iter()
        .map(|z| Integer::from_digits(z, Order::Msf))
        .collect();
    let e = Integer::from_digits(&proof.e, Order::Msf);
    for (i, row) in rows.iter().enumerate() {
        let lhs = setup.multiexp(&row.bases, &responses)?;

        let target_e = setup.exp(&row.target, &e)?;
        let rhs = setup.compose(&proof.commitments[i], &target_e)?;

        if lhs != rhs {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use rug::Integer;

    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn matrix_relation_single_row() {
        let mut setup = ClSetup::new_secp256k1(17001u64).expect("setup");

        // Single row: h^w = target, where w = 42.
        let w = Integer::from(42u32);
        let h = setup.cl().h().clone();
        let target = setup.exp(&h, &w).expect("h^w");

        let rows = vec![MatrixRow {
            bases: vec![h],
            target,
        }];

        let proof = prove_matrix(&mut setup, &rows, &[&w]).expect("prove");
        assert!(verify_matrix(&setup, &rows, &proof).expect("verify"));
    }

    #[test]
    fn matrix_relation_multi_row() {
        let mut setup = ClSetup::new_secp256k1(17002u64).expect("setup");

        let w1 = Integer::from(7u32);
        let w2 = Integer::from(13u32);
        let h = setup.cl().h().clone();

        let target1 = setup.exp(&h, &w1).expect("h^w1");
        let target2 = setup.exp(&h, &w2).expect("h^w2");

        let id = setup.identity().expect("id");
        let h2 = setup.cl().h().clone();
        let id2 = setup.identity().expect("id");

        let rows = vec![
            MatrixRow {
                bases: vec![h, id],
                target: target1,
            },
            MatrixRow {
                bases: vec![id2, h2],
                target: target2,
            },
        ];

        let proof = prove_matrix(&mut setup, &rows, &[&w1, &w2]).expect("prove");
        assert!(verify_matrix(&setup, &rows, &proof).expect("verify"));
    }
}
