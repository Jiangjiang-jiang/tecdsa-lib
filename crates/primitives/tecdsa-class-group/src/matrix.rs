#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use crate::{
    cl::{ClResult, ClSetup, Qfi},
    zk::{challenge_from_qfi, response_unbounded, sample_random},
};

pub struct MatrixRow {
    pub bases: Vec<Qfi>,
    pub target: Qfi,
}

pub struct MatrixRelationProof {
    commitments: Vec<Qfi>,
    responses: Vec<Vec<u8>>,
    e: Vec<u8>,
}

pub fn prove_matrix(
    setup: &mut ClSetup,
    rows: &[MatrixRow],
    witnesses: &[&[u8]],
) -> ClResult<MatrixRelationProof> {
    let num_witnesses = witnesses.len();

    let mut alphas = Vec::with_capacity(num_witnesses);
    for _ in 0..num_witnesses {
        alphas.push(sample_random(setup)?);
    }

    let mut commitments = Vec::with_capacity(rows.len());
    for row in rows {
        if row.bases.len() != num_witnesses {
            return Err(crate::cl::ClError::InvalidParam(format!(
                "row bases length {} != witnesses length {}",
                row.bases.len(),
                num_witnesses
            )));
        }
        let t = setup.multiexp_bytes(&row.bases, &alphas)?;
        commitments.push(t);
    }

    let mut qfi_refs: Vec<&Qfi> = Vec::new();
    for row in rows {
        qfi_refs.push(&row.target);
    }
    for c in &commitments {
        qfi_refs.push(c);
    }
    let e = challenge_from_qfi(setup, b"R_matrix", &qfi_refs, &[])?;

    let mut responses = Vec::with_capacity(num_witnesses);
    for (j, alpha) in alphas.iter().enumerate() {
        let z = response_unbounded(alpha, &e, witnesses[j])?;
        responses.push(z);
    }

    Ok(MatrixRelationProof {
        commitments,
        responses,
        e,
    })
}

pub fn verify_matrix(
    setup: &ClSetup,
    rows: &[MatrixRow],
    proof: &MatrixRelationProof,
) -> ClResult<bool> {
    if proof.commitments.len() != rows.len() {
        return Ok(false);
    }

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

    for (i, row) in rows.iter().enumerate() {
        let lhs = setup.multiexp_bytes(&row.bases, &proof.responses)?;

        let target_e = setup.exp_bytes(&row.target, &proof.e)?;
        let rhs = setup.compose(&proof.commitments[i], &target_e)?;

        if lhs != rhs {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use rug::{integer::Order, Integer};

    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn matrix_relation_single_row() {
        let mut setup = ClSetup::new_secp256k1("17001").expect("setup");

        let w = Integer::from(42u32).to_digits::<u8>(Order::Msf);
        let h = setup.cl().h().clone();
        let target = setup.exp(&h, "42").expect("h^w");

        let rows = vec![MatrixRow {
            bases: vec![h],
            target,
        }];

        let proof = prove_matrix(&mut setup, &rows, &[&w]).expect("prove");
        assert!(verify_matrix(&setup, &rows, &proof).expect("verify"));
    }

    #[test]
    fn matrix_relation_multi_row() {
        let mut setup = ClSetup::new_secp256k1("17002").expect("setup");

        let w1 = Integer::from(7u32).to_digits::<u8>(Order::Msf);
        let w2 = Integer::from(13u32).to_digits::<u8>(Order::Msf);
        let h = setup.cl().h().clone();

        let target1 = setup.exp(&h, "7").expect("h^w1");
        let target2 = setup.exp(&h, "13").expect("h^w2");

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
