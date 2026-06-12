#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use rug::{integer::Order, Integer};

use crate::{
    cl::{ClResult, ClSetup, Qfi},
    zk::challenge_from_qfi,
};

pub struct BatchInstance {
    pub base: Qfi,
    pub commitment: Qfi,
    pub target: Qfi,
    pub response: Vec<u8>,
    pub challenge: Vec<u8>,
}

pub fn batch_verify(setup: &ClSetup, instances: &[BatchInstance]) -> ClResult<bool> {
    if instances.is_empty() {
        return Ok(true);
    }

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

    let mut lhs = setup.identity()?;
    let mut rhs = setup.identity()?;

    for (idx, inst) in instances.iter().enumerate() {
        let idx_bytes = idx.to_string().into_bytes();
        let mut idx_extras: Vec<&[u8]> = extra_refs.clone();
        idx_extras.push(&idx_bytes);
        let w_bytes = challenge_from_qfi(setup, b"R_batch", &weight_qfi_refs, &idx_extras)?;
        let w = Integer::from_digits(&w_bytes, Order::Msf);

        let resp = Integer::from_digits(&inst.response, Order::Msf);
        let wz = Integer::from(&w * &resp).to_digits::<u8>(Order::Msf);
        let base_wz = setup.exp_bytes(&inst.base, &wz)?;
        lhs = setup.compose(&lhs, &base_wz)?;

        let commit_w = setup.exp_bytes(&inst.commitment, &w_bytes)?;
        let chal = Integer::from_digits(&inst.challenge, Order::Msf);
        let we = Integer::from(&w * &chal).to_digits::<u8>(Order::Msf);
        let target_we = setup.exp_bytes(&inst.target, &we)?;
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
        let mut setup = ClSetup::new_secp256k1("18001").expect("setup");

        let mut instances = Vec::new();
        for _ in 0..3 {
            let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_bytes");
            let pk_elt = pk_raw.elt().clone();

            let proof = RClKwlgProof::prove(&mut setup, &pk_raw, &sk_bytes).expect("prove");

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
