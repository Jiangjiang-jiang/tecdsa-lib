#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use rug::{integer::Order, Integer};

use crate::{
    cl::{ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi},
    zk::{r_sh::RShProof, sample_random_mod_q},
};

pub struct PvssShareOutput {
    pub c1: Qfi,
    pub c2s: Vec<Qfi>,
    pub proof: RShProof,
    pub secret_share_bytes: Vec<u8>,
}

pub struct PvssShareWithCoeffsOutput {
    pub c1: Qfi,
    pub c2s: Vec<Qfi>,
    pub proof: RShProof,
    pub secret_share_bytes: Vec<u8>,
    pub polynomial_coeffs_bytes: Vec<Vec<u8>>,
}

fn eval_poly_mod_q(coeffs: &[Integer], x: &Integer, q: &Integer) -> Integer {
    let mut result = Integer::new();
    for coeff in coeffs.iter().rev() {
        result = (Integer::from(&result * x) + coeff) % q;
    }
    result
}

pub fn pvss_share_distribute(
    setup: &mut ClSetup,
    party_ids: &[u16],
    pks: &[ClHsmqkPublicKey],
    reconstruct_threshold: u16,
    my_index_in_list: usize,
) -> ClResult<PvssShareOutput> {
    let n = party_ids.len();
    let q = Integer::from_digits(&setup.q_bytes()?, Order::Msf);
    let t = reconstruct_threshold as usize;

    let mut coeffs = Vec::with_capacity(t);
    for _ in 0..t {
        let r = sample_random_mod_q(setup)?;
        coeffs.push(Integer::from_digits(&r, Order::Msf));
    }

    let shares: Vec<Vec<u8>> = party_ids
        .iter()
        .map(|&id| {
            let x = Integer::from(id);
            eval_poly_mod_q(&coeffs, &x, &q).to_digits::<u8>(Order::Msf)
        })
        .collect();

    let (rho_sk, _) = setup.keygen()?;
    let rho_bytes = setup.sk_to_bytes(&rho_sk)?;

    let c1 = setup.power_of_h_bytes(&rho_bytes)?;

    let mut c2s: Vec<Qfi> = Vec::with_capacity(n);
    for (idx, share) in shares.iter().enumerate() {
        let pk_rho = setup.pk_pow_bytes(&pks[idx], &rho_bytes)?;
        let f_v = setup.power_of_f_bytes(share)?;
        let c2 = setup.compose(&pk_rho, &f_v)?;
        c2s.push(c2);
    }

    let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();
    let c2_refs: Vec<&Qfi> = c2s.iter().collect();
    let proof = RShProof::prove(
        setup,
        party_ids,
        reconstruct_threshold,
        &pk_refs,
        &c1,
        &c2_refs,
        &rho_bytes,
    )?;

    Ok(PvssShareOutput {
        c1,
        c2s,
        proof,
        secret_share_bytes: shares[my_index_in_list].clone(),
    })
}

pub fn pvss_share_distribute_with_secret(
    setup: &mut ClSetup,
    party_ids: &[u16],
    pks: &[ClHsmqkPublicKey],
    reconstruct_threshold: u16,
    my_index_in_list: usize,
    secret_bytes: &[u8],
) -> ClResult<PvssShareWithCoeffsOutput> {
    let n = party_ids.len();
    let q = Integer::from_digits(&setup.q_bytes()?, Order::Msf);
    let t = reconstruct_threshold as usize;

    let mut coeffs = Vec::with_capacity(t);
    coeffs.push(Integer::from_digits(secret_bytes, Order::Msf) % &q);
    for _ in 1..t {
        let r = sample_random_mod_q(setup)?;
        coeffs.push(Integer::from_digits(&r, Order::Msf));
    }

    let shares: Vec<Vec<u8>> = party_ids
        .iter()
        .map(|&id| {
            let x = Integer::from(id);
            eval_poly_mod_q(&coeffs, &x, &q).to_digits::<u8>(Order::Msf)
        })
        .collect();

    let (rho_sk, _) = setup.keygen()?;
    let rho_bytes = setup.sk_to_bytes(&rho_sk)?;

    let c1 = setup.power_of_h_bytes(&rho_bytes)?;

    let mut c2s: Vec<Qfi> = Vec::with_capacity(n);
    for (idx, share) in shares.iter().enumerate() {
        let pk_rho = setup.pk_pow_bytes(&pks[idx], &rho_bytes)?;
        let f_v = setup.power_of_f_bytes(share)?;
        let c2 = setup.compose(&pk_rho, &f_v)?;
        c2s.push(c2);
    }

    let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();
    let c2_refs: Vec<&Qfi> = c2s.iter().collect();
    let proof = RShProof::prove(
        setup,
        party_ids,
        reconstruct_threshold,
        &pk_refs,
        &c1,
        &c2_refs,
        &rho_bytes,
    )?;

    let polynomial_coeffs_bytes: Vec<Vec<u8>> = coeffs
        .iter()
        .map(|c| c.to_digits::<u8>(Order::Msf))
        .collect();

    Ok(PvssShareWithCoeffsOutput {
        c1,
        c2s,
        proof,
        secret_share_bytes: shares[my_index_in_list].clone(),
        polynomial_coeffs_bytes,
    })
}

pub fn pvss_share_verify(
    setup: &ClSetup,
    party_ids: &[u16],
    pks: &[ClHsmqkPublicKey],
    reconstruct_threshold: u16,
    c1: &Qfi,
    c2s: &[Qfi],
    proof: &RShProof,
) -> ClResult<bool> {
    if party_ids.len() != pks.len() || party_ids.len() != c2s.len() {
        return Ok(false);
    }
    let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();
    let c2_refs: Vec<&Qfi> = c2s.iter().collect();
    proof.verify(
        setup,
        party_ids,
        reconstruct_threshold,
        &pk_refs,
        c1,
        &c2_refs,
    )
}

pub fn pvss_share_decrypt(
    setup: &ClSetup,
    sk_bytes: &[u8],
    c1: &Qfi,
    c2_my: &Qfi,
) -> ClResult<Vec<u8>> {
    let mut m = setup.exp_bytes(c1, sk_bytes)?;
    m.neg();
    let f_share = setup.compose(c2_my, &m)?;
    setup.dlog_in_F_bytes(&f_share)
}
