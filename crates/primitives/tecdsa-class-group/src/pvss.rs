#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap
)]

use rug::{integer::Order, Integer};
use tecdsa_bigint::{mul_mod, pow_mod};

use crate::{
    cl::{Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi},
    zk::r_enc::REncProof,
};

pub struct PvssDeal {
    pub encrypted_shares: Vec<ClHsmqkCiphertext>,
    pub proofs: Vec<REncProof>,
    pub commitments: Vec<Qfi>,
}

impl std::fmt::Debug for PvssDeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PvssDeal")
            .field("num_shares", &self.encrypted_shares.len())
            .finish_non_exhaustive()
    }
}

pub fn deal(
    setup: &mut ClSetup,
    secret_decimal: &str,
    pks: &[ClHsmqkPublicKey],
    threshold: usize,
) -> ClResult<PvssDeal> {
    let n = pks.len();
    let q_bytes = setup.q_bytes()?;
    let q = Integer::from_digits(&q_bytes, Order::Msf);
    let secret = Integer::from_str_radix(secret_decimal, 10)
        .map_err(|e| crate::cl::ClError::InvalidParam(format!("bad secret: {e}")))?;

    let mut coeffs = vec![secret];
    for _ in 1..threshold {
        let r = crate::zk::sample_random_mod_q(setup)?;
        let r_val = Integer::from_digits(&r, Order::Msf);
        coeffs.push(r_val);
    }

    let mut commitments = Vec::with_capacity(threshold);
    for coeff in &coeffs {
        let c = setup.power_of_f(&coeff.to_string_radix(10))?;
        commitments.push(c);
    }

    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = Integer::from(i as u64);
        let mut val = Integer::new();
        let mut x_pow = Integer::from(1);
        for coeff in &coeffs {
            val = (&val + Integer::from(coeff * &x_pow)) % &q;
            x_pow = Integer::from(&x_pow * &x) % &q;
        }
        shares.push(val);
    }

    let mut encrypted_shares = Vec::with_capacity(n);
    let mut proofs = Vec::with_capacity(n);
    for (i, share) in shares.iter().enumerate() {
        let r_bytes = {
            let (sk, _) = setup.keygen()?;
            setup.sk_to_bytes(&sk)?
        };
        let share_dec = share.to_string_radix(10);
        let r_dec = Integer::from_digits(&r_bytes, Order::Msf).to_string_radix(10);
        let ct = setup.encrypt_with_r(&pks[i], &share_dec, &r_dec)?;
        let share_bytes = share.to_digits::<u8>(Order::Msf);
        let proof = REncProof::prove(setup, &pks[i], &ct, &share_bytes, &r_bytes)?;
        encrypted_shares.push(ct);
        proofs.push(proof);
    }

    Ok(PvssDeal {
        encrypted_shares,
        proofs,
        commitments,
    })
}

pub fn verify_deal(setup: &ClSetup, deal: &PvssDeal, pks: &[ClHsmqkPublicKey]) -> ClResult<bool> {
    if deal.encrypted_shares.len() != pks.len() || deal.proofs.len() != pks.len() {
        return Ok(false);
    }

    for (i, proof) in deal.proofs.iter().enumerate() {
        if !proof.verify(setup, &pks[i], &deal.encrypted_shares[i])? {
            return Ok(false);
        }
    }

    Ok(true)
}

pub fn reconstruct(setup: &ClSetup, shares: &[(usize, &str)]) -> ClResult<String> {
    let q_str = setup.cl().q().to_string();
    let q = Integer::from_str_radix(&q_str, 10)
        .map_err(|e| crate::cl::ClError::InvalidParam(format!("bad q: {e}")))?;

    let indices: Vec<usize> = shares.iter().map(|(i, _)| *i).collect();
    let mut secret = Integer::new();

    for (k, &(i_k, share_k)) in shares.iter().enumerate() {
        let share_val = Integer::from_str_radix(share_k, 10)
            .map_err(|e| crate::cl::ClError::InvalidParam(format!("bad share: {e}")))?;

        let mut num = Integer::from(1);
        let mut den = Integer::from(1);
        let i_k_big = Integer::from(i_k as i64);

        for (j, &idx_j) in indices.iter().enumerate() {
            if j == k {
                continue;
            }
            let i_j_big = Integer::from(idx_j as i64);
            num *= Integer::from(-&i_j_big);
            den *= Integer::from(&i_k_big - &i_j_big);
        }

        let num_mod = num.modulo(&q);
        let den_mod = den.modulo(&q);

        let q_minus_2 = Integer::from(&q - 2);
        let den_inv = pow_mod(&den_mod, &q_minus_2, &q);

        let lambda = mul_mod(&num_mod, &den_inv, &q);

        secret = (&secret + Integer::from(&share_val * &lambda)) % &q;
    }

    Ok(secret.to_string_radix(10))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn pvss_share_verify_reconstruct() {
        let mut setup = ClSetup::new_secp256k1("16001").expect("setup");

        let n = 3;
        let t = 2;
        let secret = "42";

        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            sks.push(sk);
            pks.push(pk);
        }

        let pvss_deal = deal(&mut setup, secret, &pks, t).expect("deal");

        assert!(verify_deal(&setup, &pvss_deal, &pks).expect("verify"));

        let mut decrypted_shares = Vec::new();
        for (i, ct) in pvss_deal.encrypted_shares.iter().enumerate() {
            let m = setup.decrypt(&sks[i], ct).expect("decrypt");
            decrypted_shares.push((i + 1, m));
        }

        let share_refs: Vec<(usize, &str)> = decrypted_shares[..t]
            .iter()
            .map(|(i, s)| (*i, s.as_str()))
            .collect();
        let reconstructed = reconstruct(&setup, &share_refs).expect("reconstruct");
        assert_eq!(reconstructed, secret);
    }
}
