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

use crate::cl::{Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, Qfi};

pub struct PartialDecryption {
    pub party_index: usize,
    pub dec_share: Qfi,
}

impl std::fmt::Debug for PartialDecryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartialDecryption")
            .field("party_index", &self.party_index)
            .finish_non_exhaustive()
    }
}

pub fn partial_decrypt(
    setup: &ClSetup,
    ct: &ClHsmqkCiphertext,
    party_index: usize,
    sk_i_bytes: &[u8],
) -> ClResult<PartialDecryption> {
    let (c1, _c2) = setup.ct_components(ct)?;
    let dec_share = setup.exp_bytes(&c1, sk_i_bytes)?;
    Ok(PartialDecryption {
        party_index,
        dec_share,
    })
}

fn lagrange_coefficients_delta(indices: &[usize], delta: &Integer) -> Vec<(usize, Integer)> {
    let mut result = Vec::with_capacity(indices.len());
    for (k, &i_k) in indices.iter().enumerate() {
        let mut coeff = delta.clone();
        let i_k_big = Integer::from(i_k as i64);

        for (j, &i_j) in indices.iter().enumerate() {
            if j == k {
                continue;
            }
            let i_j_big = Integer::from(i_j as i64);
            let diff = Integer::from(&i_k_big - &i_j_big);
            coeff /= &diff;
            coeff *= Integer::from(-&i_j_big);
        }

        result.push((i_k, coeff));
    }

    result
}

#[allow(non_snake_case)]
pub fn final_decrypt(
    setup: &ClSetup,
    ct: &ClHsmqkCiphertext,
    n_parties: usize,
    partial_decs: &[PartialDecryption],
) -> ClResult<Vec<u8>> {
    let q_bytes = setup.q_bytes()?;
    let q = Integer::from_digits(&q_bytes, Order::Msf);

    let mut delta = Integer::from(1);
    for i in 2..=n_parties {
        delta *= i as i64;
    }

    let indices: Vec<usize> = partial_decs.iter().map(|pd| pd.party_index).collect();
    let coeffs = lagrange_coefficients_delta(&indices, &delta);

    let mut bases: Vec<&Qfi> = Vec::with_capacity(coeffs.len());
    let mut exps: Vec<(bool, Vec<u8>)> = Vec::with_capacity(coeffs.len());
    for (idx, lambda) in &coeffs {
        let pd = partial_decs
            .iter()
            .find(|p| p.party_index == *idx)
            .expect("party index mismatch");
        bases.push(&pd.dec_share);
        let should_invert = lambda.cmp0() == core::cmp::Ordering::Less;
        exps.push((should_invert, lambda.to_digits::<u8>(Order::Msf)));
    }
    let mut combined = setup.multiexp_signed_bytes(&bases, &exps)?;

    let delta2 = Integer::from(&delta * &delta);
    let delta2_bytes = delta2.to_digits::<u8>(Order::Msf);
    let (_c1, c2) = setup.ct_components(ct)?;
    let c2_delta2 = setup.exp_bytes(&c2, &delta2_bytes)?;
    combined.neg();
    let plaintext_elt = setup.compose(&c2_delta2, &combined)?;

    let m_scaled_bytes = setup.dlog_in_F_bytes(&plaintext_elt)?;
    let m_scaled = Integer::from_digits(&m_scaled_bytes, Order::Msf);

    let q_minus_2 = Integer::from(&q - 2);
    let delta2_inv = pow_mod(&delta2, &q_minus_2, &q);

    let m = mul_mod(&m_scaled, &delta2_inv, &q);
    Ok(m.to_digits::<u8>(Order::Msf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    fn shamir_share_delta(
        setup: &mut ClSetup,
        sk_bytes: &[u8],
        n: usize,
        t: usize,
    ) -> ClResult<Vec<Vec<u8>>> {
        let sk = Integer::from_digits(sk_bytes, Order::Msf);

        let mut delta = Integer::from(1);
        for i in 2..=n {
            delta *= i as u64;
        }
        let delta_sk = Integer::from(&delta * &sk);

        let mut coeffs: Vec<Integer> = vec![delta_sk];
        for _ in 1..t {
            let r = super::super::zk::sample_random(setup)?;
            let r_val = Integer::from_digits(&r, Order::Msf);
            coeffs.push(r_val);
        }

        let mut shares = Vec::with_capacity(n);
        for i in 1..=n {
            let x = Integer::from(i as i64);
            let mut val = Integer::new();
            let mut x_pow = Integer::from(1);
            for coeff in &coeffs {
                val += Integer::from(coeff * &x_pow);
                x_pow *= &x;
            }
            let abs_bytes = val.to_digits::<u8>(Order::Msf);
            assert!(
                val.cmp0() != core::cmp::Ordering::Less,
                "test assumption: share should be non-negative for small t,n"
            );
            shares.push(abs_bytes);
        }

        Ok(shares)
    }

    #[test]
    fn t_cl_part_dec_correct() {
        let mut setup = ClSetup::new_secp256k1("15001").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_bytes");

        let msg = b"\x2a";
        let ct = setup.encrypt_bytes(&pk_raw, msg).expect("encrypt");

        let pd = partial_decrypt(&setup, &ct, 1, &sk_bytes).expect("pd");

        let (_c1, c2) = setup.ct_components(&ct).expect("comp");
        let mut pd_inv = pd.dec_share.clone();
        pd_inv.neg();
        let f_m = setup.compose(&c2, &pd_inv).expect("compose");
        #[allow(non_snake_case)]
        let m_bytes = setup.dlog_in_F_bytes(&f_m).expect("dlog");
        let m_val = Integer::from_digits(&m_bytes, Order::Msf);
        assert_eq!(m_val, Integer::from(42u32));
    }

    #[test]
    fn t_cl_fin_dec_2_of_3() {
        let mut setup = ClSetup::new_secp256k1("15002").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_bytes");

        let msg = &123u32.to_be_bytes();
        let ct = setup.encrypt_bytes(&pk_raw, msg).expect("encrypt");

        let n = 3;
        let t = 2;
        let shares = shamir_share_delta(&mut setup, &sk_bytes, n, t).expect("shares");

        let pd1 = partial_decrypt(&setup, &ct, 1, &shares[0]).expect("pd1");
        let pd2 = partial_decrypt(&setup, &ct, 2, &shares[1]).expect("pd2");

        let decrypted = final_decrypt(&setup, &ct, n, &[pd1, pd2]).expect("fin_dec");
        let m_val = Integer::from_digits(&decrypted, Order::Msf);
        assert_eq!(m_val, Integer::from(123u32));
    }

    #[test]
    #[ignore = "slow: larger threshold variant"]
    fn t_cl_fin_dec_3_of_5() {
        let mut setup = ClSetup::new_secp256k1("15003").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_bytes");

        let msg = &999u32.to_be_bytes();
        let ct = setup.encrypt_bytes(&pk_raw, msg).expect("encrypt");

        let n = 5;
        let t = 3;
        let shares = shamir_share_delta(&mut setup, &sk_bytes, n, t).expect("shares");

        let pd1 = partial_decrypt(&setup, &ct, 1, &shares[0]).expect("pd1");
        let pd3 = partial_decrypt(&setup, &ct, 3, &shares[2]).expect("pd3");
        let pd5 = partial_decrypt(&setup, &ct, 5, &shares[4]).expect("pd5");

        let decrypted = final_decrypt(&setup, &ct, n, &[pd1, pd3, pd5]).expect("fin_dec");
        let m_val = Integer::from_digits(&decrypted, Order::Msf);
        assert_eq!(m_val, Integer::from(999u32));
    }
}
