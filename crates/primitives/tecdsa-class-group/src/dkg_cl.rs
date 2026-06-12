#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap
)]

use rug::{Complete, Integer};

use crate::{
    cl::{
        Ciphertext as ClHsmqkCiphertext, ClError, ClResult, ClSetup, Mpz,
        PublicKey as ClHsmqkPublicKey, Qfi,
    },
    zk::{r_blnt::RBlntProof, r_gdec_cl::RGdecClProof, sample_random},
};

fn decompose_q_ary(value: &Mpz, q: &Mpz) -> Vec<Mpz> {
    let mut chunks = Vec::new();
    let mut remaining = value.inner().clone();
    while remaining > Integer::ZERO {
        let chunk;
        (remaining, chunk) = remaining.div_rem_ref(q.inner()).complete();
        chunks.push(Mpz::from_inner(chunk));
    }
    if chunks.is_empty() {
        chunks.push(Mpz::from(0));
    }
    chunks
}

#[cfg(test)]
fn recompose_q_ary(chunks: &[Mpz], q: &Mpz) -> Mpz {
    let mut result = Mpz::from(0);
    let mut q_pow = Mpz::from(1);
    for chunk in chunks {
        result = result + &q_pow * chunk;
        q_pow = q_pow * q;
    }
    result
}

fn num_chunks_for_bound(bound: &Mpz, q: &Mpz) -> usize {
    if bound.is_zero() {
        return 1;
    }
    let mut count = 0usize;
    let mut remaining = bound.inner().clone();
    while remaining > Integer::ZERO {
        remaining /= q.inner();
        count += 1;
    }
    count.max(1)
}

fn factorial(n: usize) -> Mpz {
    let mut delta = Mpz::from(1);
    for i in 2..=n {
        delta = delta * Mpz::from(i as u64);
    }
    delta
}

fn share_magnitude_bound(sk_bound: &Mpz, n: usize, t: usize) -> Mpz {
    let mut poly = factorial(n);
    if n >= 2 && t >= 2 {
        let n_mpz = Mpz::from(n as u64);
        let numer = &n_mpz.pow_u(t as u32) - &n_mpz;
        let denom = &n_mpz - &Mpz::from(1u64);
        poly = &poly + &numer.divexact(&denom);
    }
    &poly * sk_bound
}

fn shamir_share_delta_signed(
    setup: &mut ClSetup,
    s_bytes: &[u8],
    n: usize,
    t: usize,
) -> ClResult<Vec<(Vec<u8>, bool)>> {
    let s = Mpz::from_bytes_be(s_bytes);
    let delta = factorial(n);
    let delta_s = &delta * &s;

    let mut coeffs = vec![delta_s];
    for _ in 1..t {
        let r = sample_random(setup)?;
        let r_val = Mpz::from_bytes_be(&r);
        coeffs.push(r_val);
    }

    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = Mpz::from(i as i64);
        let mut val = Mpz::from(0);
        let mut x_pow = Mpz::from(1);
        for coeff in &coeffs {
            val = val + coeff * &x_pow;
            x_pow = x_pow * &x;
        }
        let is_negative = val.inner().is_negative();
        let abs_bytes = val.abs().to_bytes_be();
        shares.push((abs_bytes, is_negative));
    }

    Ok(shares)
}

pub struct DkgClGenPerRecipient {
    pub pc: Qfi,
    pub chunk_cts: Vec<(Qfi, Qfi)>,
    pub agg_ct: (Qfi, Qfi),
    pub proof: RBlntProof,
}

pub struct DkgClGenOutput {
    pub per_recipient: Vec<DkgClGenPerRecipient>,
    pub my_secret: Vec<u8>,
    pub my_secret_prime: Vec<u8>,
    pub shares: Vec<(Vec<u8>, bool)>,
    pub shares_prime: Vec<(Vec<u8>, bool)>,
}

pub fn dkg_cl_gen(
    setup: &mut ClSetup,
    all_pks: &[ClHsmqkPublicKey],
    n: usize,
    threshold: usize,
    my_index: usize,
) -> ClResult<DkgClGenOutput> {
    assert_eq!(all_pks.len(), n);
    assert!(my_index < n);
    assert!(threshold > 0 && threshold <= n);

    let q_bytes = setup.q_bytes()?;
    let q = Mpz::from_bytes_be(&q_bytes);
    let sk_bound_bytes = setup.secretkey_bound_bytes()?;
    let sk_bound = Mpz::from_bytes_be(&sk_bound_bytes);
    let share_bound = share_magnitude_bound(&sk_bound, n, threshold);
    let num_chunks = num_chunks_for_bound(&share_bound, &q);

    let chi_i_bytes = sample_random(setup)?;
    let chi_prime_i_bytes = sample_random(setup)?;

    let shares_chi = shamir_share_delta_signed(setup, &chi_i_bytes, n, threshold)?;
    let shares_chi_prime = shamir_share_delta_signed(setup, &chi_prime_i_bytes, n, threshold)?;

    let mut per_recipient = Vec::with_capacity(n);
    for j in 0..n {
        let (share_j_bytes, share_j_neg) = &shares_chi[j];
        let (share_prime_j_bytes, _share_prime_j_neg) = &shares_chi_prime[j];

        let share_j_uint = Mpz::from_bytes_be(share_j_bytes);
        let raw_chunks = decompose_q_ary(&share_j_uint, &q);

        let mut chi_chunks = raw_chunks;
        if chi_chunks.len() > num_chunks {
            return Err(ClError::InvalidParam(format!(
                "DKG-CL share needs {} q-ary chunks but only {num_chunks} were \
                 allocated (n={n}, t={threshold}); refusing to truncate the share",
                chi_chunks.len()
            )));
        }
        chi_chunks.resize(num_chunks, Mpz::from(0));

        let chi_chunk_bytes: Vec<Vec<u8>> = chi_chunks
            .iter()
            .map(|c| {
                if c.is_zero() {
                    vec![0u8]
                } else {
                    c.to_bytes_be()
                }
            })
            .collect();

        let h_chi_prime = setup.power_of_h_bytes(share_prime_j_bytes)?;
        let h_q_product = compute_h_q_pow_product(setup, &q, &chi_chunk_bytes)?;
        let pc = setup.compose(&h_chi_prime, &h_q_product)?;

        let mut chunk_cts: Vec<(Qfi, Qfi)> = Vec::with_capacity(num_chunks);
        let mut r_chunk_bytes: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);

        for chunk_b in &chi_chunk_bytes {
            let r_l = sample_random(setup)?;

            let c_l_0 = setup.power_of_h_bytes(&r_l)?;

            let f_chi_l = setup.power_of_f_bytes(chunk_b)?;
            let pk_r_l = setup.pk_pow_bytes(&all_pks[j], &r_l)?;
            let c_l_1 = setup.compose(&f_chi_l, &pk_r_l)?;

            chunk_cts.push((c_l_0, c_l_1));
            r_chunk_bytes.push(r_l);
        }

        let r_agg = sample_random(setup)?;
        let h_q_pow_product = compute_h_q_pow_product(setup, &q, &chi_chunk_bytes)?;

        let h_r_agg = setup.power_of_h_bytes(&r_agg)?;
        let c_0 = setup.compose(&h_r_agg, &h_q_pow_product)?;

        let pk_r_agg = setup.pk_pow_bytes(&all_pks[j], &r_agg)?;
        let c_1 = setup.compose(&pk_r_agg, &h_q_pow_product)?;

        let agg_ct = (c_0, c_1);

        let proof = RBlntProof::prove(
            setup,
            &all_pks[j],
            &pc,
            &chunk_cts,
            &agg_ct,
            &chi_chunk_bytes,
            share_prime_j_bytes,
            &r_chunk_bytes,
            &r_agg,
        )?;

        per_recipient.push(DkgClGenPerRecipient {
            pc,
            chunk_cts,
            agg_ct,
            proof,
        });

        let _ = share_j_neg;
    }

    Ok(DkgClGenOutput {
        per_recipient,
        my_secret: chi_i_bytes,
        my_secret_prime: chi_prime_i_bytes,
        shares: shares_chi,
        shares_prime: shares_chi_prime,
    })
}

pub fn dkg_cl_gen_with_secret(
    setup: &mut ClSetup,
    all_pks: &[ClHsmqkPublicKey],
    n: usize,
    threshold: usize,
    my_index: usize,
    secret: &[u8],
) -> ClResult<DkgClGenOutput> {
    assert_eq!(all_pks.len(), n);
    assert!(my_index < n);
    assert!(threshold > 0 && threshold <= n);

    let q_bytes = setup.q_bytes()?;
    let q = Mpz::from_bytes_be(&q_bytes);
    let sk_bound_bytes = setup.secretkey_bound_bytes()?;
    let sk_bound = Mpz::from_bytes_be(&sk_bound_bytes);
    let share_bound = share_magnitude_bound(&sk_bound, n, threshold);
    let num_chunks = num_chunks_for_bound(&share_bound, &q);

    let chi_i_bytes = secret.to_vec();
    let chi_prime_i_bytes = sample_random(setup)?;

    let shares_chi = shamir_share_delta_signed(setup, &chi_i_bytes, n, threshold)?;
    let shares_chi_prime = shamir_share_delta_signed(setup, &chi_prime_i_bytes, n, threshold)?;

    let mut per_recipient = Vec::with_capacity(n);
    for j in 0..n {
        let (share_j_bytes, share_j_neg) = &shares_chi[j];
        let (share_prime_j_bytes, _share_prime_j_neg) = &shares_chi_prime[j];

        let share_j_uint = Mpz::from_bytes_be(share_j_bytes);
        let raw_chunks = decompose_q_ary(&share_j_uint, &q);

        let mut chi_chunks = raw_chunks;
        if chi_chunks.len() > num_chunks {
            return Err(ClError::InvalidParam(format!(
                "DKG-CL share needs {} q-ary chunks but only {num_chunks} were \
                 allocated (n={n}, t={threshold}); refusing to truncate the share",
                chi_chunks.len()
            )));
        }
        chi_chunks.resize(num_chunks, Mpz::from(0));

        let chi_chunk_bytes: Vec<Vec<u8>> = chi_chunks
            .iter()
            .map(|c| {
                if c.is_zero() {
                    vec![0u8]
                } else {
                    c.to_bytes_be()
                }
            })
            .collect();

        let h_chi_prime = setup.power_of_h_bytes(share_prime_j_bytes)?;
        let h_q_product = compute_h_q_pow_product(setup, &q, &chi_chunk_bytes)?;
        let pc = setup.compose(&h_chi_prime, &h_q_product)?;

        let mut chunk_cts: Vec<(Qfi, Qfi)> = Vec::with_capacity(num_chunks);
        let mut r_chunk_bytes: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);

        for chunk_b in &chi_chunk_bytes {
            let r_l = sample_random(setup)?;
            let c_l_0 = setup.power_of_h_bytes(&r_l)?;
            let f_chi_l = setup.power_of_f_bytes(chunk_b)?;
            let pk_r_l = setup.pk_pow_bytes(&all_pks[j], &r_l)?;
            let c_l_1 = setup.compose(&f_chi_l, &pk_r_l)?;
            chunk_cts.push((c_l_0, c_l_1));
            r_chunk_bytes.push(r_l);
        }

        let r_agg = sample_random(setup)?;
        let h_q_pow_product = compute_h_q_pow_product(setup, &q, &chi_chunk_bytes)?;
        let h_r_agg = setup.power_of_h_bytes(&r_agg)?;
        let c_0 = setup.compose(&h_r_agg, &h_q_pow_product)?;
        let pk_r_agg = setup.pk_pow_bytes(&all_pks[j], &r_agg)?;
        let c_1 = setup.compose(&pk_r_agg, &h_q_pow_product)?;
        let agg_ct = (c_0, c_1);

        let proof = RBlntProof::prove(
            setup,
            &all_pks[j],
            &pc,
            &chunk_cts,
            &agg_ct,
            &chi_chunk_bytes,
            share_prime_j_bytes,
            &r_chunk_bytes,
            &r_agg,
        )?;

        per_recipient.push(DkgClGenPerRecipient {
            pc,
            chunk_cts,
            agg_ct,
            proof,
        });

        let _ = share_j_neg;
    }

    Ok(DkgClGenOutput {
        per_recipient,
        my_secret: chi_i_bytes,
        my_secret_prime: chi_prime_i_bytes,
        shares: shares_chi,
        shares_prime: shares_chi_prime,
    })
}

pub fn dkg_cl_gen_verify(
    setup: &ClSetup,
    dealer_output: &DkgClGenPerRecipient,
    _dealer_pk: &ClHsmqkPublicKey,
    my_pk: &ClHsmqkPublicKey,
) -> ClResult<bool> {
    dealer_output.proof.verify(
        setup,
        my_pk,
        &dealer_output.pc,
        &dealer_output.chunk_cts,
        &dealer_output.agg_ct,
    )
}

pub struct DkgClRevealOutput {
    pub combined_share: Vec<u8>,
    pub pk_share: Qfi,
    pub proof: RGdecClProof,
    pub combined_ct: ClHsmqkCiphertext,
}

pub fn dkg_cl_reveal(
    setup: &mut ClSetup,
    my_sk_bytes: &[u8],
    my_pk: &ClHsmqkPublicKey,
    received_chunks: &[Vec<(Qfi, Qfi)>],
    n: usize,
) -> ClResult<DkgClRevealOutput> {
    assert_eq!(received_chunks.len(), n);

    let q_bytes = setup.q_bytes()?;
    let q = Mpz::from_bytes_be(&q_bytes);

    let sk = setup.sk_from_bytes(my_sk_bytes)?;

    let mut combined_share = Mpz::from(0);

    let mut combined_c1_bases = vec![];
    let mut combined_c2_bases = vec![];
    let mut exps = vec![];

    for dealer_chunks in received_chunks {
        let mut dealer_share = Mpz::from(0);
        let mut q_pow = Mpz::from(1);

        for (c_l_0, c_l_1) in dealer_chunks {
            let ct_l = setup.ct_from_components(c_l_0, c_l_1)?;
            let m_l_bytes = setup.decrypt_bytes(&sk, &ct_l)?;
            let m_l = Mpz::from_bytes_be(&m_l_bytes);
            let q_pow_bytes = q_pow.to_bytes_be();

            dealer_share = dealer_share + &q_pow * &m_l;
            q_pow = q_pow * &q;

            combined_c1_bases.push(c_l_0);
            combined_c2_bases.push(c_l_1);
            exps.push(q_pow_bytes);
        }

        combined_share = combined_share + dealer_share;
    }
    let combined_c1 = setup.multiexp_bytes(&combined_c1_bases, &exps)?;
    let combined_c2 = setup.multiexp_bytes(&combined_c2_bases, &exps)?;

    let combined_share_bytes = if combined_share.is_zero() {
        vec![0u8]
    } else {
        combined_share.to_bytes_be()
    };

    let pk_share = setup.power_of_h_bytes(&combined_share_bytes)?;

    let combined_ct = setup.ct_from_components(&combined_c1, &combined_c2)?;

    let dec_result = setup.power_of_f_bytes(&combined_share_bytes)?;

    let proof = RGdecClProof::prove(setup, my_pk, &combined_ct, &dec_result, my_sk_bytes)?;

    Ok(DkgClRevealOutput {
        combined_share: combined_share_bytes,
        pk_share,
        proof,
        combined_ct,
    })
}

pub fn dkg_cl_reveal_verify(
    setup: &ClSetup,
    reveal: &DkgClRevealOutput,
    party_pk: &ClHsmqkPublicKey,
) -> ClResult<bool> {
    let dec_result = setup.power_of_f_bytes(&reveal.combined_share)?;

    reveal
        .proof
        .verify(setup, party_pk, &reveal.combined_ct, &dec_result)
}

pub fn dkg_cl_aggregate(
    setup: &ClSetup,
    public_shares: &[Qfi],
    party_indices: &[usize],
    n_total: usize,
) -> ClResult<Qfi> {
    assert_eq!(public_shares.len(), party_indices.len());

    let delta = factorial(n_total);
    let coeffs = lagrange_coefficients_delta(party_indices, &delta);

    let mut bases: Vec<&Qfi> = Vec::with_capacity(coeffs.len());
    let mut exps: Vec<(bool, Vec<u8>)> = Vec::with_capacity(coeffs.len());
    for (idx, lambda) in &coeffs {
        let share_pos = party_indices
            .iter()
            .position(|&i| i == *idx)
            .expect("index mismatch");
        bases.push(&public_shares[share_pos]);
        exps.push((lambda.inner().is_negative(), lambda.abs().to_bytes_be()));
    }
    let aggregate = setup.multiexp_signed_bytes(&bases, &exps)?;

    Ok(aggregate)
}

fn lagrange_coefficients_delta(indices: &[usize], delta: &Mpz) -> Vec<(usize, Mpz)> {
    let mut result = Vec::with_capacity(indices.len());
    for (k, &i_k) in indices.iter().enumerate() {
        let mut coeff = delta.clone();
        let i_k_big = Mpz::from(i_k as i64);

        for (j, &i_j) in indices.iter().enumerate() {
            if j == k {
                continue;
            }
            let i_j_big = Mpz::from(i_j as i64);
            let diff = &i_k_big - &i_j_big;
            coeff = Mpz::from_inner((coeff.inner() / diff.inner()).complete());
            coeff = coeff * -&i_j_big;
        }

        result.push((i_k, coeff));
    }
    result
}

fn compute_h_q_pow_product(setup: &ClSetup, q: &Mpz, exponents: &[Vec<u8>]) -> ClResult<Qfi> {
    let mut product = setup.identity()?;
    let mut q_pow_l = Mpz::from(1);

    for x_l in exponents {
        let x = Mpz::from_bytes_be(x_l);
        let exp = &q_pow_l * &x;

        if !exp.is_zero() {
            let exp_bytes = exp.to_bytes_be();
            let h_exp = setup.power_of_h_bytes(&exp_bytes)?;
            product = setup.compose(&product, &h_exp)?;
        }

        q_pow_l = q_pow_l * q;
    }

    Ok(product)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::Mpz;

    #[test]
    fn dkg_cl_3_of_3_full_round() {
        let n = 3;
        let t = 2;

        let mut setup = ClSetup::new_secp256k1("50001").expect("setup");

        let mut sks = Vec::new();
        let mut pks = Vec::new();
        let mut sk_bytes_vec = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_bytes(&sk).expect("sk_bytes");
            sks.push(sk);
            pks.push(pk);
            sk_bytes_vec.push(sk_bytes);
        }

        let mut gen_outputs = Vec::new();
        for i in 0..n {
            let output = dkg_cl_gen(&mut setup, &pks, n, t, i).expect("gen");
            gen_outputs.push(output);
        }

        for dealer in 0..n {
            for recipient in 0..n {
                let ok = dkg_cl_gen_verify(
                    &setup,
                    &gen_outputs[dealer].per_recipient[recipient],
                    &pks[dealer],
                    &pks[recipient],
                )
                .expect("gen_verify");
                assert!(
                    ok,
                    "GenVf failed for dealer={dealer}, recipient={recipient}"
                );
            }
        }

        let mut reveal_outputs = Vec::new();
        for i in 0..n {
            let received: Vec<Vec<(Qfi, Qfi)>> = (0..n)
                .map(|dealer| gen_outputs[dealer].per_recipient[i].chunk_cts.clone())
                .collect();

            let reveal =
                dkg_cl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &received, n).expect("reveal");
            reveal_outputs.push(reveal);
        }

        for i in 0..n {
            let ok =
                dkg_cl_reveal_verify(&setup, &reveal_outputs[i], &pks[i]).expect("reveal_verify");
            assert!(ok, "RevealVf failed for party={i}");
        }

        let public_shares: Vec<Qfi> = reveal_outputs.iter().map(|r| r.pk_share.clone()).collect();
        let party_indices: Vec<usize> = (1..=n).collect();

        let agg = dkg_cl_aggregate(&setup, &public_shares, &party_indices, n).expect("aggregate");

        let identity = setup.identity().expect("identity");
        assert_ne!(agg, identity, "aggregate should not be the identity");
    }

    #[test]
    fn dkg_cl_128bit_multi_chunk_full_round() {
        let n = 3;
        let t = 2;

        let mut setup = ClSetup::new_secp256k1_128bit("42042").expect("setup");

        let mut pks = Vec::new();
        let mut sk_bytes_vec = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_bytes(&sk).expect("sk_bytes");
            pks.push(pk);
            sk_bytes_vec.push(sk_bytes);
        }

        let mut gen_outputs = Vec::new();
        for i in 0..n {
            gen_outputs.push(dkg_cl_gen(&mut setup, &pks, n, t, i).expect("gen"));
        }

        let mut reveal_outputs = Vec::new();
        for i in 0..n {
            let received: Vec<Vec<(Qfi, Qfi)>> = (0..n)
                .map(|dealer| gen_outputs[dealer].per_recipient[i].chunk_cts.clone())
                .collect();
            reveal_outputs.push(
                dkg_cl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &received, n).expect("reveal"),
            );
        }

        for i in 0..n {
            assert!(
                dkg_cl_reveal_verify(&setup, &reveal_outputs[i], &pks[i]).expect("verify"),
                "RevealVf failed for party={i}"
            );
        }
    }

    #[test]
    fn q_ary_roundtrip() {
        let q = Mpz::from(997u32);

        for val in [0u64, 1, 42, 996, 997, 998, 1000000, u64::MAX] {
            let v = Mpz::from(val);
            let chunks = decompose_q_ary(&v, &q);
            let recomposed = recompose_q_ary(&chunks, &q);
            assert_eq!(v, recomposed, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn q_ary_chunks_in_range() {
        let q = Mpz::from(256u32);
        let v = Mpz::from(123456789u64);
        let chunks = decompose_q_ary(&v, &q);
        for chunk in &chunks {
            assert!(chunk < &q, "chunk {chunk} >= q");
        }
    }

    #[test]
    fn chunk_count_correct() {
        let q = Mpz::from(10u32);
        assert_eq!(num_chunks_for_bound(&Mpz::from(0), &q), 1);
        assert_eq!(num_chunks_for_bound(&Mpz::from(9u32), &q), 1);
        assert_eq!(num_chunks_for_bound(&Mpz::from(10u32), &q), 2);
        assert_eq!(num_chunks_for_bound(&Mpz::from(99u32), &q), 2);
        assert_eq!(num_chunks_for_bound(&Mpz::from(100u32), &q), 3);
    }

    #[test]
    fn share_chunks_not_truncated_for_large_n() {
        let setup = ClSetup::new_secp256k1("424242").expect("setup");
        let q = Mpz::from_bytes_be(&setup.q_bytes().expect("q"));
        let b = Mpz::from_bytes_be(&setup.secretkey_bound_bytes().expect("B"));

        let poly = |n: usize, t: usize| -> Mpz {
            let n_mpz = Mpz::from(n as u64);
            let mut acc = factorial(n);
            let mut n_pow = Mpz::from(1u64);
            for _ in 1..t {
                n_pow = &n_pow * &n_mpz;
                acc = &acc + &n_pow;
            }
            acc
        };
        let max_coeff = &b - &Mpz::from(1u64);

        for &(n, t) in &[(2usize, 2usize), (5, 5), (10, 10), (20, 20)] {
            let new_chunks = num_chunks_for_bound(&share_magnitude_bound(&b, n, t), &q);
            let worst_share = &max_coeff * &poly(n, t);
            let needed = decompose_q_ary(&worst_share, &q).len();
            assert!(
                needed <= new_chunks,
                "n={n},t={t}: worst-case share needs {needed} chunks but \
                 share-magnitude bound only allots {new_chunks}",
            );
        }

        let old_chunks = num_chunks_for_bound(&b, &q);
        let worst_share_20 = &max_coeff * &poly(20, 20);
        assert!(
            decompose_q_ary(&worst_share_20, &q).len() > old_chunks,
            "n=t=20 share should overflow the old secret-sized chunk count",
        );
    }

    #[test]
    fn dkg_cl_2_of_2() {
        let n = 2;
        let t = 2;

        let mut setup = ClSetup::new_secp256k1("50010").expect("setup");

        let mut pks = Vec::new();
        let mut sk_bytes_vec = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_bytes(&sk).expect("sk_bytes");
            pks.push(pk);
            sk_bytes_vec.push(sk_bytes);
        }

        let mut gen_outputs = Vec::new();
        for i in 0..n {
            gen_outputs.push(dkg_cl_gen(&mut setup, &pks, n, t, i).expect("gen"));
        }

        for d in 0..n {
            for r in 0..n {
                assert!(
                    dkg_cl_gen_verify(&setup, &gen_outputs[d].per_recipient[r], &pks[d], &pks[r])
                        .expect("verify"),
                    "GenVf failed d={d} r={r}"
                );
            }
        }

        let mut reveals = Vec::new();
        for i in 0..n {
            let received: Vec<Vec<(Qfi, Qfi)>> = (0..n)
                .map(|d| gen_outputs[d].per_recipient[i].chunk_cts.clone())
                .collect();
            reveals.push(
                dkg_cl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &received, n).expect("reveal"),
            );
        }

        for i in 0..n {
            assert!(
                dkg_cl_reveal_verify(&setup, &reveals[i], &pks[i]).expect("verify"),
                "RevealVf failed i={i}"
            );
        }

        let public_shares: Vec<Qfi> = reveals.iter().map(|r| r.pk_share.clone()).collect();
        let indices: Vec<usize> = (1..=n).collect();
        let agg = dkg_cl_aggregate(&setup, &public_shares, &indices, n).expect("aggregate");
        let id = setup.identity().expect("id");
        assert_ne!(agg, id);
    }
}
