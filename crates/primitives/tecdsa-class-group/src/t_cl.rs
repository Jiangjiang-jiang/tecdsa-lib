// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap
)]

//! Threshold CL: partial decryption, final decryption, and Lagrange
//! interpolation over class-group elements.
//!
//! In a `(t, n)` threshold CL scheme, each party `i` holds a share
//! `sk_i` of the secret key and a public key `pk_i = h^{sk_i}`.
//! The overall secret key is `sk = sum(lambda_i * sk_i)` over any
//! `t`-subset, where `lambda_i` are Lagrange coefficients.
//!
//! - **`PartialDecryption`**: party `i` computes `pd_i = c1^{sk_i}`.
//! - **`FinDec`**: given `t` partial decryptions, combine them via
//!   Lagrange in the exponent: `combined = product(pd_i^{lambda_i})`,
//!   then extract plaintext from `c2 * combined^{-1}`.

use rug::Integer;

use crate::cl::{Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, Qfi};

/// A partial decryption share from party `i`.
pub struct PartialDecryption {
    /// The party index (1-based).
    pub party_index: usize,
    /// The decryption share `pd_i = c1^{sk_i}`.
    pub dec_share: Qfi,
}

impl std::fmt::Debug for PartialDecryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartialDecryption")
            .field("party_index", &self.party_index)
            .finish_non_exhaustive()
    }
}

/// Computes a partial decryption for party `i`.
///
/// `sk_i` is party `i`'s secret-key share.
pub fn partial_decrypt(
    setup: &ClSetup,
    ct: &ClHsmqkCiphertext,
    party_index: usize,
    sk_i: &Integer,
) -> ClResult<PartialDecryption> {
    let (c1, _c2) = setup.ct_components(ct)?;
    let dec_share = setup.exp(&c1, sk_i)?;
    Ok(PartialDecryption {
        party_index,
        dec_share,
    })
}

/// Computes integer Lagrange coefficients scaled by `delta` for the
/// given party indices evaluated at x=0.
///
/// Each coefficient is `delta * product_{j!=k} (-i_j / (i_k - i_j))`,
/// which is guaranteed to be an integer because `delta = N!` contains
/// all required denominators as factors.
///
/// Returns `(index, signed_lambda)` pairs.
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
            // Exact division: delta = N! ensures this is always exact.
            coeff /= &diff;
            coeff *= Integer::from(-&i_j_big);
        }

        result.push((i_k, coeff));
    }

    result
}

/// Final decryption: combines `t` partial decryptions using Lagrange
/// interpolation to recover the plaintext.
///
/// Uses the "delta trick" from threshold CL-HSMqk: Lagrange
/// coefficients are multiplied by `delta = N!` to ensure integer
/// exponents.  The combined result is `c1^{sk * delta^2}`, so
/// `c2^{delta^2} * combined^{-1} = f^{m * delta^2}`, and the plaintext
/// is recovered as `dlog_in_F(.) * delta^{-2} mod q`.
///
/// - `n_parties`: total number of parties (used to compute `delta = n!`).
/// - `partial_decs`: exactly `t` partial decryptions from distinct parties.
///
/// Each partial decryption share must have been computed from a key
/// share where the Shamir polynomial has constant term `delta * sk`.
///
/// Returns the plaintext.
#[allow(non_snake_case)]
pub fn final_decrypt(
    setup: &ClSetup,
    ct: &ClHsmqkCiphertext,
    n_parties: usize,
    partial_decs: &[PartialDecryption],
) -> ClResult<Integer> {
    let q = setup.cl().q().clone();

    // delta = n_parties!
    let mut delta = Integer::from(1);
    for i in 2..=n_parties {
        delta *= i as i64;
    }

    let indices: Vec<usize> = partial_decs.iter().map(|pd| pd.party_index).collect();
    let coeffs = lagrange_coefficients_delta(&indices, &delta);

    // Compute combined = product(pd_i^{lambda_i}) via one shared-squaring
    // multi-exponentiation (lambda_i are signed Lagrange-delta coefficients).
    // Since shares come from F(j) = delta*sk + r1*j + ..., and lambda_i includes
    // a delta factor, the combined exponent is sk * delta^2.
    let mut bases: Vec<&Qfi> = Vec::with_capacity(coeffs.len());
    let mut exps: Vec<Integer> = Vec::with_capacity(coeffs.len());
    for (idx, lambda) in &coeffs {
        let pd = partial_decs
            .iter()
            .find(|p| p.party_index == *idx)
            .expect("party index mismatch");
        bases.push(&pd.dec_share);
        exps.push(lambda.clone());
    }
    let mut combined = setup.multiexp(&bases, &exps)?;

    // plaintext element = c2^{delta^2} * combined^{-1}
    //
    // combined = c1^{sk * delta^2}
    // c2^{delta^2} = (h^{sk*r} * f^m)^{delta^2} = h^{sk*r*delta^2} * f^{m*delta^2}
    // result = f^{m * delta^2}
    let delta2 = Integer::from(&delta * &delta);
    let (_c1, c2) = setup.ct_components(ct)?;
    let c2_delta2 = setup.exp(&c2, &delta2)?;
    combined.neg();
    let plaintext_elt = setup.compose(&c2_delta2, &combined)?;

    // Extract m * delta^2 mod q, then divide by delta^2 mod q.
    let m_scaled = setup.dlog_in_F(&plaintext_elt)?;

    // delta2_inv = delta^{-2} mod q  (via Fermat's little theorem)
    let q_minus_2 = Integer::from(&q - 2);
    let delta2_inv = delta2
        .pow_mod(&q_minus_2, &q)
        .expect("q - 2 is non-negative");

    let m = (m_scaled * delta2_inv).modulo(&q);
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    /// Generates threshold key shares using the delta-scaled Shamir
    /// scheme matching the BICYCL threshold CL protocol.
    ///
    /// The polynomial is `F(X) = delta * sk + r1 * X + ... + r_{t-1} * X^{t-1}`
    /// where `delta = n!` (n factorial).  The constant term is scaled
    /// by delta so that integer Lagrange interpolation (also scaled
    /// by delta) recovers `sk * delta^2` exactly.
    ///
    /// Shares are computed over the integers (unbounded), NOT mod q.
    ///
    /// Returns shares as signed integers (for `exp`, callers pass them
    /// directly since `Integer` carries its own sign).
    fn shamir_share_delta(
        setup: &mut ClSetup,
        sk: &Integer,
        n: usize,
        t: usize,
    ) -> ClResult<Vec<Integer>> {
        // delta = n!
        let mut delta = Integer::from(1);
        for i in 2..=n {
            delta *= i as u64;
        }
        let delta_sk = delta * sk;

        // Generate t-1 random coefficients (arbitrary precision).
        // Use secretkey_bound as the range for random coefficients.
        let mut coeffs: Vec<Integer> = vec![delta_sk];
        for _ in 1..t {
            coeffs.push(super::super::zk::sample_random(setup)?);
        }

        // Evaluate polynomial at i = 1, 2, ..., n (over the integers).
        let mut shares = Vec::with_capacity(n);
        for i in 1..=n {
            let x = Integer::from(i as i64);
            let mut val = Integer::new();
            let mut x_pow = Integer::from(1);
            for coeff in &coeffs {
                val += Integer::from(coeff * &x_pow);
                x_pow *= &x;
            }
            // Polynomial evaluations are always non-negative for small
            // (t,n) and large delta*sk in these tests; assert to catch
            // any unexpected cases.
            assert!(
                val.cmp0() != core::cmp::Ordering::Less,
                "test assumption: share should be non-negative for small t,n"
            );
            shares.push(val);
        }

        Ok(shares)
    }

    #[test]
    fn t_cl_part_dec_correct() {
        let mut setup = ClSetup::new_secp256k1(15001u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let msg = Integer::from(42u32);
        let ct = setup.encrypt(&pk_raw, &msg).expect("encrypt");

        // Single party (1-of-1) partial decryption = full decryption.
        let pd = partial_decrypt(&setup, &ct, 1, &sk).expect("pd");

        // Verify: pd = c1^sk, so c2 * pd^{-1} should give f^m.
        let (_c1, c2) = setup.ct_components(&ct).expect("comp");
        let mut pd_inv = pd.dec_share.clone();
        pd_inv.neg();
        let f_m = setup.compose(&c2, &pd_inv).expect("compose");
        let m_val = setup.dlog_in_F(&f_m).expect("dlog");
        assert_eq!(m_val, Integer::from(42u32));
    }

    #[test]
    fn t_cl_fin_dec_2_of_3() {
        let mut setup = ClSetup::new_secp256k1(15002u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let msg = Integer::from(123u32);
        let ct = setup.encrypt(&pk_raw, &msg).expect("encrypt");

        let n = 3;
        let t = 2;
        let shares = shamir_share_delta(&mut setup, &sk, n, t).expect("shares");

        // Partial decryptions from parties 1 and 2.
        let pd1 = partial_decrypt(&setup, &ct, 1, &shares[0]).expect("pd1");
        let pd2 = partial_decrypt(&setup, &ct, 2, &shares[1]).expect("pd2");

        let decrypted = final_decrypt(&setup, &ct, n, &[pd1, pd2]).expect("fin_dec");
        assert_eq!(decrypted, Integer::from(123u32));
    }

    #[test]
    #[ignore = "slow: larger threshold variant"]
    fn t_cl_fin_dec_3_of_5() {
        let mut setup = ClSetup::new_secp256k1(15003u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let msg = Integer::from(999u32);
        let ct = setup.encrypt(&pk_raw, &msg).expect("encrypt");

        let n = 5;
        let t = 3;
        let shares = shamir_share_delta(&mut setup, &sk, n, t).expect("shares");

        // Partial decryptions from parties 1, 3, 5.
        let pd1 = partial_decrypt(&setup, &ct, 1, &shares[0]).expect("pd1");
        let pd3 = partial_decrypt(&setup, &ct, 3, &shares[2]).expect("pd3");
        let pd5 = partial_decrypt(&setup, &ct, 5, &shares[4]).expect("pd5");

        let decrypted = final_decrypt(&setup, &ct, n, &[pd1, pd3, pd5]).expect("fin_dec");
        assert_eq!(decrypted, Integer::from(999u32));
    }
}
