// SPDX-License-Identifier: GPL-3.0-or-later
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

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::{ClHsmqkCiphertext, Qfi};

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
/// `sk_i_bytes` is party `i`'s secret-key share as big-endian bytes.
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

/// Computes integer Lagrange coefficients scaled by `delta` for the
/// given party indices evaluated at x=0.
///
/// Each coefficient is `delta * product_{j!=k} (-i_j / (i_k - i_j))`,
/// which is guaranteed to be an integer because `delta = N!` contains
/// all required denominators as factors.
///
/// Returns `(index, signed_lambda)` pairs.
fn lagrange_coefficients_delta(
    indices: &[usize],
    delta: &num_bigint::BigInt,
) -> Vec<(usize, num_bigint::BigInt)> {
    use num_bigint::BigInt;

    let mut result = Vec::with_capacity(indices.len());
    for (k, &i_k) in indices.iter().enumerate() {
        let mut coeff = delta.clone();
        let i_k_big = BigInt::from(i_k as i64);

        for (j, &i_j) in indices.iter().enumerate() {
            if j == k {
                continue;
            }
            let i_j_big = BigInt::from(i_j as i64);
            let diff = &i_k_big - &i_j_big;
            // Exact division: delta = N! ensures this is always exact.
            coeff = &coeff / &diff;
            coeff *= -&i_j_big;
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
/// Returns the plaintext as big-endian bytes.
#[allow(non_snake_case)]
pub fn final_decrypt(
    setup: &ClSetup,
    ct: &ClHsmqkCiphertext,
    n_parties: usize,
    partial_decs: &[PartialDecryption],
) -> ClResult<Vec<u8>> {
    use num_bigint::BigInt;
    use num_traits::One as _;

    let q_bytes = setup.q_bytes()?;
    let q = num_bigint::BigUint::from_bytes_be(&q_bytes);

    // delta = n_parties!
    let mut delta = BigInt::one();
    for i in 2..=n_parties {
        delta *= BigInt::from(i as i64);
    }

    let indices: Vec<usize> = partial_decs.iter().map(|pd| pd.party_index).collect();
    let coeffs = lagrange_coefficients_delta(&indices, &delta);

    // Compute combined = product(pd_i^{lambda_i}).
    // Since shares come from F(j) = delta*sk + r1*j + ..., and
    // lambda_i includes a delta factor, the combined exponent
    // is sk * delta^2.
    let id = setup.identity()?;
    let mut combined = id;

    for (idx, lambda) in &coeffs {
        let pd = partial_decs
            .iter()
            .find(|p| p.party_index == *idx)
            .expect("party index mismatch");

        let (exp_bytes, should_invert) = if lambda.sign() == num_bigint::Sign::Minus {
            let abs_val = (-lambda).to_biguint().expect("abs value");
            (abs_val.to_bytes_be(), true)
        } else {
            let abs_val = lambda.to_biguint().expect("abs value");
            (abs_val.to_bytes_be(), false)
        };

        let mut pd_lambda = setup.exp_bytes(&pd.dec_share, &exp_bytes)?;
        if should_invert {
            pd_lambda = pd_lambda.neg(setup.ctx())?;
        }
        combined = setup.compose(&combined, &pd_lambda)?;
    }

    // plaintext element = c2^{delta^2} * combined^{-1}
    //
    // combined = c1^{sk * delta^2}
    // c2^{delta^2} = (h^{sk*r} * f^m)^{delta^2} = h^{sk*r*delta^2} * f^{m*delta^2}
    // result = f^{m * delta^2}
    let delta2 = (&delta * &delta)
        .to_biguint()
        .expect("delta^2 non-negative");
    let delta2_bytes = delta2.to_bytes_be();
    let (_c1, c2) = setup.ct_components(ct)?;
    let c2_delta2 = setup.exp_bytes(&c2, &delta2_bytes)?;
    let combined_inv = combined.neg(setup.ctx())?;
    let plaintext_elt = setup.compose(&c2_delta2, &combined_inv)?;

    // Extract m * delta^2 mod q, then divide by delta^2 mod q.
    let m_scaled_bytes = setup.dlog_in_F_bytes(&plaintext_elt)?;
    let m_scaled = num_bigint::BigUint::from_bytes_be(&m_scaled_bytes);

    // delta2_inv = delta^{-2} mod q  (via Fermat's little theorem)
    let q_minus_2 = &q - num_bigint::BigUint::from(2u32);
    let delta2_inv = delta2.modpow(&q_minus_2, &q);

    let m = (&m_scaled * &delta2_inv) % &q;
    Ok(m.to_bytes_be())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::ClSetup;
    use num_bigint::BigUint;

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
    /// Returns shares as signed big-endian byte strings (for exp_bytes,
    /// callers must handle sign separately).
    fn shamir_share_delta(
        setup: &mut ClSetup,
        sk_bytes: &[u8],
        n: usize,
        t: usize,
    ) -> ClResult<Vec<Vec<u8>>> {
        let sk = BigUint::from_bytes_be(sk_bytes);

        // delta = n!
        let mut delta = BigUint::from(1u32);
        for i in 2..=n {
            delta *= BigUint::from(i as u64);
        }
        let delta_sk = &delta * &sk;

        // Generate t-1 random coefficients (arbitrary precision).
        // Use secretkey_bound as the range for random coefficients.
        let mut coeffs: Vec<num_bigint::BigInt> = vec![num_bigint::BigInt::from(delta_sk)];
        for _ in 1..t {
            let r = super::super::zk::sample_random(setup)?;
            let r_val = num_bigint::BigInt::from(num_bigint::BigUint::from_bytes_be(&r));
            coeffs.push(r_val);
        }

        // Evaluate polynomial at i = 1, 2, ..., n (over the integers).
        let mut shares = Vec::with_capacity(n);
        for i in 1..=n {
            let x = num_bigint::BigInt::from(i as i64);
            let mut val = num_bigint::BigInt::from(0);
            let mut x_pow = num_bigint::BigInt::from(1);
            for coeff in &coeffs {
                val += coeff * &x_pow;
                x_pow *= &x;
            }
            // Store share magnitude as big-endian bytes. exp_bytes
            // requires unsigned input; for small (t,n) and large
            // delta*sk, polynomial evaluations are always non-negative.
            // We assert this below to catch any unexpected cases.
            let abs_val = val.magnitude();
            let abs_bytes = abs_val.to_bytes_be();
            // For negative values, we'd need to negate after exponentiation.
            // In practice, delta * sk is much larger than the random terms,
            // so shares are always positive.
            // To be safe, we'll assert non-negative in tests.
            assert!(
                val.sign() != num_bigint::Sign::Minus,
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

        let msg = b"\x2a"; // 42
        let ct = setup.encrypt_bytes(&pk_raw, msg).expect("encrypt");

        // Single party (1-of-1) partial decryption = full decryption.
        let pd = partial_decrypt(&setup, &ct, 1, &sk_bytes).expect("pd");

        // Verify: pd = c1^sk, so c2 * pd^{-1} should give f^m.
        let (_c1, c2) = setup.ct_components(&ct).expect("comp");
        let pd_inv = pd.dec_share.neg(setup.ctx()).expect("neg");
        let f_m = setup.compose(&c2, &pd_inv).expect("compose");
        #[allow(non_snake_case)]
        let m_bytes = setup.dlog_in_F_bytes(&f_m).expect("dlog");
        let m_val = BigUint::from_bytes_be(&m_bytes);
        assert_eq!(m_val, BigUint::from(42u32));
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

        // Partial decryptions from parties 1 and 2.
        let pd1 = partial_decrypt(&setup, &ct, 1, &shares[0]).expect("pd1");
        let pd2 = partial_decrypt(&setup, &ct, 2, &shares[1]).expect("pd2");

        let decrypted = final_decrypt(&setup, &ct, n, &[pd1, pd2]).expect("fin_dec");
        let m_val = BigUint::from_bytes_be(&decrypted);
        assert_eq!(m_val, BigUint::from(123u32));
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

        // Partial decryptions from parties 1, 3, 5.
        let pd1 = partial_decrypt(&setup, &ct, 1, &shares[0]).expect("pd1");
        let pd3 = partial_decrypt(&setup, &ct, 3, &shares[2]).expect("pd3");
        let pd5 = partial_decrypt(&setup, &ct, 5, &shares[4]).expect("pd5");

        let decrypted = final_decrypt(&setup, &ct, n, &[pd1, pd3, pd5]).expect("fin_dec");
        let m_val = BigUint::from_bytes_be(&decrypted);
        assert_eq!(m_val, BigUint::from(999u32));
    }
}
