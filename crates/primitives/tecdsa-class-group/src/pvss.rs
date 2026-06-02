// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap
)]

//! Cascudo-David PVSS (Publicly Verifiable Secret Sharing).
//!
//! The dealer:
//! 1. Picks a secret `s` and generates Shamir shares `s_1, ..., s_n`.
//! 2. Encrypts each share `s_i` under party `i`'s CL public key.
//! 3. Generates a ZK proof of correct encryption for each share.
//!
//! Any verifier can check all proofs using only public keys.
//!
//! Reconstruction:
//! 1. Each party `i` partially decrypts its encrypted share.
//! 2. Combine `t` partial decryptions using Lagrange interpolation.

use crate::bicycl_glue::{ClResult, ClSetup};
use crate::zk::r_enc::REncProof;
use bicycl_rs::{ClHsmqkCiphertext, ClHsmqkPublicKey};
use num_bigint::BigUint;
use num_traits::Num;

/// A PVSS dealing: encrypted shares + proofs of correct encryption.
pub struct PvssDeal {
    /// Encrypted shares, one per party (indexed 0..n-1).
    pub encrypted_shares: Vec<ClHsmqkCiphertext>,
    /// Proofs of correct encryption, one per share.
    pub proofs: Vec<REncProof>,
    /// Commitments to the polynomial coefficients: `f^{a_j}` for j = 0..t-1.
    pub commitments: Vec<bicycl_rs::Qfi>,
}

impl std::fmt::Debug for PvssDeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PvssDeal")
            .field("num_shares", &self.encrypted_shares.len())
            .finish_non_exhaustive()
    }
}

/// Deals a PVSS: generates Shamir shares, encrypts each under the
/// corresponding public key, and produces ZK proofs.
///
/// - `secret_decimal`: the secret to share.
/// - `pks`: public keys of each party (length = n).
/// - `threshold`: the threshold `t` (requires `t` shares to reconstruct).
///
/// Returns the dealing.
pub fn deal(
    setup: &mut ClSetup,
    secret_decimal: &str,
    pks: &[ClHsmqkPublicKey],
    threshold: usize,
) -> ClResult<PvssDeal> {
    let n = pks.len();
    let q_bytes = setup.q_bytes()?;
    let q = BigUint::from_bytes_be(&q_bytes);
    let secret = BigUint::from_str_radix(secret_decimal, 10)
        .map_err(|e| crate::bicycl_glue::ClError::InvalidParam(format!("bad secret: {e}")))?;

    // Generate polynomial coefficients: a_0 = secret, a_1..a_{t-1} random.
    let mut coeffs = vec![secret];
    for _ in 1..threshold {
        let r = crate::zk::sample_random_mod_q(setup)?;
        let r_val = BigUint::from_bytes_be(&r);
        coeffs.push(r_val);
    }

    // Compute commitments: f^{a_j} for each coefficient.
    let mut commitments = Vec::with_capacity(threshold);
    for coeff in &coeffs {
        let c = setup.power_of_f(&coeff.to_str_radix(10))?;
        commitments.push(c);
    }

    // Evaluate polynomial at i = 1, 2, ..., n to get shares.
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = BigUint::from(i as u64);
        let mut val = BigUint::ZERO;
        let mut x_pow = BigUint::from(1u32);
        for coeff in &coeffs {
            val = (&val + coeff * &x_pow) % &q;
            x_pow = (&x_pow * &x) % &q;
        }
        shares.push(val);
    }

    // Encrypt each share and produce a proof.
    let mut encrypted_shares = Vec::with_capacity(n);
    let mut proofs = Vec::with_capacity(n);
    for (i, share) in shares.iter().enumerate() {
        // Encrypt with known randomness so we can produce the proof.
        let r_bytes = {
            let (sk, _) = setup.keygen()?;
            setup.sk_to_bytes(&sk)?
        };
        let share_dec = share.to_str_radix(10);
        let r_dec = BigUint::from_bytes_be(&r_bytes).to_str_radix(10);
        let ct = setup.encrypt_with_r(&pks[i], &share_dec, &r_dec)?;
        let share_bytes = share.to_bytes_be();
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

/// Verifies a PVSS dealing: checks all ZK proofs.
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

/// Reconstructs the secret from `t` decrypted shares using Lagrange
/// interpolation over Z/q.
///
/// `shares` is a list of `(party_index, share_decimal)` pairs where
/// `party_index` is 1-based.
pub fn reconstruct(setup: &ClSetup, shares: &[(usize, &str)]) -> ClResult<String> {
    let q_str = setup.q_decimal()?;
    let q = BigUint::from_str_radix(&q_str, 10)
        .map_err(|e| crate::bicycl_glue::ClError::InvalidParam(format!("bad q: {e}")))?;

    let indices: Vec<usize> = shares.iter().map(|(i, _)| *i).collect();
    let mut secret = BigUint::ZERO;

    for (k, &(i_k, share_k)) in shares.iter().enumerate() {
        let share_val = BigUint::from_str_radix(share_k, 10)
            .map_err(|e| crate::bicycl_glue::ClError::InvalidParam(format!("bad share: {e}")))?;

        // Compute Lagrange coefficient lambda_k mod q.
        let mut num = num_bigint::BigInt::from(1);
        let mut den = num_bigint::BigInt::from(1);
        let i_k_big = num_bigint::BigInt::from(i_k as i64);

        for (j, &idx_j) in indices.iter().enumerate() {
            if j == k {
                continue;
            }
            let i_j_big = num_bigint::BigInt::from(idx_j as i64);
            num *= -&i_j_big;
            den *= &i_k_big - &i_j_big;
        }

        // lambda_k = num * den^{-1} mod q
        let q_big = num_bigint::BigInt::from(q.clone());
        let num_mod = ((num % &q_big) + &q_big) % &q_big;
        let den_mod = ((den % &q_big) + &q_big) % &q_big;

        // Modular inverse of den via Fermat's little theorem: den^{q-2} mod q.
        let den_uint = den_mod.to_biguint().expect("positive");
        let q_minus_2 = &q - BigUint::from(2u32);
        let den_inv = den_uint.modpow(&q_minus_2, &q);

        let num_uint = num_mod.to_biguint().expect("positive");
        let lambda = (&num_uint * &den_inv) % &q;

        secret = (&secret + &share_val * &lambda) % &q;
    }

    Ok(secret.to_str_radix(10))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::ClSetup;

    #[test]
    fn pvss_share_verify_reconstruct() {
        let mut setup = ClSetup::new_secp256k1("16001").expect("setup");

        let n = 3;
        let t = 2;
        let secret = "42";

        // Generate key pairs for each party.
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            sks.push(sk);
            pks.push(pk);
        }

        // Deal.
        let pvss_deal = deal(&mut setup, secret, &pks, t).expect("deal");

        // Verify.
        assert!(verify_deal(&setup, &pvss_deal, &pks).expect("verify"));

        // Decrypt each share.
        let mut decrypted_shares = Vec::new();
        for (i, ct) in pvss_deal.encrypted_shares.iter().enumerate() {
            let m = setup.decrypt(&sks[i], ct).expect("decrypt");
            decrypted_shares.push((i + 1, m));
        }

        // Reconstruct from first t shares.
        let share_refs: Vec<(usize, &str)> = decrypted_shares[..t]
            .iter()
            .map(|(i, s)| (*i, s.as_str()))
            .collect();
        let reconstructed = reconstruct(&setup, &share_refs).expect("reconstruct");
        assert_eq!(reconstructed, secret);
    }
}
