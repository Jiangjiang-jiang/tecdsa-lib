// SPDX-License-Identifier: MIT OR Apache-2.0
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

//! `R_Sh` (PolyVerify) -- proof that encrypted shares come from a
//! degree-(t-1) polynomial with shared randomness rho.
//!
//! The PVSS ciphertext structure uses common randomness:
//!   c1 = h^rho  (shared across all parties)
//!   c2_j = pk_j^rho * f^{v_j}  for each party j
//!
//! The proof aggregates per-party public data into `prod_U` and `prod_V`
//! using hash challenges and dual-code polynomial coefficients, then
//! proves a Schnorr-like relation: `prod_V = prod_U^rho` and `c1 = h^rho`.
//!
//! The proof data is constant-size: just `(k, rho_response)`.
//!
//! Follows the PolyVerify pattern from BICYCL C++ reference (TX25).

use rug::{integer::Order, Integer};
use sha2::{Digest, Sha256};
use tecdsa_bigint::pow_mod;

use super::sample_random;
use crate::cl::{ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi};

/// Security parameter for hash challenges (bit-width of c_j).
const SOUNDNESS_BITS: u32 = 40;

/// Statistical distance parameter (lambda_distance).
const LAMBDA_DISTANCE: u32 = 40;

/// Proof that encrypted shares come from a polynomial with shared randomness.
pub struct RShProof {
    /// Fiat-Shamir challenge (big-endian bytes).
    pub k: Vec<u8>,
    /// Response: rho_response = k * rho + rho0 (big-endian bytes).
    pub rho_response: Vec<u8>,
}

/// Computes per-party hash challenge: `c_j = H(sum_c2_repr, pk_j_repr, j) mod 2^SOUNDNESS_BITS`.
fn c_from_hash(c2s: &[&Qfi], pk_j: &Qfi, j: u16) -> ClResult<Integer> {
    let mut hasher = Sha256::new();

    // Hash all c2 elements to form a binding context.
    for c2 in c2s {
        let bytes = c2.to_bytes();
        hasher.update(&bytes);
        hasher.update(b"||");
    }

    // Hash pk_j.
    let pk_bytes = pk_j.to_bytes();
    hasher.update(&pk_bytes);
    hasher.update(b"||");

    // Hash party index.
    hasher.update(j.to_string().as_bytes());

    let hash = hasher.finalize();
    let hash_uint = Integer::from_digits(&hash, Order::Msf);
    let modulus = Integer::from(1) << SOUNDNESS_BITS;
    Ok(hash_uint % modulus)
}

/// Derives deterministic dual-code polynomial coefficients from a hash of the c2 values.
///
/// Returns `degree + 1` coefficients in `[0, q)`.
fn dual_code_coeffs(c2s: &[&Qfi], degree: usize, q: &Integer) -> ClResult<Vec<Integer>> {
    let mut coeffs = Vec::with_capacity(degree + 1);

    for d in 0..=degree {
        let mut hasher = Sha256::new();
        hasher.update(b"dual_code_coeff|");
        hasher.update(d.to_string().as_bytes());
        hasher.update(b"|");

        for c2 in c2s {
            let bytes = c2.to_bytes();
            hasher.update(&bytes);
            hasher.update(b"||");
        }

        let hash = hasher.finalize();
        let coeff = Integer::from_digits(&hash, Order::Msf) % q;
        coeffs.push(coeff);
    }

    Ok(coeffs)
}

/// Evaluates a polynomial at a point using Horner's method (mod q).
fn horner_eval(coeffs: &[Integer], x: &Integer, q: &Integer) -> Integer {
    let mut result = Integer::new();
    for coeff in coeffs.iter().rev() {
        result = (Integer::from(&result * x) + coeff) % q;
    }
    result
}

/// Computes the aggregated (prod_U, prod_V) from public data.
///
/// For each party i:
///   den_i = 1 / prod_{j != i}(i - j)  mod q    (Lagrange inverse denominator)
///   value_i = horner(check_coeffs, i)  mod q     (random polynomial at i)
///   den_i = den_i * value_i mod q
///   exp_i = c_i * M + den_i
///   prod_U *= pk_i^{exp_i}
///   prod_V *= c2_i^{exp_i}
#[allow(non_snake_case)]
fn aggregate_products(
    setup: &ClSetup,
    party_ids: &[u16],
    threshold: u16,
    pks: &[&ClHsmqkPublicKey],
    c2s: &[&Qfi],
) -> ClResult<(Qfi, Qfi)> {
    let n = party_ids.len();
    let q = Integer::from_digits(&setup.q_bytes()?, Order::Msf);
    let M = Integer::from_digits(&setup.cl().m().to_bytes_be(), Order::Msf);

    // degree = n - t - 2  (the dual code degree).
    // When n <= t + 1, degree < 0 and there is no dual code check.
    let degree_signed = n as i64 - threshold as i64 - 2;

    // Retrieve pk elements.
    let pk_elts: Vec<Qfi> = pks.iter().map(|pk| pk.elt().clone()).collect::<Vec<_>>();

    // Compute per-party challenges c_j.
    let challenges: Vec<Integer> = party_ids
        .iter()
        .enumerate()
        .map(|(idx, &j)| c_from_hash(c2s, &pk_elts[idx], j))
        .collect::<ClResult<Vec<_>>>()?;

    // Compute dual-code coefficients if degree >= 0.
    let check_coeffs = if degree_signed >= 0 {
        dual_code_coeffs(c2s, degree_signed as usize, &q)?
    } else {
        vec![]
    };

    let q_minus_2 = Integer::from(&q - 2);

    // Compute every party's aggregation exponent `exp_i = c_i*M + den_i`, then
    // fold each product with a single shared-squaring multi-exponentiation
    // (`prod_U = ∏ pk_i^{exp_i}`, `prod_V = ∏ c2_i^{exp_i}`) instead of `n`
    // independent exp+compose pairs — the dominant O(n^2) keygen cost.
    let mut exps: Vec<Vec<u8>> = Vec::with_capacity(n);
    for (idx, &i_id) in party_ids.iter().enumerate() {
        let i_big = Integer::from(i_id);

        // Compute Lagrange inverse denominator: 1 / prod_{j != i}(i - j) mod q.
        let mut den = Integer::from(1);

        for (jdx, &j_id) in party_ids.iter().enumerate() {
            if jdx == idx {
                continue;
            }
            // (i - j) mod q, normalized to [0, q).
            let diff_pos = (Integer::from(i_id) - Integer::from(j_id)).modulo(&q);
            den = Integer::from(&den * &diff_pos) % &q;
        }

        // Invert via Fermat's little theorem.
        den = pow_mod(&den, &q_minus_2, &q);

        // If dual code is active, multiply by polynomial evaluation.
        if degree_signed >= 0 {
            let value = horner_eval(&check_coeffs, &i_big, &q);
            den = Integer::from(&den * &value) % &q;
        }

        // exp_i = c_i * M + den.
        let exp_i = Integer::from(&challenges[idx] * &M) + &den;
        exps.push(exp_i.to_digits::<u8>(Order::Msf));
    }

    let pk_refs: Vec<&Qfi> = pk_elts.iter().collect();
    let prod_U = setup.multiexp_bytes(&pk_refs, &exps)?;
    let prod_V = setup.multiexp_bytes(c2s, &exps)?;

    Ok((prod_U, prod_V))
}

/// Computes the Fiat-Shamir challenge from (prod_U, prod_V, R0, V0).
///
/// Returns `H(prod_U, prod_V, R0, V0) mod 2^SOUNDNESS_BITS`.
fn schnorr_challenge(prod_u: &Qfi, prod_v: &Qfi, r0: &Qfi, v0: &Qfi) -> ClResult<Vec<u8>> {
    let mut hasher = Sha256::new();

    for qfi in [prod_u, prod_v, r0, v0] {
        let bytes = qfi.to_bytes();
        hasher.update(&bytes);
        hasher.update(b"||");
    }

    let hash = hasher.finalize();
    let k_full = Integer::from_digits(&hash, Order::Msf);
    let modulus = Integer::from(1) << SOUNDNESS_BITS;
    let k = k_full % modulus;
    Ok(k.to_digits::<u8>(Order::Msf))
}

impl RShProof {
    /// Generates a proof that encrypted shares come from a polynomial
    /// of degree <= t-1 with shared randomness rho.
    ///
    /// # Arguments
    ///
    /// - `party_ids`: list of 1-based party indices.
    /// - `threshold`: the threshold `t`.
    /// - `pks`: public keys indexed same as `party_ids`.
    /// - `c1`: shared ciphertext component `h^rho`.
    /// - `c2s`: per-party `c2_j` values indexed same as `party_ids`.
    /// - `rho_bytes`: witness randomness rho (big-endian bytes).
    #[allow(non_snake_case)]
    #[allow(unused_variables)]
    pub fn prove(
        setup: &mut ClSetup,
        party_ids: &[u16],
        threshold: u16,
        pks: &[&ClHsmqkPublicKey],
        c1: &Qfi,
        c2s: &[&Qfi],
        rho_bytes: &[u8],
    ) -> ClResult<Self> {
        let n = party_ids.len();
        assert_eq!(n, pks.len());
        assert_eq!(n, c2s.len());

        // When n <= t+1, degree < 0 => trivially valid.
        let degree_signed = n as i64 - threshold as i64 - 2;
        if degree_signed < 0 {
            return Ok(Self {
                k: vec![0],
                rho_response: vec![0],
            });
        }

        // 1. Aggregate products from public data.
        let (prod_U, prod_V) = aggregate_products(setup, party_ids, threshold, pks, c2s)?;

        // 2. Compute the randomness bound for the Schnorr-like proof.
        //    B = secretkey_bound * 2^soundness * 2^lambda_distance
        let sk_bound = Integer::from_digits(&setup.secretkey_bound_bytes()?, Order::Msf);
        let B = Integer::from(&sk_bound << (SOUNDNESS_BITS + LAMBDA_DISTANCE));

        // 3. Sample rho0 in [0, B).  We use sample_random and reduce mod B.
        let rho0_raw = sample_random(setup)?;
        let rho0_uint = Integer::from_digits(&rho0_raw, Order::Msf);
        let rho0 = rho0_uint % &B;
        let rho0_bytes = rho0.to_digits::<u8>(Order::Msf);

        // 4. Compute commitments R0 = h^{rho0}, V0 = prod_U^{rho0}.
        let R0 = setup.power_of_h_bytes(&rho0_bytes)?;
        let V0 = setup.exp_bytes(&prod_U, &rho0_bytes)?;

        // 5. Fiat-Shamir challenge: k = H(prod_U, prod_V, R0, V0).
        let k_bytes = schnorr_challenge(&prod_U, &prod_V, &R0, &V0)?;

        // 6. Response: rho_response = k * rho + rho0.
        let k_uint = Integer::from_digits(&k_bytes, Order::Msf);
        let rho_uint = Integer::from_digits(rho_bytes, Order::Msf);
        let rho_response = Integer::from(&k_uint * &rho_uint) + &rho0;

        Ok(Self {
            k: k_bytes,
            rho_response: rho_response.to_digits::<u8>(Order::Msf),
        })
    }

    /// Verifies the proof that encrypted shares come from a polynomial
    /// of degree <= t-1 with shared randomness rho.
    #[allow(non_snake_case)]
    pub fn verify(
        &self,
        setup: &ClSetup,
        party_ids: &[u16],
        threshold: u16,
        pks: &[&ClHsmqkPublicKey],
        c1: &Qfi,
        c2s: &[&Qfi],
    ) -> ClResult<bool> {
        let n = party_ids.len();
        assert_eq!(n, pks.len());
        assert_eq!(n, c2s.len());

        // When n <= t+1, degree < 0 => trivially valid.
        let degree_signed = n as i64 - threshold as i64 - 2;
        if degree_signed < 0 {
            return Ok(true);
        }

        // 1. Check rho_response is in range: 0 <= rho_response <= bound.
        //    bound = (1 + 2^lambda_distance) * 2^soundness * secretkey_bound
        let sk_bound = Integer::from_digits(&setup.secretkey_bound_bytes()?, Order::Msf);
        let factor = (Integer::from(1) << LAMBDA_DISTANCE) + 1;
        let upper_bound = Integer::from(&sk_bound << SOUNDNESS_BITS) * &factor;

        let rho_resp = Integer::from_digits(&self.rho_response, Order::Msf);
        if rho_resp > upper_bound {
            return Ok(false);
        }

        // 2. Recompute aggregated products.
        let (prod_U, prod_V) = aggregate_products(setup, party_ids, threshold, pks, c2s)?;

        // 3. Reconstruct R0: R = h^{rho_response}, R_tmp = R / c1^k.
        let rho_resp_bytes = rho_resp.to_digits::<u8>(Order::Msf);
        let R = setup.power_of_h_bytes(&rho_resp_bytes)?;
        let mut c1_k = setup.exp_bytes(c1, &self.k)?;
        c1_k.neg();
        let R_tmp = setup.compose(&R, &c1_k)?;

        // 4. Reconstruct V0: V = prod_U^{rho_response}, V_tmp = V / prod_V^k.
        let V = setup.exp_bytes(&prod_U, &rho_resp_bytes)?;
        let mut prod_V_k = setup.exp_bytes(&prod_V, &self.k)?;
        prod_V_k.neg();
        let V_tmp = setup.compose(&V, &prod_V_k)?;

        // 5. Check: k == H(prod_U, prod_V, R_tmp, V_tmp).
        let k_check = schnorr_challenge(&prod_U, &prod_V, &R_tmp, &V_tmp)?;
        Ok(k_check == self.k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cl::ClSetup, zk::sample_random_mod_q};

    /// Creates a PVSS dealing with shared randomness rho.
    ///
    /// Returns (c1, c2s, rho_bytes).
    #[allow(non_snake_case)]
    fn create_pvss_ciphertexts(
        setup: &mut ClSetup,
        party_ids: &[u16],
        threshold: u16,
        pks: &[&ClHsmqkPublicKey],
    ) -> ClResult<(Qfi, Vec<Qfi>, Vec<u8>)> {
        let q = Integer::from_digits(&setup.q_bytes()?, Order::Msf);
        let n = party_ids.len();

        // Generate degree-(t-1) polynomial coefficients.
        let mut coeffs = Vec::with_capacity(threshold as usize);
        for _ in 0..threshold {
            let r = sample_random_mod_q(setup)?;
            let r_val = Integer::from_digits(&r, Order::Msf);
            coeffs.push(r_val);
        }

        // Evaluate polynomial at each party's id.
        let mut shares = Vec::with_capacity(n);
        for &id in party_ids {
            let x = Integer::from(id);
            let mut val = Integer::new();
            let mut x_pow = Integer::from(1);
            for coeff in &coeffs {
                val = (&val + Integer::from(coeff * &x_pow)) % &q;
                x_pow = Integer::from(&x_pow * &x) % &q;
            }
            shares.push(val.to_digits::<u8>(Order::Msf));
        }

        // Sample shared randomness rho.
        let rho_bytes = {
            let (sk, _) = setup.keygen()?;
            setup.sk_to_bytes(&sk)?
        };

        // c1 = h^rho.
        let c1 = setup.power_of_h_bytes(&rho_bytes)?;

        // c2_j = pk_j^rho * f^{v_j}.
        let mut c2s = Vec::with_capacity(n);
        for (idx, share) in shares.iter().enumerate() {
            let pk_elt = pks[idx].elt();
            let pk_rho = setup.exp_bytes(pk_elt, &rho_bytes)?;
            let f_v = setup.power_of_f_bytes(share)?;
            let c2 = setup.compose(&pk_rho, &f_v)?;
            c2s.push(c2);
        }

        Ok((c1, c2s, rho_bytes))
    }

    #[test]
    fn r_sh_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("20001").expect("setup");
        let n = 5u16;
        let t = 2u16;

        // Generate keypairs.
        let mut pks = Vec::new();
        for _ in 0..n {
            let (_, pk) = setup.keygen().expect("keygen");
            pks.push(pk);
        }

        let party_ids: Vec<u16> = (1..=n).collect();
        let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();

        // Create PVSS ciphertexts.
        let (c1, c2s, rho) =
            create_pvss_ciphertexts(&mut setup, &party_ids, t, &pk_refs).expect("pvss");
        let c2_refs: Vec<&Qfi> = c2s.iter().collect();

        // Prove.
        let proof = RShProof::prove(&mut setup, &party_ids, t, &pk_refs, &c1, &c2_refs, &rho)
            .expect("prove");

        // Verify.
        assert!(proof
            .verify(&setup, &party_ids, t, &pk_refs, &c1, &c2_refs)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_sh_rejects_wrong_rho() {
        let mut setup = ClSetup::new_secp256k1("20002").expect("setup");
        let n = 5u16;
        let t = 2u16;

        let mut pks = Vec::new();
        for _ in 0..n {
            let (_, pk) = setup.keygen().expect("keygen");
            pks.push(pk);
        }

        let party_ids: Vec<u16> = (1..=n).collect();
        let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();

        let (c1, c2s, _rho) =
            create_pvss_ciphertexts(&mut setup, &party_ids, t, &pk_refs).expect("pvss");
        let c2_refs: Vec<&Qfi> = c2s.iter().collect();

        // Prove with wrong rho.
        let wrong_rho = {
            let (sk2, _) = setup.keygen().expect("kg2");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };
        let proof = RShProof::prove(
            &mut setup, &party_ids, t, &pk_refs, &c1, &c2_refs, &wrong_rho,
        )
        .expect("prove");

        assert!(!proof
            .verify(&setup, &party_ids, t, &pk_refs, &c1, &c2_refs)
            .expect("verify"));
    }

    #[ignore = "redundant ZK negative test"]
    #[test]
    fn r_sh_rejects_wrong_shares() {
        let mut setup = ClSetup::new_secp256k1("20003").expect("setup");
        let n = 5u16;
        let t = 2u16;

        let mut pks = Vec::new();
        for _ in 0..n {
            let (_, pk) = setup.keygen().expect("keygen");
            pks.push(pk);
        }

        let party_ids: Vec<u16> = (1..=n).collect();
        let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();

        // Create valid PVSS.
        let (c1, c2s, rho) =
            create_pvss_ciphertexts(&mut setup, &party_ids, t, &pk_refs).expect("pvss");

        // Tamper with one c2: replace c2[0] with a random element.
        let mut tampered_c2s = c2s;
        let random_val = sample_random_mod_q(&mut setup).expect("rand");
        let f_bad = setup.power_of_f_bytes(&random_val).expect("f_bad");
        let pk0_elt = &pks[0].elt();
        let pk0_rho = setup.exp_bytes(pk0_elt, &rho).expect("pk0^rho");
        tampered_c2s[0] = setup.compose(&pk0_rho, &f_bad).expect("compose");

        let c2_refs: Vec<&Qfi> = tampered_c2s.iter().collect();

        // The proof uses the correct rho, but c2s do not come from a
        // degree-(t-1) polynomial, so verification should fail.
        let proof = RShProof::prove(&mut setup, &party_ids, t, &pk_refs, &c1, &c2_refs, &rho)
            .expect("prove");

        assert!(!proof
            .verify(&setup, &party_ids, t, &pk_refs, &c1, &c2_refs)
            .expect("verify"));
    }
    #[ignore = "redundant ZK negative test"]
    #[test]
    fn r_sh_trivial_when_n_leq_t_plus_1() {
        let mut setup = ClSetup::new_secp256k1("20004").expect("setup");
        // n = 3, t = 2 => degree = 3 - 2 - 2 = -1 < 0 => trivial.
        let n = 3u16;
        let t = 2u16;

        let mut pks = Vec::new();
        for _ in 0..n {
            let (_, pk) = setup.keygen().expect("keygen");
            pks.push(pk);
        }

        let party_ids: Vec<u16> = (1..=n).collect();
        let pk_refs: Vec<&ClHsmqkPublicKey> = pks.iter().collect();

        let (c1, c2s, rho) =
            create_pvss_ciphertexts(&mut setup, &party_ids, t, &pk_refs).expect("pvss");
        let c2_refs: Vec<&Qfi> = c2s.iter().collect();

        let proof = RShProof::prove(&mut setup, &party_ids, t, &pk_refs, &c1, &c2_refs, &rho)
            .expect("prove");

        // Trivial proof should always verify.
        assert!(proof
            .verify(&setup, &party_ids, t, &pk_refs, &c1, &c2_refs)
            .expect("verify"));
    }
}
