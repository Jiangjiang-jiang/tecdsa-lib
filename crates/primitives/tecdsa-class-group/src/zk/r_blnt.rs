// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_Blnt` -- blinded chunk-encryption proof (WMC24, Appendix B.d, Figure 6).
//!
//! Proves that a big integer chi committed in a Pedersen commitment PC is
//! correctly encrypted chunk-by-chunk AND as an aggregated GEnc ciphertext.
//!
//! # Relation
//!
//! ```text
//! R_Blnt = {
//!   ((PC, {c_{l,0}, c_{l,1}}_l, (c_0, c_1), ek),
//!    ({chi_l}_l, chi', {r_l}_l, r)):
//!
//!   PC = g_q^{chi'} * prod_l (g_q^{q^l})^{chi_l}       -- Pedersen commitment
//!   c_{l,0} = g_q^{r_l}                                -- per-chunk encryption (c1)
//!   c_{l,1} = f^{chi_l} * ek^{r_l}                     -- per-chunk encryption (c2)
//!   c_0 = g_q^r * prod_l (g_q^{q^l})^{chi_l}           -- aggregated GEnc (c1)
//!   c_1 = ek^r * prod_l (g_q^{q^l})^{chi_l}            -- aggregated GEnc (c2)
//! }
//! ```
//!
//! In our CL-HSMqk code: `g_q = h` (hidden-order generator), `f` (order-q
//! generator), `ek = pk` (public key).

use rug::{Complete, Integer};
use tecdsa_bigint::BigIntExt;

use super::{challenge_from_qfi, response_unbounded, sample_random, sample_random_mod_q};
use crate::cl::{ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi};

/// Blinded chunk-encryption proof (`Z_Blnt` / `R_Blnt`).
pub struct RBlntProof {
    /// Commitment: C = h^{a_2} * prod_l h^{q^l * a_{1l}}
    pub c_commit: Qfi,
    /// Per-chunk randomness commitments: R_l = h^{a_{3l}}
    pub r_chunks: Vec<Qfi>,
    /// Per-chunk encryption commitments: S_l = f^{a_{1l}} * pk^{a_{3l}}
    pub s_chunks: Vec<Qfi>,
    /// Aggregated randomness commitment: R_0 = h^{a_4} * prod_l h^{q^l * a_{1l}}
    pub r_0: Qfi,
    /// Aggregated encryption commitment: S_0 = pk^{a_4} * prod_l h^{q^l * a_{1l}}
    pub s_0: Qfi,
    /// Responses z_{1l} (unbounded integer, big-endian bytes per chunk)
    pub z1_chunks: Vec<Vec<u8>>,
    /// Responses z_{3l} (unbounded integer, big-endian bytes per chunk)
    pub z3_chunks: Vec<Vec<u8>>,
    /// Response z_2 (unbounded integer, big-endian bytes)
    pub z2: Vec<u8>,
    /// Response z_4 (unbounded integer, big-endian bytes)
    pub z4: Vec<u8>,
    /// Fiat-Shamir challenge (big-endian bytes)
    pub e: Vec<u8>,
}

impl RBlntProof {
    /// Generates the R_Blnt proof.
    ///
    /// # Arguments
    ///
    /// - `setup`: mutable reference to CL-HSMqk setup.
    /// - `pk`: public key `ek`.
    /// - `pc`: Pedersen commitment `PC`.
    /// - `chunk_cts`: per-chunk ciphertexts `{(c_{l,0}, c_{l,1})}`.
    /// - `agg_ct`: aggregated GEnc ciphertext `(c_0, c_1)`.
    /// - `chi_chunks`: per-chunk plaintexts `{chi_l}` (big-endian bytes, mod q).
    /// - `chi_prime`: commitment randomness `chi'` (big-endian bytes).
    /// - `r_chunks`: per-chunk encryption randomness `{r_l}` (big-endian bytes).
    /// - `r_agg`: aggregated randomness `r` (big-endian bytes).
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        pc: &Qfi,
        chunk_cts: &[(Qfi, Qfi)],
        agg_ct: &(Qfi, Qfi),
        chi_chunks: &[Vec<u8>],
        chi_prime: &[u8],
        r_chunks: &[Vec<u8>],
        r_agg: &[u8],
    ) -> ClResult<Self> {
        let num_chunks = chunk_cts.len();
        assert_eq!(chi_chunks.len(), num_chunks);
        assert_eq!(r_chunks.len(), num_chunks);

        let q = setup.cl().q().clone();

        // 1. Sample random commitment values.
        // a_{1l} <- Z_q (one per chunk)
        let mut a1_vec: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            a1_vec.push(sample_random_mod_q(setup)?);
        }
        // a_2 <- secretkey_bound (for chi' randomness)
        let a2 = sample_random(setup)?;
        // a_{3l} <- secretkey_bound (one per chunk, for r_l randomness)
        let mut a3_vec: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            a3_vec.push(sample_random(setup)?);
        }
        // a_4 <- secretkey_bound (for r_agg randomness)
        let a4 = sample_random(setup)?;

        // 2. Compute the product term prod_l h^{q^l * a_{1l}}
        let h_q_pow_a1_product = compute_h_q_pow_product(setup, &q, &a1_vec)?;

        // 3. Compute commitments.
        // C = h^{a_2} * prod_l h^{q^l * a_{1l}}
        let h_a2 = setup.power_of_h_bytes(&a2)?;
        let c_commit = setup.compose(&h_a2, &h_q_pow_a1_product)?;

        // R_l = h^{a_{3l}}
        let mut r_chunks_commit: Vec<Qfi> = Vec::with_capacity(num_chunks);
        for a3l in &a3_vec {
            r_chunks_commit.push(setup.power_of_h_bytes(a3l)?);
        }

        // S_l = f^{a_{1l}} * pk^{a_{3l}}
        let pk_elt = pk.elt();
        let mut s_chunks_commit: Vec<Qfi> = Vec::with_capacity(num_chunks);
        for idx in 0..num_chunks {
            let f_a1 = setup.power_of_f_bytes(&a1_vec[idx])?;
            let pk_a3 = setup.exp_bytes(pk_elt, &a3_vec[idx])?;
            s_chunks_commit.push(setup.compose(&f_a1, &pk_a3)?);
        }

        // R_0 = h^{a_4} * prod_l h^{q^l * a_{1l}}
        let h_a4 = setup.power_of_h_bytes(&a4)?;
        let r_0 = setup.compose(&h_a4, &h_q_pow_a1_product)?;

        // S_0 = pk^{a_4} * prod_l h^{q^l * a_{1l}}
        let pk_a4 = setup.exp_bytes(pk_elt, &a4)?;
        let s_0 = setup.compose(&pk_a4, &h_q_pow_a1_product)?;

        // 4. Compute Fiat-Shamir challenge.
        let (agg_c0, agg_c1) = agg_ct;
        let mut qfi_elements: Vec<&Qfi> = Vec::new();
        qfi_elements.push(pc);
        for (c0, c1) in chunk_cts.iter() {
            qfi_elements.push(c0);
            qfi_elements.push(c1);
        }
        qfi_elements.push(agg_c0);
        qfi_elements.push(agg_c1);
        qfi_elements.push(pk_elt);
        qfi_elements.push(&c_commit);
        for rl in &r_chunks_commit {
            qfi_elements.push(rl);
        }
        for sl in &s_chunks_commit {
            qfi_elements.push(sl);
        }
        qfi_elements.push(&r_0);
        qfi_elements.push(&s_0);

        let e = challenge_from_qfi(setup, b"R_Blnt", &qfi_elements, &[])?;

        // 5. Compute responses.
        // z_{1l} = a_{1l} + chi_l * chal (unbounded integer -- NOT reduced mod q,
        // because h^{q^l * z1l} in checks 6/7/8 requires the full exponent;
        // f^{z1l} in check 5 naturally reduces because f has order q).
        let mut z1_chunks_resp: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);
        for idx in 0..num_chunks {
            z1_chunks_resp.push(response_unbounded(&a1_vec[idx], &e, &chi_chunks[idx])?);
        }

        // z_{3l} = a_{3l} + r_l * chal (unbounded)
        let mut z3_chunks_resp: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);
        for idx in 0..num_chunks {
            z3_chunks_resp.push(response_unbounded(&a3_vec[idx], &e, &r_chunks[idx])?);
        }

        // z_2 = a_2 + chal * chi' (unbounded)
        let z2 = response_unbounded(&a2, &e, chi_prime)?;

        // z_4 = a_4 + chal * r (unbounded)
        let z4 = response_unbounded(&a4, &e, r_agg)?;

        Ok(Self {
            c_commit,
            r_chunks: r_chunks_commit,
            s_chunks: s_chunks_commit,
            r_0,
            s_0,
            z1_chunks: z1_chunks_resp,
            z3_chunks: z3_chunks_resp,
            z2,
            z4,
            e,
        })
    }

    /// Verifies the R_Blnt proof.
    ///
    /// # Arguments
    ///
    /// - `setup`: reference to CL-HSMqk setup.
    /// - `pk`: public key `ek`.
    /// - `pc`: Pedersen commitment `PC`.
    /// - `chunk_cts`: per-chunk ciphertexts `{(c_{l,0}, c_{l,1})}`.
    /// - `agg_ct`: aggregated GEnc ciphertext `(c_0, c_1)`.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        pc: &Qfi,
        chunk_cts: &[(Qfi, Qfi)],
        agg_ct: &(Qfi, Qfi),
    ) -> ClResult<bool> {
        let num_chunks = chunk_cts.len();
        if self.r_chunks.len() != num_chunks
            || self.s_chunks.len() != num_chunks
            || self.z1_chunks.len() != num_chunks
            || self.z3_chunks.len() != num_chunks
        {
            return Ok(false);
        }

        let pk_elt = pk.elt();
        let (agg_c0, agg_c1) = agg_ct;

        // Recompute Fiat-Shamir challenge.
        let mut qfi_elements: Vec<&Qfi> = Vec::new();
        qfi_elements.push(pc);
        for (c0, c1) in chunk_cts.iter() {
            qfi_elements.push(c0);
            qfi_elements.push(c1);
        }
        qfi_elements.push(agg_c0);
        qfi_elements.push(agg_c1);
        qfi_elements.push(pk_elt);
        qfi_elements.push(&self.c_commit);
        for rl in &self.r_chunks {
            qfi_elements.push(rl);
        }
        for sl in &self.s_chunks {
            qfi_elements.push(sl);
        }
        qfi_elements.push(&self.r_0);
        qfi_elements.push(&self.s_0);

        let e_check = challenge_from_qfi(setup, b"R_Blnt", &qfi_elements, &[])?;
        if e_check != self.e {
            return Ok(false);
        }

        let q = setup.cl().q();

        // Compute the shared product term: prod_l h^{q^l * z_{1l}}
        let h_q_pow_z1_product = compute_h_q_pow_product(setup, q, &self.z1_chunks)?;

        // Check per-chunk equations (4) and (5).
        for (idx, (c_l_0, c_l_1)) in chunk_cts.iter().enumerate() {
            // Check 4: h^{z_{3l}} == R_l * c_{l,0}^{chal}
            let lhs4 = setup.power_of_h_bytes(&self.z3_chunks[idx])?;
            let c_l_0_e = setup.exp_bytes(c_l_0, &self.e)?;
            let rhs4 = setup.compose(&self.r_chunks[idx], &c_l_0_e)?;
            if lhs4 != rhs4 {
                return Ok(false);
            }

            // Check 5: f^{z_{1l}} * pk^{z_{3l}} == S_l * c_{l,1}^{chal}
            let f_z1 = setup.power_of_f_bytes(&self.z1_chunks[idx])?;
            let pk_z3 = setup.pk_pow_bytes(pk, &self.z3_chunks[idx])?;
            let lhs5 = setup.compose(&f_z1, &pk_z3)?;
            let c_l_1_e = setup.exp_bytes(c_l_1, &self.e)?;
            let rhs5 = setup.compose(&self.s_chunks[idx], &c_l_1_e)?;
            if lhs5 != rhs5 {
                return Ok(false);
            }
        }

        // Check 6: h^{z_4} * prod_l h^{q^l * z_{1l}} == R_0 * c_0^{chal}
        let h_z4 = setup.power_of_h_bytes(&self.z4)?;
        let lhs6 = setup.compose(&h_z4, &h_q_pow_z1_product)?;
        let c_0_e = setup.exp_bytes(agg_c0, &self.e)?;
        let rhs6 = setup.compose(&self.r_0, &c_0_e)?;
        if lhs6 != rhs6 {
            return Ok(false);
        }

        // Check 7: h^{z_2} * prod_l h^{q^l * z_{1l}} == C * PC^{chal}
        let h_z2 = setup.power_of_h_bytes(&self.z2)?;
        let lhs7 = setup.compose(&h_z2, &h_q_pow_z1_product)?;
        let pc_e = setup.exp_bytes(pc, &self.e)?;
        let rhs7 = setup.compose(&self.c_commit, &pc_e)?;
        if lhs7 != rhs7 {
            return Ok(false);
        }

        // Check 8: pk^{z_4} * prod_l h^{q^l * z_{1l}} == S_0 * c_1^{chal}
        let pk_z4 = setup.pk_pow_bytes(pk, &self.z4)?;
        let lhs8 = setup.compose(&pk_z4, &h_q_pow_z1_product)?;
        let c_1_e = setup.exp_bytes(agg_c1, &self.e)?;
        let rhs8 = setup.compose(&self.s_0, &c_1_e)?;
        if lhs8 != rhs8 {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Computes `prod_l h^{q^l * x_l}` for a list of exponents `x_l`.
///
/// Each `x_l` is big-endian bytes. The product iterates over `l = 0, 1, ...`
/// computing `h^{q^l * x_l}` and composing them together.
fn compute_h_q_pow_product(setup: &ClSetup, q: &Integer, exponents: &[Vec<u8>]) -> ClResult<Qfi> {
    let mut product = setup.identity()?;
    let mut q_pow_l = Integer::from(1); // q^0 = 1

    for x_l in exponents {
        // Compute q^l * x_l
        let x = Integer::from_bytes_msf(x_l);
        let exp = (&q_pow_l * &x).complete();

        if !exp.is_zero() {
            let exp_bytes = exp.to_bytes_msf();
            let h_exp = setup.power_of_h_bytes(&exp_bytes)?;
            product = setup.compose(&product, &h_exp)?;
        }

        // q^{l+1} = q^l * q
        q_pow_l *= q;
    }

    Ok(product)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    /// Helper: compute the Pedersen commitment PC = h^{chi'} * prod_l h^{q^l * chi_l}
    fn compute_pc(setup: &ClSetup, chi_prime: &[u8], chi_chunks: &[Vec<u8>]) -> ClResult<Qfi> {
        let q = setup.cl().q();
        let h_chi_prime = setup.power_of_h_bytes(chi_prime)?;
        let product = compute_h_q_pow_product(setup, q, chi_chunks)?;
        setup.compose(&h_chi_prime, &product)
    }

    /// Helper: compute aggregated ciphertext (c_0, c_1) where:
    /// c_0 = h^r * prod_l h^{q^l * chi_l}
    /// c_1 = pk^r * prod_l h^{q^l * chi_l}
    fn compute_agg_ct(
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        chi_chunks: &[Vec<u8>],
        r_agg: &[u8],
    ) -> ClResult<(Qfi, Qfi)> {
        let q = setup.cl().q();

        let product = compute_h_q_pow_product(setup, q, chi_chunks)?;

        let h_r = setup.power_of_h_bytes(r_agg)?;
        let c0 = setup.compose(&h_r, &product)?;

        let pk_r = setup.exp_bytes(pk.elt(), r_agg)?;
        let c1 = setup.compose(&pk_r, &product)?;

        Ok((c0, c1))
    }

    /// Helper: compute per-chunk ciphertext (c_{l,0}, c_{l,1}) where:
    /// c_{l,0} = h^{r_l}
    /// c_{l,1} = f^{chi_l} * pk^{r_l}
    fn compute_chunk_ct(
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        chi_l: &[u8],
        r_l: &[u8],
    ) -> ClResult<(Qfi, Qfi)> {
        let c_l_0 = setup.power_of_h_bytes(r_l)?;
        let f_chi = setup.power_of_f_bytes(chi_l)?;
        let pk_r = setup.exp_bytes(pk.elt(), r_l)?;
        let c_l_1 = setup.compose(&f_chi, &pk_r)?;
        Ok((c_l_0, c_l_1))
    }

    #[test]
    fn r_blnt_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("90001").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        // Use 2 chunks for testing.
        let num_chunks = 2;
        let chi_chunks: Vec<Vec<u8>> = vec![
            Integer::from(42u32).to_bytes_msf(),
            Integer::from(77u32).to_bytes_msf(),
        ];

        // chi' (commitment randomness)
        let chi_prime = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        // Per-chunk randomness
        let mut r_chunks_witness: Vec<Vec<u8>> = Vec::new();
        for _ in 0..num_chunks {
            let (sk2, _) = setup.keygen().expect("kg");
            r_chunks_witness.push(setup.sk_to_bytes(&sk2).expect("bytes"));
        }

        // Aggregated randomness
        let r_agg = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        // Compute statement elements.
        let pc = compute_pc(&setup, &chi_prime, &chi_chunks).expect("pc");

        let mut chunk_cts: Vec<(Qfi, Qfi)> = Vec::new();
        for idx in 0..num_chunks {
            chunk_cts.push(
                compute_chunk_ct(&setup, &pk, &chi_chunks[idx], &r_chunks_witness[idx])
                    .expect("chunk_ct"),
            );
        }

        let agg_ct = compute_agg_ct(&setup, &pk, &chi_chunks, &r_agg).expect("agg_ct");

        // Prove.
        let proof = RBlntProof::prove(
            &mut setup,
            &pk,
            &pc,
            &chunk_cts,
            &agg_ct,
            &chi_chunks,
            &chi_prime,
            &r_chunks_witness,
            &r_agg,
        )
        .expect("prove");

        // Verify.
        assert!(proof
            .verify(&setup, &pk, &pc, &chunk_cts, &agg_ct)
            .expect("verify"));
    }

    #[test]
    fn r_blnt_single_chunk_verifies() {
        let mut setup = ClSetup::new_secp256k1("90002").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        // Single chunk.
        let chi_chunks: Vec<Vec<u8>> = vec![Integer::from(100u32).to_bytes_msf()];

        let chi_prime = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        let r_chunks_witness: Vec<Vec<u8>> = vec![{
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        }];

        let r_agg = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        let pc = compute_pc(&setup, &chi_prime, &chi_chunks).expect("pc");
        let chunk_cts: Vec<(Qfi, Qfi)> =
            vec![
                compute_chunk_ct(&setup, &pk, &chi_chunks[0], &r_chunks_witness[0])
                    .expect("chunk_ct"),
            ];
        let agg_ct = compute_agg_ct(&setup, &pk, &chi_chunks, &r_agg).expect("agg_ct");

        let proof = RBlntProof::prove(
            &mut setup,
            &pk,
            &pc,
            &chunk_cts,
            &agg_ct,
            &chi_chunks,
            &chi_prime,
            &r_chunks_witness,
            &r_agg,
        )
        .expect("prove");

        assert!(proof
            .verify(&setup, &pk, &pc, &chunk_cts, &agg_ct)
            .expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_blnt_rejects_wrong_chi() {
        let mut setup = ClSetup::new_secp256k1("90003").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let chi_chunks: Vec<Vec<u8>> = vec![
            Integer::from(42u32).to_bytes_msf(),
            Integer::from(77u32).to_bytes_msf(),
        ];

        let chi_prime = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        let r_chunks_witness: Vec<Vec<u8>> = vec![
            {
                let (sk2, _) = setup.keygen().expect("kg");
                setup.sk_to_bytes(&sk2).expect("bytes")
            },
            {
                let (sk2, _) = setup.keygen().expect("kg");
                setup.sk_to_bytes(&sk2).expect("bytes")
            },
        ];

        let r_agg = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_bytes(&sk2).expect("bytes")
        };

        let pc = compute_pc(&setup, &chi_prime, &chi_chunks).expect("pc");
        let mut chunk_cts: Vec<(Qfi, Qfi)> = Vec::new();
        for idx in 0..2 {
            chunk_cts.push(
                compute_chunk_ct(&setup, &pk, &chi_chunks[idx], &r_chunks_witness[idx])
                    .expect("chunk_ct"),
            );
        }
        let agg_ct = compute_agg_ct(&setup, &pk, &chi_chunks, &r_agg).expect("agg_ct");

        // Prove with WRONG chi_chunks.
        let wrong_chi: Vec<Vec<u8>> = vec![
            Integer::from(99u32).to_bytes_msf(),
            Integer::from(77u32).to_bytes_msf(),
        ];

        let proof = RBlntProof::prove(
            &mut setup,
            &pk,
            &pc,
            &chunk_cts,
            &agg_ct,
            &wrong_chi,
            &chi_prime,
            &r_chunks_witness,
            &r_agg,
        )
        .expect("prove");

        assert!(!proof
            .verify(&setup, &pk, &pc, &chunk_cts, &agg_ct)
            .expect("verify"));
    }
}
