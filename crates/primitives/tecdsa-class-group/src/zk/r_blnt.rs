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

use rug::Integer;

use super::{challenge_from_qfi, response_unbounded, sample_random, sample_random_mod_q};
use crate::{
    cl::{ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi},
    dkg_cl::compute_h_q_pow_product,
};

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
    /// - `chi_chunks`: per-chunk plaintexts `{chi_l}` (mod q).
    /// - `chi_prime`: commitment randomness `chi'`.
    /// - `r_chunks`: per-chunk encryption randomness `{r_l}`.
    /// - `r_agg`: aggregated randomness `r`.
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        pc: &Qfi,
        chunk_cts: &[(Qfi, Qfi)],
        agg_ct: &(Qfi, Qfi),
        chi_chunks: &[Integer],
        chi_prime: &Integer,
        r_chunks: &[Integer],
        r_agg: &Integer,
    ) -> ClResult<Self> {
        let num_chunks = chunk_cts.len();
        assert_eq!(chi_chunks.len(), num_chunks);
        assert_eq!(r_chunks.len(), num_chunks);

        let q = setup.cl().q().clone();

        // 1. Sample random commitment values.
        // a_{1l} <- Z_q (one per chunk)
        let mut a1_vec: Vec<Integer> = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            a1_vec.push(sample_random_mod_q(setup)?);
        }
        // a_2 <- secretkey_bound (for chi' randomness)
        let a2 = sample_random(setup)?;
        // a_{3l} <- secretkey_bound (one per chunk, for r_l randomness)
        let mut a3_vec: Vec<Integer> = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            a3_vec.push(sample_random(setup)?);
        }
        // a_4 <- secretkey_bound (for r_agg randomness)
        let a4 = sample_random(setup)?;

        // 2. Compute the product term prod_l h^{q^l * a_{1l}}
        let h_q_pow_a1_product = compute_h_q_pow_product(setup, &q, &a1_vec)?;

        // 3. Compute commitments.
        // C = h^{a_2} * prod_l h^{q^l * a_{1l}}
        let h_a2 = setup.power_of_h(&a2)?;
        let c_commit = setup.compose(&h_a2, &h_q_pow_a1_product)?;

        // R_l = h^{a_{3l}}
        let mut r_chunks_commit: Vec<Qfi> = Vec::with_capacity(num_chunks);
        for a3l in &a3_vec {
            r_chunks_commit.push(setup.power_of_h(a3l)?);
        }

        // S_l = f^{a_{1l}} * pk^{a_{3l}}
        let pk_elt = pk.elt();
        let mut s_chunks_commit: Vec<Qfi> = Vec::with_capacity(num_chunks);
        for idx in 0..num_chunks {
            let f_a1 = setup.power_of_f(&a1_vec[idx])?;
            let pk_a3 = setup.exp(pk_elt, &a3_vec[idx])?;
            s_chunks_commit.push(setup.compose(&f_a1, &pk_a3)?);
        }

        // R_0 = h^{a_4} * prod_l h^{q^l * a_{1l}}
        let h_a4 = setup.power_of_h(&a4)?;
        let r_0 = setup.compose(&h_a4, &h_q_pow_a1_product)?;

        // S_0 = pk^{a_4} * prod_l h^{q^l * a_{1l}}
        let pk_a4 = setup.exp(pk_elt, &a4)?;
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
            z1_chunks_resp.push(response_unbounded(&a1_vec[idx], &e, &chi_chunks[idx]));
        }

        // z_{3l} = a_{3l} + r_l * chal (unbounded)
        let mut z3_chunks_resp: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);
        for idx in 0..num_chunks {
            z3_chunks_resp.push(response_unbounded(&a3_vec[idx], &e, &r_chunks[idx]));
        }

        // z_2 = a_2 + chal * chi' (unbounded)
        let z2 = response_unbounded(&a2, &e, chi_prime);

        // z_4 = a_4 + chal * r (unbounded)
        let z4 = response_unbounded(&a4, &e, r_agg);

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

        let z1_chunks: Vec<Integer> = self
            .z1_chunks
            .iter()
            .map(|z| Integer::from_digits(z, rug::integer::Order::Msf))
            .collect();
        let z3_chunks: Vec<Integer> = self
            .z3_chunks
            .iter()
            .map(|z| Integer::from_digits(z, rug::integer::Order::Msf))
            .collect();
        let z2 = Integer::from_digits(&self.z2, rug::integer::Order::Msf);
        let z4 = Integer::from_digits(&self.z4, rug::integer::Order::Msf);
        let e = Integer::from_digits(&self.e, rug::integer::Order::Msf);

        // Compute the shared product term: prod_l h^{q^l * z_{1l}}
        let h_q_pow_z1_product = compute_h_q_pow_product(setup, q, &z1_chunks)?;

        // Check per-chunk equations (4) and (5).
        for (idx, (c_l_0, c_l_1)) in chunk_cts.iter().enumerate() {
            // Check 4: h^{z_{3l}} == R_l * c_{l,0}^{chal}
            let lhs4 = setup.power_of_h(&z3_chunks[idx])?;
            let c_l_0_e = setup.exp(c_l_0, &e)?;
            let rhs4 = setup.compose(&self.r_chunks[idx], &c_l_0_e)?;
            if lhs4 != rhs4 {
                return Ok(false);
            }

            // Check 5: f^{z_{1l}} * pk^{z_{3l}} == S_l * c_{l,1}^{chal}
            let f_z1 = setup.power_of_f(&z1_chunks[idx])?;
            let pk_z3 = setup.pk_pow(pk, &z3_chunks[idx])?;
            let lhs5 = setup.compose(&f_z1, &pk_z3)?;
            let c_l_1_e = setup.exp(c_l_1, &e)?;
            let rhs5 = setup.compose(&self.s_chunks[idx], &c_l_1_e)?;
            if lhs5 != rhs5 {
                return Ok(false);
            }
        }

        // Check 6: h^{z_4} * prod_l h^{q^l * z_{1l}} == R_0 * c_0^{chal}
        let h_z4 = setup.power_of_h(&z4)?;
        let lhs6 = setup.compose(&h_z4, &h_q_pow_z1_product)?;
        let c_0_e = setup.exp(agg_c0, &e)?;
        let rhs6 = setup.compose(&self.r_0, &c_0_e)?;
        if lhs6 != rhs6 {
            return Ok(false);
        }

        // Check 7: h^{z_2} * prod_l h^{q^l * z_{1l}} == C * PC^{chal}
        let h_z2 = setup.power_of_h(&z2)?;
        let lhs7 = setup.compose(&h_z2, &h_q_pow_z1_product)?;
        let pc_e = setup.exp(pc, &e)?;
        let rhs7 = setup.compose(&self.c_commit, &pc_e)?;
        if lhs7 != rhs7 {
            return Ok(false);
        }

        // Check 8: pk^{z_4} * prod_l h^{q^l * z_{1l}} == S_0 * c_1^{chal}
        let pk_z4 = setup.pk_pow(pk, &z4)?;
        let lhs8 = setup.compose(&pk_z4, &h_q_pow_z1_product)?;
        let c_1_e = setup.exp(agg_c1, &e)?;
        let rhs8 = setup.compose(&self.s_0, &c_1_e)?;
        if lhs8 != rhs8 {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    /// Helper: compute the Pedersen commitment PC = h^{chi'} * prod_l h^{q^l * chi_l}
    fn compute_pc(setup: &ClSetup, chi_prime: &Integer, chi_chunks: &[Integer]) -> ClResult<Qfi> {
        let q = setup.cl().q();
        let h_chi_prime = setup.power_of_h(chi_prime)?;
        let product = compute_h_q_pow_product(setup, q, chi_chunks)?;
        setup.compose(&h_chi_prime, &product)
    }

    /// Helper: compute aggregated ciphertext (c_0, c_1) where:
    /// c_0 = h^r * prod_l h^{q^l * chi_l}
    /// c_1 = pk^r * prod_l h^{q^l * chi_l}
    fn compute_agg_ct(
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        chi_chunks: &[Integer],
        r_agg: &Integer,
    ) -> ClResult<(Qfi, Qfi)> {
        let q = setup.cl().q();

        let product = compute_h_q_pow_product(setup, q, chi_chunks)?;

        let h_r = setup.power_of_h(r_agg)?;
        let c0 = setup.compose(&h_r, &product)?;

        let pk_r = setup.exp(pk.elt(), r_agg)?;
        let c1 = setup.compose(&pk_r, &product)?;

        Ok((c0, c1))
    }

    /// Helper: compute per-chunk ciphertext (c_{l,0}, c_{l,1}) where:
    /// c_{l,0} = h^{r_l}
    /// c_{l,1} = f^{chi_l} * pk^{r_l}
    fn compute_chunk_ct(
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        chi_l: &Integer,
        r_l: &Integer,
    ) -> ClResult<(Qfi, Qfi)> {
        let c_l_0 = setup.power_of_h(r_l)?;
        let f_chi = setup.power_of_f(chi_l)?;
        let pk_r = setup.exp(pk.elt(), r_l)?;
        let c_l_1 = setup.compose(&f_chi, &pk_r)?;
        Ok((c_l_0, c_l_1))
    }

    #[test]
    fn r_blnt_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(90001u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        // Use 2 chunks for testing.
        let num_chunks = 2;
        let chi_chunks: Vec<Integer> = vec![Integer::from(42u32), Integer::from(77u32)];

        // chi' (commitment randomness)
        let chi_prime = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };

        // Per-chunk randomness
        let mut r_chunks_witness: Vec<Integer> = Vec::new();
        for _ in 0..num_chunks {
            let (sk2, _) = setup.keygen().expect("kg");
            r_chunks_witness.push(setup.sk_to_integer(&sk2));
        }

        // Aggregated randomness
        let r_agg = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
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
        let mut setup = ClSetup::new_secp256k1(90002u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        // Single chunk.
        let chi_chunks: Vec<Integer> = vec![Integer::from(100u32)];

        let chi_prime = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };

        let r_chunks_witness: Vec<Integer> = vec![{
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        }];

        let r_agg = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
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
        let mut setup = ClSetup::new_secp256k1(90003u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");

        let chi_chunks: Vec<Integer> = vec![Integer::from(42u32), Integer::from(77u32)];

        let chi_prime = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
        };

        let r_chunks_witness: Vec<Integer> = vec![
            {
                let (sk2, _) = setup.keygen().expect("kg");
                setup.sk_to_integer(&sk2)
            },
            {
                let (sk2, _) = setup.keygen().expect("kg");
                setup.sk_to_integer(&sk2)
            },
        ];

        let r_agg = {
            let (sk2, _) = setup.keygen().expect("kg");
            setup.sk_to_integer(&sk2)
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
        let wrong_chi: Vec<Integer> = vec![Integer::from(99u32), Integer::from(77u32)];

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
