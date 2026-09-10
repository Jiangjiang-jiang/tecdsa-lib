// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap
)]

//! DKG-CL: Distributed Key Generation over class groups.
//!
//! Implements WMC24 Figure 2 (page 7-8) as reusable round functions that
//! JTX25 and WMC24 keygen can both call.
//!
//! The secret `chi_i` is a big integer in `[0, B]` where `B` is the CL
//! secret key bound. It is decomposed into base-`q` chunks:
//! `chi_i = sum q^l * chi_{il}`. Each chunk `chi_{il} in Z_q` is
//! separately encrypted under each party's CL public key.
//!
//! # Phases
//!
//! - **Gen**: generate shares, Pedersen commitments, chunk encryptions,
//!   aggregated GEnc ciphertexts, and `R_Blnt` proofs.
//! - **GenVf**: verify received Gen messages.
//! - **Reveal**: decrypt chunks, combine shares, compute public share,
//!   prove with `R_GDec-CL`.
//! - **RevealVf**: verify Reveal messages and compute aggregate public
//!   key.

use rug::{ops::Pow, Complete, Integer};

use crate::{
    cl::{
        Ciphertext as ClHsmqkCiphertext, ClError, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey,
        Qfi,
    },
    zk::{r_blnt::RBlntProof, r_gdec_cl::RGdecClProof, sample_random},
};

// ---- q-ary decomposition / recomposition -----------------------------------

/// Decomposes `value` into base-`q` digits: `value = sum q^l * chunks[l]`.
///
/// Each chunk is in `[0, q)`. The returned vector has at least one element.
fn decompose_q_ary(value: &Integer, q: &Integer) -> Vec<Integer> {
    let mut chunks = Vec::new();
    let mut remaining = value.clone();
    while remaining > Integer::ZERO {
        let chunk;
        (remaining, chunk) = remaining.div_rem_ref(q).complete();
        chunks.push(chunk);
    }
    if chunks.is_empty() {
        chunks.push(Integer::from(0));
    }
    chunks
}

/// Recomposes a value from base-`q` digits: `result = sum q^l * chunks[l]`.
#[cfg(test)]
fn recompose_q_ary(chunks: &[Integer], q: &Integer) -> Integer {
    let mut result = Integer::from(0);
    let mut q_pow = Integer::from(1);
    for chunk in chunks {
        result += &q_pow * chunk;
        q_pow *= q;
    }
    result
}

/// Number of base-`q` digits needed to represent values up to `bound`
/// (inclusive): `ceil(log_q(bound + 1))`, but at least 1.
fn num_chunks_for_bound(bound: &Integer, q: &Integer) -> usize {
    if bound.is_zero() {
        return 1;
    }
    let mut count = 0usize;
    let mut remaining = bound.clone();
    while remaining > Integer::ZERO {
        remaining /= q;
        count += 1;
    }
    count.max(1)
}

// ---- delta-scaled integer Shamir sharing -----------------------------------

/// Computes `Delta = n!`.
fn factorial(n: usize) -> Integer {
    let mut delta = Integer::from(1);
    for i in 2..=n {
        delta *= Integer::from(i as u64);
    }
    delta
}

/// Upper bound on the magnitude of a delta-scaled Shamir share
/// `F(j) = Delta*s + r_1*j + ... + r_{t-1}*j^{t-1}` evaluated at any point
/// `j <= n`, where the shared secret `s` and the random coefficients `r_l`
/// are each strictly below `sk_bound`.
///
/// The bound is `sk_bound * (Delta + sum_{l=1}^{t-1} n^l)` with `Delta = n!`.
///
/// A share is far larger than the secret it shares — by the `Delta = n!`
/// scaling of the constant term and by the high-degree terms `r_l * j^l` — so
/// the q-ary chunk decomposition must be sized for this bound. Sizing it for
/// `sk_bound` alone silently truncates the high-order chunks for larger
/// `(n, t)` (see the `resize` in the Gen phase), corrupting the integer share
/// and breaking delta-scaled Lagrange reconstruction.
fn share_magnitude_bound(sk_bound: &Integer, n: usize, t: usize) -> Integer {
    // poly = Delta + sum_{l=1}^{t-1} n^l, with the geometric sum in closed form
    //   sum_{l=1}^{t-1} n^l = (n^t - n) / (n - 1)   (n >= 2; the sum is 0 when
    // t <= 1). The numerator is always divisible by (n - 1) since
    // n ≡ 1 (mod n - 1), so `divexact` is exact.
    let mut poly = factorial(n); // Delta = n!
    if n >= 2 && t >= 2 {
        let n_mpz = Integer::from(n as u64);
        let numer = n_mpz.clone().pow(t as u32) - &n_mpz; // n^t - n
        let denom = &n_mpz - Integer::from(1u64); // n - 1
        poly = &poly + numer.div_exact(&denom);
    }
    poly * sk_bound
}

/// Share a secret `s` using delta-scaled integer Shamir with polynomial
/// degree `t - 1` (reconstruction threshold `t`).
///
/// Returns `n` signed shares. Shares are computed over the integers
/// (unbounded), NOT mod q.
///
/// The polynomial is `F(X) = Delta * s + r_1 * X + ... + r_{t-1} * X^{t-1}`
/// where `Delta = n!`.
fn shamir_share_delta_signed(
    setup: &mut ClSetup,
    s: &Integer,
    n: usize,
    t: usize,
) -> ClResult<Vec<Integer>> {
    let delta = factorial(n);
    let delta_s = delta * s;

    // Random coefficients for degree 1..t-1.
    let mut coeffs = vec![delta_s];
    for _ in 1..t {
        coeffs.push(sample_random(setup)?);
    }

    // Evaluate at X = 1, 2, ..., n.
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = Integer::from(i as i64);
        let mut val = Integer::from(0);
        let mut x_pow = Integer::from(1);
        for coeff in &coeffs {
            val += (coeff * &x_pow).complete();
            x_pow *= &x;
        }
        shares.push(val);
    }

    Ok(shares)
}

// ---- Per-recipient Gen data ------------------------------------------------

/// Per-recipient data produced during the Gen phase.
pub struct DkgClGenPerRecipient {
    /// Pedersen commitment `PC = h^{chi_ij} * g_q^{chi'_ij * Delta}`.
    pub pc: Qfi,
    /// Per-chunk ciphertexts `(c_{l,0}, c_{l,1})` for each base-q digit.
    pub chunk_cts: Vec<(Qfi, Qfi)>,
    /// Aggregated GEnc ciphertext `(c_0, c_1)`.
    pub agg_ct: (Qfi, Qfi),
    /// `R_Blnt` proof.
    pub proof: RBlntProof,
}

/// Output of the Gen phase for one party.
pub struct DkgClGenOutput {
    /// Per-recipient data indexed by recipient (0-based, same order as
    /// `all_pks`).
    pub per_recipient: Vec<DkgClGenPerRecipient>,
    /// The secret `chi_i`.
    pub my_secret: Integer,
    /// The Pedersen blinding factor `chi'_i`.
    pub my_secret_prime: Integer,
    /// Per-recipient Shamir shares `chi_{ij}` (signed).
    /// Needed for Reveal aggregation by the protocol layer.
    pub shares: Vec<Integer>,
    /// Per-recipient blinding shares `chi'_{ij}` (signed).
    pub shares_prime: Vec<Integer>,
}

/// Runs the DKG-CL Gen phase for one party.
///
/// # Arguments
///
/// - `setup`: mutable reference to `ClSetup` (provides PRNG and CL operations).
/// - `all_pks`: public keys `{ek_j}` of all `n` parties.
/// - `n`: total number of parties.
/// - `threshold`: reconstruction threshold (`threshold` shares needed to
///   reconstruct). Polynomial degree = `threshold - 1`.
/// - `my_index`: 0-based index of this party.
///
/// # Returns
///
/// The Gen output containing per-recipient commitments, encryptions, and proofs.
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

    let q = setup.cl().q().clone();
    let sk_bound = setup.secretkey_bound().clone();
    // Size the q-ary chunk count for the SHARE magnitude, not the secret
    // bound: a delta-scaled Shamir share is far larger than `sk_bound`, so
    // sizing for `sk_bound` would silently truncate high-order chunks for
    // larger `(n, t)` and corrupt the share.
    let share_bound = share_magnitude_bound(&sk_bound, n, threshold);
    let num_chunks = num_chunks_for_bound(&share_bound, &q);

    // 1. Sample chi_i in [0, B] and chi'_i in [0, B].
    let chi_i = sample_random(setup)?;
    let chi_prime_i = sample_random(setup)?;

    // 2. Shamir share chi_i and chi'_i over Z with delta scaling.
    //    Polynomial degree = threshold - 1, reconstruction needs threshold shares.
    let shares_chi = shamir_share_delta_signed(setup, &chi_i, n, threshold)?;
    let shares_chi_prime = shamir_share_delta_signed(setup, &chi_prime_i, n, threshold)?;

    // 3. For each recipient j, produce (PC, chunk_cts, agg_ct, proof).
    let mut per_recipient = Vec::with_capacity(n);
    for j in 0..n {
        let share_j = &shares_chi[j];
        let share_prime_j = &shares_chi_prime[j];

        // q-ary decomposition of |chi_ij|.
        let raw_chunks = decompose_q_ary(&share_j.clone().abs(), &q);

        // Pad to exactly num_chunks. `num_chunks` is sized (via
        // `share_magnitude_bound`) so the share always fits; never truncate.
        let mut chi_chunks = raw_chunks;
        if chi_chunks.len() > num_chunks {
            return Err(ClError::InvalidParam(format!(
                "DKG-CL share needs {} q-ary chunks but only {num_chunks} were \
                 allocated (n={n}, t={threshold}); refusing to truncate the share",
                chi_chunks.len()
            )));
        }
        chi_chunks.resize(num_chunks, Integer::from(0));

        // Pedersen commitment matching R_Blnt relation:
        // PC = h^{chi'_ij} * prod_l h^{q^l * chi_{ij,l}}
        let h_chi_prime = setup.power_of_h(share_prime_j)?;
        let h_q_product = compute_h_q_pow_product(setup, &q, &chi_chunks)?;
        let pc = setup.compose(&h_chi_prime, &h_q_product)?;

        // Per-chunk encryption under pk_j.
        let mut chunk_cts: Vec<(Qfi, Qfi)> = Vec::with_capacity(num_chunks);
        let mut r_chunks: Vec<Integer> = Vec::with_capacity(num_chunks);

        for chunk in &chi_chunks {
            // Sample randomness for this chunk encryption.
            let r_l = sample_random(setup)?;

            // c_{l,0} = h^{r_l}
            let c_l_0 = setup.power_of_h(&r_l)?;

            // c_{l,1} = f^{chi_l} * pk_j^{r_l}
            let f_chi_l = setup.power_of_f(chunk)?;
            let pk_r_l = setup.pk_pow(&all_pks[j], &r_l)?;
            let c_l_1 = setup.compose(&f_chi_l, &pk_r_l)?;

            chunk_cts.push((c_l_0, c_l_1));
            r_chunks.push(r_l);
        }

        // Aggregated GEnc ciphertext: separate randomness r.
        // c_0 = h^r * prod_l h^{q^l * chi_l}
        // c_1 = pk^r * prod_l h^{q^l * chi_l}
        //
        // The "h^{q^l * chi_l}" product here uses h (the hidden-order
        // generator), matching the R_Blnt relation.
        let r_agg = sample_random(setup)?;
        let h_q_pow_product = compute_h_q_pow_product(setup, &q, &chi_chunks)?;

        let h_r_agg = setup.power_of_h(&r_agg)?;
        let c_0 = setup.compose(&h_r_agg, &h_q_pow_product)?;

        let pk_r_agg = setup.pk_pow(&all_pks[j], &r_agg)?;
        let c_1 = setup.compose(&pk_r_agg, &h_q_pow_product)?;

        let agg_ct = (c_0, c_1);

        // R_Blnt proof binding PC, chunk_cts, agg_ct to the witnesses.
        //
        // The proof's Pedersen commitment uses `h^{chi'} * prod h^{q^l chi_l}`
        // (the R_Blnt "PC" is NOT the same as our pedersen_commit_cl PC above
        // in general, but the relation binds the same chunks). We build the
        // R_Blnt statement elements matching the proof's internal check.
        let proof = RBlntProof::prove(
            setup,
            &all_pks[j],
            &pc,
            &chunk_cts,
            &agg_ct,
            &chi_chunks,
            share_prime_j,
            &r_chunks,
            &r_agg,
        )?;

        per_recipient.push(DkgClGenPerRecipient {
            pc,
            chunk_cts,
            agg_ct,
            proof,
        });
    }

    Ok(DkgClGenOutput {
        per_recipient,
        my_secret: chi_i,
        my_secret_prime: chi_prime_i,
        shares: shares_chi,
        shares_prime: shares_chi_prime,
    })
}

/// Variant of [`dkg_cl_gen`] that shares an externally-provided secret
/// instead of sampling a fresh one.
///
/// This is used by JTX25 where each party shares their existing CL
/// secret key (so the aggregate matches the composed public key).
///
/// # Arguments
///
/// Same as [`dkg_cl_gen`], plus:
/// - `secret`: the secret to share, must be within the secret key bound.
pub fn dkg_cl_gen_with_secret(
    setup: &mut ClSetup,
    all_pks: &[ClHsmqkPublicKey],
    n: usize,
    threshold: usize,
    my_index: usize,
    secret: &Integer,
) -> ClResult<DkgClGenOutput> {
    assert_eq!(all_pks.len(), n);
    assert!(my_index < n);
    assert!(threshold > 0 && threshold <= n);

    let q = setup.cl().q().clone();
    let sk_bound = setup.secretkey_bound().clone();
    // Size the q-ary chunk count for the SHARE magnitude, not the secret
    // bound (see `share_magnitude_bound`): shares are far larger than the
    // secret, so sizing for `sk_bound` would silently truncate the share.
    let share_bound = share_magnitude_bound(&sk_bound, n, threshold);
    let num_chunks = num_chunks_for_bound(&share_bound, &q);

    // Use the provided secret instead of sampling.
    let chi_i = secret.clone();
    let chi_prime_i = sample_random(setup)?;

    // Shamir share chi_i and chi'_i over Z with delta scaling.
    let shares_chi = shamir_share_delta_signed(setup, &chi_i, n, threshold)?;
    let shares_chi_prime = shamir_share_delta_signed(setup, &chi_prime_i, n, threshold)?;

    let mut per_recipient = Vec::with_capacity(n);
    for j in 0..n {
        let share_j = &shares_chi[j];
        let share_prime_j = &shares_chi_prime[j];

        let raw_chunks = decompose_q_ary(&share_j.clone().abs(), &q);

        // `num_chunks` is sized via `share_magnitude_bound` so the share
        // always fits; never truncate (that would corrupt the share).
        let mut chi_chunks = raw_chunks;
        if chi_chunks.len() > num_chunks {
            return Err(ClError::InvalidParam(format!(
                "DKG-CL share needs {} q-ary chunks but only {num_chunks} were \
                 allocated (n={n}, t={threshold}); refusing to truncate the share",
                chi_chunks.len()
            )));
        }
        chi_chunks.resize(num_chunks, Integer::from(0));

        let h_chi_prime = setup.power_of_h(share_prime_j)?;
        let h_q_product = compute_h_q_pow_product(setup, &q, &chi_chunks)?;
        let pc = setup.compose(&h_chi_prime, &h_q_product)?;

        let mut chunk_cts: Vec<(Qfi, Qfi)> = Vec::with_capacity(num_chunks);
        let mut r_chunks: Vec<Integer> = Vec::with_capacity(num_chunks);

        for chunk in &chi_chunks {
            let r_l = sample_random(setup)?;
            let c_l_0 = setup.power_of_h(&r_l)?;
            let f_chi_l = setup.power_of_f(chunk)?;
            let pk_r_l = setup.pk_pow(&all_pks[j], &r_l)?;
            let c_l_1 = setup.compose(&f_chi_l, &pk_r_l)?;
            chunk_cts.push((c_l_0, c_l_1));
            r_chunks.push(r_l);
        }

        let r_agg = sample_random(setup)?;
        let h_q_pow_product = compute_h_q_pow_product(setup, &q, &chi_chunks)?;
        let h_r_agg = setup.power_of_h(&r_agg)?;
        let c_0 = setup.compose(&h_r_agg, &h_q_pow_product)?;
        let pk_r_agg = setup.pk_pow(&all_pks[j], &r_agg)?;
        let c_1 = setup.compose(&pk_r_agg, &h_q_pow_product)?;
        let agg_ct = (c_0, c_1);

        let proof = RBlntProof::prove(
            setup,
            &all_pks[j],
            &pc,
            &chunk_cts,
            &agg_ct,
            &chi_chunks,
            share_prime_j,
            &r_chunks,
            &r_agg,
        )?;

        per_recipient.push(DkgClGenPerRecipient {
            pc,
            chunk_cts,
            agg_ct,
            proof,
        });
    }

    Ok(DkgClGenOutput {
        per_recipient,
        my_secret: chi_i,
        my_secret_prime: chi_prime_i,
        shares: shares_chi,
        shares_prime: shares_chi_prime,
    })
}

/// Verifies the Gen phase output from one dealer addressed to us.
///
/// This checks the `R_Blnt` proof for the per-recipient bundle.
///
/// # Arguments
///
/// - `setup`: reference to CL-HSMqk setup.
/// - `dealer_output`: the dealer's per-recipient data for us.
/// - `dealer_pk`: the dealer's public key (for proof context binding).
/// - `my_pk`: our public key (the recipient's `ek`).
///
/// # Returns
///
/// `true` if the proof verifies, `false` otherwise.
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

// ---- Reveal phase ----------------------------------------------------------

/// Output of the Reveal phase for one party.
pub struct DkgClRevealOutput {
    /// Combined secret share `x_i = sum_j chi_{ji}`, unreduced over the
    /// integers.
    pub combined_share: Integer,
    /// Public CL share `h^{x_i}` for the combined integer share.
    pub pk_share: Qfi,
    /// `R_GDec-CL` proof attesting correct decryption.
    pub proof: RGdecClProof,
    /// The homomorphically-combined ciphertext `c_{x_i}` (for verifiers).
    pub combined_ct: ClHsmqkCiphertext,
}

/// Runs the DKG-CL Reveal phase for one party.
///
/// Each party decrypts the chunk ciphertexts received from all dealers,
/// recombines the base-`q` digits, sums the shares, computes the public
/// share, and proves correctness.
///
/// # Arguments
///
/// - `setup`: mutable reference to `ClSetup`.
/// - `my_sk`: this party's CL secret key.
/// - `my_pk`: this party's CL public key.
/// - `received_chunks`: for each dealer `j`, the chunk ciphertexts
///   `{(c_{l,0}, c_{l,1})}_l` addressed to this party.
/// - `n`: total number of parties.
///
/// # Returns
///
/// The Reveal output containing the combined share, public share, proof, and
/// combined ciphertext.
pub fn dkg_cl_reveal(
    setup: &mut ClSetup,
    my_sk: &Integer,
    my_pk: &ClHsmqkPublicKey,
    received_chunks: &[Vec<(Qfi, Qfi)>],
    n: usize,
) -> ClResult<DkgClRevealOutput> {
    assert_eq!(received_chunks.len(), n);

    let q = setup.cl().q().clone();

    // Import our secret key so we can decrypt.
    let sk = setup.sk_from_integer(my_sk)?;

    // Decrypt and recombine shares from each dealer.
    let mut combined_share = Integer::from(0);

    // Also accumulate the homomorphically-combined ciphertext for the proof.
    let mut combined_c1_bases = vec![];
    let mut combined_c2_bases = vec![];
    let mut exps: Vec<Integer> = vec![];

    for dealer_chunks in received_chunks {
        // Decrypt each chunk via standard CL decryption and recombine.
        let mut dealer_share = Integer::from(0);
        let mut q_pow = Integer::from(1);

        for (c_l_0, c_l_1) in dealer_chunks {
            // Decrypt: m_l = dlog_in_F( c_{l,1} * (c_{l,0}^{sk})^{-1} )
            let ct_l = setup.ct_from_components(c_l_0, c_l_1)?;
            let m_l = setup.decrypt(&sk, &ct_l)?;

            dealer_share += &q_pow * &m_l;
            combined_c1_bases.push(c_l_0);
            combined_c2_bases.push(c_l_1);
            exps.push(q_pow.clone());

            q_pow *= &q;
        }

        combined_share += dealer_share;
    }
    let combined_c1 = setup.multiexp(&combined_c1_bases, &exps)?;
    let combined_c2 = setup.multiexp(&combined_c2_bases, &exps)?;

    let pk_share = setup.power_of_h(&combined_share)?;

    // Build the combined ciphertext object.
    let combined_ct = setup.ct_from_components(&combined_c1, &combined_c2)?;

    let dec_result = setup.power_of_f(&combined_share)?;

    // Prove correct decryption with R_GDec-CL.
    let proof = RGdecClProof::prove(setup, my_pk, &combined_ct, &dec_result, my_sk)?;

    Ok(DkgClRevealOutput {
        combined_share,
        pk_share,
        proof,
        combined_ct,
    })
}

/// Verifies the Reveal phase output from one party.
///
/// Checks the `R_GDec-CL` proof attesting that the combined share is
/// consistent with the homomorphically-combined ciphertext.
///
/// # Arguments
///
/// - `setup`: reference to CL-HSMqk setup.
/// - `reveal`: the party's Reveal output.
/// - `party_pk`: the party's CL public key.
///
/// # Returns
///
/// `true` if the proof verifies, `false` otherwise.
pub fn dkg_cl_reveal_verify(
    setup: &ClSetup,
    reveal: &DkgClRevealOutput,
    party_pk: &ClHsmqkPublicKey,
) -> ClResult<bool> {
    // The R_GDec-CL proof attests correct generalized decryption:
    // D = c2 * (c1^sk)^{-1} = f^{combined_share}.
    // The verifier reconstructs D from the combined_share provided by the
    // prover, then checks the proof against (pk, ct, D).
    let dec_result = setup.power_of_f(&reveal.combined_share)?;

    reveal
        .proof
        .verify(setup, party_pk, &reveal.combined_ct, &dec_result)
}

/// Computes the aggregate public key from all parties' public shares.
///
/// The aggregate is `agg = prod_i lift_i^{Delta * L_{i,P}}` where
/// `L_{i,P}` are the delta-scaled Lagrange coefficients at evaluation
/// point 0 for the set of party indices `P`.
///
/// # Arguments
///
/// - `setup`: reference to CL-HSMqk setup.
/// - `public_shares`: the public share elements from each party's Reveal.
/// - `party_indices`: 1-based indices of the parties.
/// - `n_total`: total number of parties (for computing `Delta = n!`).
///
/// # Returns
///
/// The aggregate class-group element representing the shared public key.
pub fn dkg_cl_aggregate(
    setup: &ClSetup,
    public_shares: &[Qfi],
    party_indices: &[usize],
    n_total: usize,
) -> ClResult<Qfi> {
    assert_eq!(public_shares.len(), party_indices.len());

    let delta = factorial(n_total);
    let coeffs = lagrange_coefficients_delta(party_indices, &delta);

    // aggregate = product(share_i^{lambda_i}) via one shared-squaring multi-exp
    // (lambda_i are signed delta-scaled Lagrange coefficients).
    let mut bases: Vec<&Qfi> = Vec::with_capacity(coeffs.len());
    let mut exps: Vec<Integer> = Vec::with_capacity(coeffs.len());
    for (idx, lambda) in &coeffs {
        let share_pos = party_indices
            .iter()
            .position(|&i| i == *idx)
            .expect("index mismatch");
        bases.push(&public_shares[share_pos]);
        exps.push(lambda.clone());
    }
    let aggregate = setup.multiexp(&bases, &exps)?;

    Ok(aggregate)
}

// ---- Internal helpers ------------------------------------------------------

/// Computes delta-scaled Lagrange coefficients for the given 1-based
/// party indices evaluated at x=0.
///
/// Each coefficient is `delta * prod_{j!=k} (-i_j / (i_k - i_j))`,
/// guaranteed integer because `delta = N!`.
fn lagrange_coefficients_delta(indices: &[usize], delta: &Integer) -> Vec<(usize, Integer)> {
    let mut result = Vec::with_capacity(indices.len());
    for (k, &i_k) in indices.iter().enumerate() {
        let mut coeff = delta.clone();

        for (j, &i_j) in indices.iter().enumerate() {
            if j == k {
                continue;
            }
            coeff /= i_k as i64 - i_j as i64;
            coeff *= -(i_j as i64);
        }

        result.push((i_k, coeff));
    }
    result
}

/// Computes `prod_l h^{q^l * x_l}` for a list of exponents `x_l`.
///
/// Shared with [`crate::zk::r_blnt`], whose `R_Blnt` relation uses the same
/// product over the commitment/proof randomness.
pub(crate) fn compute_h_q_pow_product(
    setup: &ClSetup,
    q: &Integer,
    exponents: &[Integer],
) -> ClResult<Qfi> {
    let mut product = setup.identity()?;
    let mut q_pow_l = Integer::from(1);

    for x_l in exponents {
        let exp = (&q_pow_l * x_l).complete();

        if !exp.is_zero() {
            let h_exp = setup.power_of_h(&exp)?;
            product = setup.compose(&product, &h_exp)?;
        }

        q_pow_l *= q;
    }

    Ok(product)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Basic smoke test: 3 parties, threshold t=2 (2-of-3).
    /// Runs Gen + GenVf + Reveal + RevealVf + Aggregate.
    #[test]
    fn dkg_cl_3_of_3_full_round() {
        let n = 3;
        let t = 2; // reconstruction threshold: 2-of-2

        let mut setup = ClSetup::new_secp256k1(50001u64).expect("setup");

        // Generate key pairs for all parties.
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        let mut sk_bytes_vec = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_integer(&sk);
            sks.push(sk);
            pks.push(pk);
            sk_bytes_vec.push(sk_bytes);
        }

        // === Gen phase ===
        let mut gen_outputs = Vec::new();
        for i in 0..n {
            let output = dkg_cl_gen(&mut setup, &pks, n, t, i).expect("gen");
            gen_outputs.push(output);
        }

        // === GenVf phase ===
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

        // === Reveal phase ===
        let mut reveal_outputs = Vec::new();
        for i in 0..n {
            // Collect chunk ciphertexts addressed to party i from all dealers.
            let received: Vec<Vec<(Qfi, Qfi)>> = (0..n)
                .map(|dealer| gen_outputs[dealer].per_recipient[i].chunk_cts.clone())
                .collect();

            let reveal =
                dkg_cl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &received, n).expect("reveal");
            reveal_outputs.push(reveal);
        }

        // === RevealVf phase ===
        for i in 0..n {
            let ok =
                dkg_cl_reveal_verify(&setup, &reveal_outputs[i], &pks[i]).expect("reveal_verify");
            assert!(ok, "RevealVf failed for party={i}");
        }

        // === Aggregate ===
        let public_shares: Vec<Qfi> = reveal_outputs.iter().map(|r| r.pk_share.clone()).collect();
        let party_indices: Vec<usize> = (1..=n).collect();

        let agg = dkg_cl_aggregate(&setup, &public_shares, &party_indices, n).expect("aggregate");

        // The aggregate should be non-trivial (not the identity).
        let identity = setup.identity().expect("identity");
        assert_ne!(agg, identity, "aggregate should not be the identity");
    }

    /// 128-bit parameters use multiple q-ary chunks; RevealVf must prove the
    /// recomposed `sum q^l * chunk_l` share, not the unweighted sum of digits.
    #[test]
    fn dkg_cl_128bit_multi_chunk_full_round() {
        let n = 3;
        let t = 2; // reconstruction threshold: 2-of-2

        let mut setup = ClSetup::new_secp256k1_128bit(42042u64).expect("setup");

        let mut pks = Vec::new();
        let mut sk_bytes_vec = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_integer(&sk);
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

    /// Tests that q-ary decompose/recompose round-trips correctly.
    #[test]
    fn q_ary_roundtrip() {
        let q = Integer::from(997u32); // small prime for testing

        for val in [0u64, 1, 42, 996, 997, 998, 1000000, u64::MAX] {
            let v = Integer::from(val);
            let chunks = decompose_q_ary(&v, &q);
            let recomposed = recompose_q_ary(&chunks, &q);
            assert_eq!(v, recomposed, "roundtrip failed for {val}");
        }
    }

    /// Tests that decomposition produces chunks < q.
    #[test]
    fn q_ary_chunks_in_range() {
        let q = Integer::from(256u32);
        let v = Integer::from(123456789u64);
        let chunks = decompose_q_ary(&v, &q);
        for chunk in &chunks {
            assert!(chunk < &q, "chunk {chunk} >= q");
        }
    }

    /// Tests that num_chunks_for_bound gives the right count.
    #[test]
    fn chunk_count_correct() {
        let q = Integer::from(10u32);
        assert_eq!(num_chunks_for_bound(&Integer::from(0), &q), 1);
        assert_eq!(num_chunks_for_bound(&Integer::from(9u32), &q), 1);
        assert_eq!(num_chunks_for_bound(&Integer::from(10u32), &q), 2);
        assert_eq!(num_chunks_for_bound(&Integer::from(99u32), &q), 2);
        assert_eq!(num_chunks_for_bound(&Integer::from(100u32), &q), 3);
    }

    /// Regression for the WMC24 `n = t = 20` failure ("ECDSA verification
    /// failed after signature assembly").
    ///
    /// A delta-scaled Shamir share `F(j) = Delta*chi + sum r_l*j^l`
    /// (`Delta = n!`) is far larger than the secret `chi`. The chunk count was
    /// sized for the secret bound, so for larger `(n, t)` the high-order q-ary
    /// chunks were silently dropped by `resize`, corrupting the share and
    /// breaking Lagrange reconstruction. This checks the share-magnitude bound
    /// is large enough to hold the worst-case share without truncation, and
    /// that the old (secret-sized) count would indeed have truncated at n=t=20.
    #[test]
    fn share_chunks_not_truncated_for_large_n() {
        let setup = ClSetup::new_secp256k1(424_242u64).expect("setup");
        let q = setup.cl().q().clone();
        let b = setup.secretkey_bound().clone();

        // `poly = Delta + sum_{l=1}^{t-1} n^l`; worst-case share = (B-1)*poly.
        let poly = |n: usize, t: usize| -> Integer {
            let n_mpz = Integer::from(n as u64);
            let mut acc = factorial(n);
            let mut n_pow = Integer::from(1u64);
            for _ in 1..t {
                n_pow *= &n_mpz;
                acc += &n_pow;
            }
            acc
        };
        let max_coeff = &b - Integer::from(1u64);

        for &(n, t) in &[(2usize, 2usize), (5, 5), (10, 10), (20, 20)] {
            let new_chunks = num_chunks_for_bound(&share_magnitude_bound(&b, n, t), &q);
            let worst_share = &max_coeff * poly(n, t);
            let needed = decompose_q_ary(&worst_share, &q).len();
            assert!(
                needed <= new_chunks,
                "n={n},t={t}: worst-case share needs {needed} chunks but \
                 share-magnitude bound only allots {new_chunks}",
            );
        }

        // The reported failing case must overflow the OLD secret-sized count
        // (i.e. the bug really was a truncation at n=t=20).
        let old_chunks = num_chunks_for_bound(&b, &q);
        let worst_share_20 = max_coeff * &poly(20, 20);
        assert!(
            decompose_q_ary(&worst_share_20, &q).len() > old_chunks,
            "n=t=20 share should overflow the old secret-sized chunk count",
        );
    }

    /// Tests the 2-party degenerate case.
    #[test]
    fn dkg_cl_2_of_2() {
        let n = 2;
        let t = 2; // reconstruction threshold: 2-of-2

        let mut setup = ClSetup::new_secp256k1(50010u64).expect("setup");

        let mut pks = Vec::new();
        let mut sk_bytes_vec = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_integer(&sk);
            pks.push(pk);
            sk_bytes_vec.push(sk_bytes);
        }

        // Gen
        let mut gen_outputs = Vec::new();
        for i in 0..n {
            gen_outputs.push(dkg_cl_gen(&mut setup, &pks, n, t, i).expect("gen"));
        }

        // GenVf
        for d in 0..n {
            for r in 0..n {
                assert!(
                    dkg_cl_gen_verify(&setup, &gen_outputs[d].per_recipient[r], &pks[d], &pks[r])
                        .expect("verify"),
                    "GenVf failed d={d} r={r}"
                );
            }
        }

        // Reveal
        let mut reveals = Vec::new();
        for i in 0..n {
            let received: Vec<Vec<(Qfi, Qfi)>> = (0..n)
                .map(|d| gen_outputs[d].per_recipient[i].chunk_cts.clone())
                .collect();
            reveals.push(
                dkg_cl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &received, n).expect("reveal"),
            );
        }

        // RevealVf
        for i in 0..n {
            assert!(
                dkg_cl_reveal_verify(&setup, &reveals[i], &pks[i]).expect("verify"),
                "RevealVf failed i={i}"
            );
        }

        // Aggregate
        let public_shares: Vec<Qfi> = reveals.iter().map(|r| r.pk_share.clone()).collect();
        let indices: Vec<usize> = (1..=n).collect();
        let agg = dkg_cl_aggregate(&setup, &public_shares, &indices, n).expect("aggregate");
        let id = setup.identity().expect("id");
        assert_ne!(agg, id);
    }
}
