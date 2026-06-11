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

use rug::{Complete, Integer};

use crate::{
    cl::{
        Ciphertext as ClHsmqkCiphertext, ClError, ClResult, ClSetup, Mpz,
        PublicKey as ClHsmqkPublicKey, Qfi,
    },
    zk::{r_blnt::RBlntProof, r_gdec_cl::RGdecClProof, sample_random},
};

// ---- q-ary decomposition / recomposition -----------------------------------

/// Decomposes `value` into base-`q` digits: `value = sum q^l * chunks[l]`.
///
/// Each chunk is in `[0, q)`. The returned vector has at least one element.
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

/// Recomposes a value from base-`q` digits: `result = sum q^l * chunks[l]`.
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

/// Number of base-`q` digits needed to represent values up to `bound`
/// (inclusive): `ceil(log_q(bound + 1))`, but at least 1.
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

// ---- delta-scaled integer Shamir sharing -----------------------------------

/// Computes `Delta = n!`.
fn factorial(n: usize) -> Mpz {
    let mut delta = Mpz::from(1);
    for i in 2..=n {
        delta = delta * Mpz::from(i as u64);
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
fn share_magnitude_bound(sk_bound: &Mpz, n: usize, t: usize) -> Mpz {
    // poly = Delta + sum_{l=1}^{t-1} n^l, with the geometric sum in closed form
    //   sum_{l=1}^{t-1} n^l = (n^t - n) / (n - 1)   (n >= 2; the sum is 0 when
    // t <= 1). The numerator is always divisible by (n - 1) since
    // n ≡ 1 (mod n - 1), so `divexact` is exact.
    let mut poly = factorial(n); // Delta = n!
    if n >= 2 && t >= 2 {
        let n_mpz = Mpz::from(n as u64);
        let numer = &n_mpz.pow_u(t as u32) - &n_mpz; // n^t - n
        let denom = &n_mpz - &Mpz::from(1u64); // n - 1
        poly = &poly + &numer.divexact(&denom);
    }
    &poly * sk_bound
}

/// Share a secret `s` (big-endian unsigned bytes) using delta-scaled
/// integer Shamir with polynomial degree `t - 1` (reconstruction
/// threshold `t`).
///
/// Returns `n` shares as `(magnitude_bytes, is_negative)` pairs.
/// Shares are computed over the integers (unbounded), NOT mod q.
///
/// The polynomial is `F(X) = Delta * s + r_1 * X + ... + r_{t-1} * X^{t-1}`
/// where `Delta = n!`.
fn shamir_share_delta_signed(
    setup: &mut ClSetup,
    s_bytes: &[u8],
    n: usize,
    t: usize,
) -> ClResult<Vec<(Vec<u8>, bool)>> {
    let s = Mpz::from_bytes_be(s_bytes);
    let delta = factorial(n);
    let delta_s = &delta * &s;

    // Random coefficients for degree 1..t-1.
    let mut coeffs = vec![delta_s];
    for _ in 1..t {
        let r = sample_random(setup)?;
        let r_val = Mpz::from_bytes_be(&r);
        coeffs.push(r_val);
    }

    // Evaluate at X = 1, 2, ..., n.
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
    /// The secret `chi_i` (big-endian unsigned bytes).
    pub my_secret: Vec<u8>,
    /// The Pedersen blinding factor `chi'_i` (big-endian unsigned bytes).
    pub my_secret_prime: Vec<u8>,
    /// Per-recipient Shamir shares `chi_{ij}` as `(magnitude_bytes, is_negative)`.
    /// Needed for Reveal aggregation by the protocol layer.
    pub shares: Vec<(Vec<u8>, bool)>,
    /// Per-recipient blinding shares `chi'_{ij}` as `(magnitude_bytes, is_negative)`.
    pub shares_prime: Vec<(Vec<u8>, bool)>,
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

    let q_bytes = setup.q_bytes()?;
    let q = Mpz::from_bytes_be(&q_bytes);
    let sk_bound_bytes = setup.secretkey_bound_bytes()?;
    let sk_bound = Mpz::from_bytes_be(&sk_bound_bytes);
    // Size the q-ary chunk count for the SHARE magnitude, not the secret
    // bound: a delta-scaled Shamir share is far larger than `sk_bound`, so
    // sizing for `sk_bound` would silently truncate high-order chunks for
    // larger `(n, t)` and corrupt the share.
    let share_bound = share_magnitude_bound(&sk_bound, n, threshold);
    let num_chunks = num_chunks_for_bound(&share_bound, &q);

    // 1. Sample chi_i in [0, B] and chi'_i in [0, B].
    let chi_i_bytes = sample_random(setup)?;
    let chi_prime_i_bytes = sample_random(setup)?;

    // 2. Shamir share chi_i and chi'_i over Z with delta scaling.
    //    Polynomial degree = threshold - 1, reconstruction needs threshold shares.
    let shares_chi = shamir_share_delta_signed(setup, &chi_i_bytes, n, threshold)?;
    let shares_chi_prime = shamir_share_delta_signed(setup, &chi_prime_i_bytes, n, threshold)?;

    // 3. For each recipient j, produce (PC, chunk_cts, agg_ct, proof).
    let mut per_recipient = Vec::with_capacity(n);
    for j in 0..n {
        let (share_j_bytes, share_j_neg) = &shares_chi[j];
        let (share_prime_j_bytes, _share_prime_j_neg) = &shares_chi_prime[j];

        // q-ary decomposition of |chi_ij|.
        let share_j_uint = Mpz::from_bytes_be(share_j_bytes);
        let raw_chunks = decompose_q_ary(&share_j_uint, &q);

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

        // Pedersen commitment matching R_Blnt relation:
        // PC = h^{chi'_ij} * prod_l h^{q^l * chi_{ij,l}}
        let h_chi_prime = setup.power_of_h_bytes(share_prime_j_bytes)?;
        let h_q_product = compute_h_q_pow_product(setup, &q, &chi_chunk_bytes)?;
        let pc = setup.compose(&h_chi_prime, &h_q_product)?;

        // Per-chunk encryption under pk_j.
        let mut chunk_cts: Vec<(Qfi, Qfi)> = Vec::with_capacity(num_chunks);
        let mut r_chunk_bytes: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);

        for chunk_b in &chi_chunk_bytes {
            // Sample randomness for this chunk encryption.
            let r_l = sample_random(setup)?;

            // c_{l,0} = h^{r_l}
            let c_l_0 = setup.power_of_h_bytes(&r_l)?;

            // c_{l,1} = f^{chi_l} * pk_j^{r_l}
            let f_chi_l = setup.power_of_f_bytes(chunk_b)?;
            let pk_r_l = setup.pk_pow_bytes(&all_pks[j], &r_l)?;
            let c_l_1 = setup.compose(&f_chi_l, &pk_r_l)?;

            chunk_cts.push((c_l_0, c_l_1));
            r_chunk_bytes.push(r_l);
        }

        // Aggregated GEnc ciphertext: separate randomness r.
        // c_0 = h^r * prod_l h^{q^l * chi_l}
        // c_1 = pk^r * prod_l h^{q^l * chi_l}
        //
        // The "h^{q^l * chi_l}" product here uses h (the hidden-order
        // generator), matching the R_Blnt relation.
        let r_agg = sample_random(setup)?;
        let h_q_pow_product = compute_h_q_pow_product(setup, &q, &chi_chunk_bytes)?;

        let h_r_agg = setup.power_of_h_bytes(&r_agg)?;
        let c_0 = setup.compose(&h_r_agg, &h_q_pow_product)?;

        let pk_r_agg = setup.pk_pow_bytes(&all_pks[j], &r_agg)?;
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

        let _ = share_j_neg; // silence unused warning
    }

    Ok(DkgClGenOutput {
        per_recipient,
        my_secret: chi_i_bytes,
        my_secret_prime: chi_prime_i_bytes,
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
/// - `secret`: the secret to share (big-endian unsigned bytes, must be
///   within the secret key bound).
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
    // Size the q-ary chunk count for the SHARE magnitude, not the secret
    // bound (see `share_magnitude_bound`): shares are far larger than the
    // secret, so sizing for `sk_bound` would silently truncate the share.
    let share_bound = share_magnitude_bound(&sk_bound, n, threshold);
    let num_chunks = num_chunks_for_bound(&share_bound, &q);

    // Use the provided secret instead of sampling.
    let chi_i_bytes = secret.to_vec();
    let chi_prime_i_bytes = sample_random(setup)?;

    // Shamir share chi_i and chi'_i over Z with delta scaling.
    let shares_chi = shamir_share_delta_signed(setup, &chi_i_bytes, n, threshold)?;
    let shares_chi_prime = shamir_share_delta_signed(setup, &chi_prime_i_bytes, n, threshold)?;

    let mut per_recipient = Vec::with_capacity(n);
    for j in 0..n {
        let (share_j_bytes, share_j_neg) = &shares_chi[j];
        let (share_prime_j_bytes, _share_prime_j_neg) = &shares_chi_prime[j];

        let share_j_uint = Mpz::from_bytes_be(share_j_bytes);
        let raw_chunks = decompose_q_ary(&share_j_uint, &q);

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
    /// Combined secret share `x_i = sum_j chi_{ji}` (big-endian unsigned
    /// bytes, unreduced over the integers).
    pub combined_share: Vec<u8>,
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
/// - `my_sk_bytes`: this party's CL secret key (big-endian bytes).
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
    my_sk_bytes: &[u8],
    my_pk: &ClHsmqkPublicKey,
    received_chunks: &[Vec<(Qfi, Qfi)>],
    n: usize,
) -> ClResult<DkgClRevealOutput> {
    assert_eq!(received_chunks.len(), n);

    let q_bytes = setup.q_bytes()?;
    let q = Mpz::from_bytes_be(&q_bytes);

    // Import our secret key so we can decrypt.
    let sk = setup.sk_from_bytes(my_sk_bytes)?;

    // Decrypt and recombine shares from each dealer.
    let mut combined_share = Mpz::from(0);

    // Also accumulate the homomorphically-combined ciphertext for the proof.
    let mut combined_c1_bases = vec![];
    let mut combined_c2_bases = vec![];
    let mut exps = vec![];

    for dealer_chunks in received_chunks {
        // Decrypt each chunk via standard CL decryption and recombine.
        let mut dealer_share = Mpz::from(0);
        let mut q_pow = Mpz::from(1);

        for (c_l_0, c_l_1) in dealer_chunks {
            // Decrypt: m_l = dlog_in_F( c_{l,1} * (c_{l,0}^{sk})^{-1} )
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

    // Build the combined ciphertext object.
    let combined_ct = setup.ct_from_components(&combined_c1, &combined_c2)?;

    let dec_result = setup.power_of_f_bytes(&combined_share_bytes)?;

    // Prove correct decryption with R_GDec-CL.
    let proof = RGdecClProof::prove(setup, my_pk, &combined_ct, &dec_result, my_sk_bytes)?;

    Ok(DkgClRevealOutput {
        combined_share: combined_share_bytes,
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
    let dec_result = setup.power_of_f_bytes(&reveal.combined_share)?;

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

// ---- Internal helpers ------------------------------------------------------

/// Computes delta-scaled Lagrange coefficients for the given 1-based
/// party indices evaluated at x=0.
///
/// Each coefficient is `delta * prod_{j!=k} (-i_j / (i_k - i_j))`,
/// guaranteed integer because `delta = N!`.
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

/// Computes `prod_l h^{q^l * x_l}` for a list of exponents `x_l` (big-endian bytes).
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

    /// Basic smoke test: 3 parties, threshold t=2 (2-of-3).
    /// Runs Gen + GenVf + Reveal + RevealVf + Aggregate.
    #[test]
    fn dkg_cl_3_of_3_full_round() {
        let n = 3;
        let t = 2; // reconstruction threshold: 2-of-2

        let mut setup = ClSetup::new_secp256k1("50001").expect("setup");

        // Generate key pairs for all parties.
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

    /// Tests that q-ary decompose/recompose round-trips correctly.
    #[test]
    fn q_ary_roundtrip() {
        let q = Mpz::from(997u32); // small prime for testing

        for val in [0u64, 1, 42, 996, 997, 998, 1000000, u64::MAX] {
            let v = Mpz::from(val);
            let chunks = decompose_q_ary(&v, &q);
            let recomposed = recompose_q_ary(&chunks, &q);
            assert_eq!(v, recomposed, "roundtrip failed for {val}");
        }
    }

    /// Tests that decomposition produces chunks < q.
    #[test]
    fn q_ary_chunks_in_range() {
        let q = Mpz::from(256u32);
        let v = Mpz::from(123456789u64);
        let chunks = decompose_q_ary(&v, &q);
        for chunk in &chunks {
            assert!(chunk < &q, "chunk {chunk} >= q");
        }
    }

    /// Tests that num_chunks_for_bound gives the right count.
    #[test]
    fn chunk_count_correct() {
        let q = Mpz::from(10u32);
        assert_eq!(num_chunks_for_bound(&Mpz::from(0), &q), 1);
        assert_eq!(num_chunks_for_bound(&Mpz::from(9u32), &q), 1);
        assert_eq!(num_chunks_for_bound(&Mpz::from(10u32), &q), 2);
        assert_eq!(num_chunks_for_bound(&Mpz::from(99u32), &q), 2);
        assert_eq!(num_chunks_for_bound(&Mpz::from(100u32), &q), 3);
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
        let setup = ClSetup::new_secp256k1("424242").expect("setup");
        let q = Mpz::from_bytes_be(&setup.q_bytes().expect("q"));
        let b = Mpz::from_bytes_be(&setup.secretkey_bound_bytes().expect("B"));

        // `poly = Delta + sum_{l=1}^{t-1} n^l`; worst-case share = (B-1)*poly.
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

        // The reported failing case must overflow the OLD secret-sized count
        // (i.e. the bug really was a truncation at n=t=20).
        let old_chunks = num_chunks_for_bound(&b, &q);
        let worst_share_20 = &max_coeff * &poly(20, 20);
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

        let mut setup = ClSetup::new_secp256k1("50010").expect("setup");

        let mut pks = Vec::new();
        let mut sk_bytes_vec = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_bytes(&sk).expect("sk_bytes");
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
