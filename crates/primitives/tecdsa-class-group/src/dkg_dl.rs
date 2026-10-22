// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::needless_range_loop
)]

//! DKG-DL: Distributed Key Generation for discrete-log keys (ElGamal).
//!
//! Implements WMC24 Figure 1 (page 7) as reusable round functions that
//! WMC24 keygen can call for generating threshold ElGamal key shares.
//!
//! Each party `i` holds a secret `chi_i in F_q` (ElGamal decryption key
//! share). The protocol produces threshold Shamir shares of `x = sum chi_j`
//! with public key `X = g^x`.
//!
//! # Differences from DKG-CL
//!
//! - Secrets are in `F_q` (not big integers): standard Shamir, not Z-SS.
//! - Pedersen commitments are EC-based (`g^a * h^b`), not class-group.
//! - Share encryption uses standard `CL.Enc`, not GEnc with q-ary decomposition.
//! - No `R_Blnt` needed: uses `R_Enc-PC` instead.
//! - Reveal uses `R_Dec-DL` (not `R_GDec-CL`).
//!
//! # Phases
//!
//! - **Gen**: generate shares, EC Pedersen commitments, CL-encrypt each share
//!   under the recipient's key, prove `R_Enc-PC`.
//! - **GenVf**: verify Pedersen VSS shares and `R_Enc-PC` proofs.
//! - **Reveal**: decrypt shares, combine, compute public share `X_i = g^{x_i}`,
//!   prove `R_Dec-DL`.
//! - **RevealVf**: verify `R_Dec-DL` proof.
//! - **Aggregate**: compute aggregate public key via Lagrange interpolation.

use elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use rand_core::CryptoRngCore;
use rug::Integer;
use tecdsa_curve::{ScalarExt, TecdsaCurve};

// ---------------------------------------------------------------------------
// Pedersen VSS: shared with `drg.rs` (`dkg_dl` reuses the same pattern).
// ---------------------------------------------------------------------------
/// A Pedersen VSS share for DKG-DL: index, value share, and randomness share.
pub use crate::drg::PedersenVssShare as DkgDlPedersenShare;
use crate::{
    cl::{Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey},
    drg::{pedersen_vss_share, pedersen_vss_verify},
    zk::{r_dec_dl::RDecDlProof, r_enc_pc::REncPcProof},
};

// ---------------------------------------------------------------------------
// Gen phase types
// ---------------------------------------------------------------------------

/// Per-recipient data produced during the DKG-DL Gen phase.
pub struct DkgDlGenPerRecipient {
    /// EC Pedersen commitment: `PC = g^{chi_ij} * h^{chi'_ij}`.
    ///
    /// This is the evaluation of the commitment polynomial at the recipient's
    /// index, equivalent to `prod F_d^{j^d}`.
    pub pc: k256::ProjectivePoint,
    /// CL ciphertext of `chi_ij` under `ek_j`.
    pub ct: ClHsmqkCiphertext,
    /// `R_Enc-PC` proof: cross-domain proof linking CL ciphertext plaintext
    /// to the EC Pedersen commitment `PC`.
    pub proof: REncPcProof,
}

/// Output of the DKG-DL Gen phase for one party.
pub struct DkgDlGenOutput {
    /// Per-recipient data indexed by recipient (0-based).
    pub per_recipient: Vec<DkgDlGenPerRecipient>,
    /// Pedersen VSS polynomial commitments `{F_d}` for `d = 0..t-1`.
    pub commitments: Vec<k256::ProjectivePoint>,
    /// The secret `chi_i` sampled by this party.
    pub my_secret: k256::Scalar,
    /// The randomness `chi'_i` (Pedersen blinding constant term).
    pub my_secret_prime: k256::Scalar,
    /// Shamir value shares `{chi_{ij}}_j` for each recipient.
    pub my_shares: Vec<k256::Scalar>,
    /// Pedersen randomness shares `{chi'_{ij}}_j` for each recipient.
    pub my_shares_prime: Vec<k256::Scalar>,
}

// ---------------------------------------------------------------------------
// Gen phase
// ---------------------------------------------------------------------------

/// Runs the DKG-DL Gen phase for one party (WMC24 Figure 1, Gen).
///
/// Each party `i`:
/// 1. Samples `chi_i` from `Z_q` and creates Pedersen VSS shares.
/// 2. For each recipient `j`, encrypts `chi_{ij}` under `ek_j` and proves
///    `R_Enc-PC`.
///
/// # Arguments
///
/// - `setup`: mutable CL setup (provides PRNG and CL operations).
/// - `all_pks`: CL public keys `{ek_j}` of all `n` parties.
/// - `n`: total number of parties.
/// - `threshold`: reconstruction threshold (`threshold` shares needed).
///   Polynomial degree = `threshold - 1`.
/// - `my_index`: 0-based index of this party.
/// - `rng`: cryptographic RNG for EC operations.
///
/// # Returns
///
/// The Gen output containing per-recipient commitments, ciphertexts, and proofs.
pub fn dkg_dl_gen(
    setup: &mut ClSetup,
    all_pks: &[ClHsmqkPublicKey],
    n: usize,
    threshold: usize,
    my_index: usize,
    rng: &mut impl CryptoRngCore,
) -> ClResult<DkgDlGenOutput> {
    assert_eq!(all_pks.len(), n);
    assert!(my_index < n);
    assert!(threshold > 0 && threshold <= n);

    // Step 1: Sample chi_i and create Pedersen VSS.
    // Polynomial degree = threshold - 1, reconstruction needs threshold shares.
    let chi_i = k256::Secp256k1::random_scalar(rng);
    let vss = pedersen_vss_share(&chi_i, threshold as u16, n as u16, rng);

    // Step 2: For each recipient j, encrypt share and prove.
    let mut per_recipient = Vec::with_capacity(n);
    let mut share_values = Vec::with_capacity(n);
    let mut share_randomness = Vec::with_capacity(n);

    for j in 0..n {
        let share = &vss.shares[j];
        let chi_ij = share.value;
        let chi_prime_ij = share.randomness;
        let chi_ij_int = chi_ij.to_integer();

        // EC Pedersen commitment: PC = g^{chi_ij} * h^{chi'_ij}
        // This equals evaluating the commitment polynomial at j's index.
        let g = <k256::Secp256k1 as TecdsaCurve>::generator();
        let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();
        let pc = g * chi_ij + h * chi_prime_ij;

        // CL encrypt chi_ij under ek_j with explicit randomness.
        let pk_j = &all_pks[j];
        let (r_sk, _) = setup.keygen()?;
        let r = setup.sk_to_integer(&r_sk);
        let ct = setup.encrypt_with_r(pk_j, &chi_ij_int, &r)?;

        // R_Enc-PC proof (cross-domain): proves ct encrypts chi_ij AND
        // PC = g^{chi_ij} * h^{chi'_ij} uses the same chi_ij.
        let chi_prime_ij_int = chi_prime_ij.to_integer();
        let proof = REncPcProof::prove(setup, pk_j, &ct, &pc, &chi_ij_int, &chi_prime_ij_int, &r)?;

        per_recipient.push(DkgDlGenPerRecipient { pc, ct, proof });
        share_values.push(chi_ij);
        share_randomness.push(chi_prime_ij);
    }

    Ok(DkgDlGenOutput {
        per_recipient,
        commitments: vss.commitments,
        my_secret: vss.secret,
        my_secret_prime: vss.secret_randomness,
        my_shares: share_values,
        my_shares_prime: share_randomness,
    })
}

// ---------------------------------------------------------------------------
// GenVf phase
// ---------------------------------------------------------------------------

/// Verifies one dealer's Gen output for a specific recipient (WMC24 Figure 1, GenVf).
///
/// Checks:
/// 1. Pedersen VSS share consistency: `PC == g^{value} * h^{randomness}`
///    evaluated from the commitment polynomial.
/// 2. `R_Enc-PC` proof verification.
///
/// # Arguments
///
/// - `setup`: CL setup reference.
/// - `per_recipient`: the dealer's per-recipient data for us.
/// - `commitments`: the dealer's Pedersen VSS polynomial commitments.
/// - `dealer_pk`: the dealer's CL public key (the `ek` under which the
///   ciphertext was encrypted -- actually this is the *recipient's* pk).
/// - `recipient_pk`: the recipient's CL public key (encryption target).
/// - `my_share`: the Pedersen VSS share designated for this recipient.
///
/// # Returns
///
/// `true` if both checks pass.
pub fn dkg_dl_gen_verify(
    setup: &ClSetup,
    per_recipient: &DkgDlGenPerRecipient,
    commitments: &[k256::ProjectivePoint],
    recipient_pk: &ClHsmqkPublicKey,
    my_share: &DkgDlPedersenShare,
) -> ClResult<bool> {
    // Step 1: Verify Pedersen VSS share against commitments.
    if !pedersen_vss_verify(my_share, commitments) {
        return Ok(false);
    }

    // Step 2: Verify R_Enc-PC proof (cross-domain).
    // The proof binds the CL ciphertext plaintext to the EC Pedersen commitment PC.
    let proof_ok =
        per_recipient
            .proof
            .verify(setup, recipient_pk, &per_recipient.ct, &per_recipient.pc)?;
    Ok(proof_ok)
}

// ---------------------------------------------------------------------------
// Reveal phase types
// ---------------------------------------------------------------------------

/// Output of the DKG-DL Reveal phase for one party.
pub struct DkgDlRevealOutput {
    /// Combined share: `x_i = sum_j chi_{ji} mod q`.
    pub combined_share: k256::Scalar,
    /// Public share: `X_i = g^{x_i}`.
    pub public_share: k256::ProjectivePoint,
    /// `R_Dec-DL` proof attesting correct decryption and DL relation.
    pub proof: RDecDlProof,
    /// The homomorphically-combined ciphertext (for verifiers).
    pub combined_ct: ClHsmqkCiphertext,
}

// ---------------------------------------------------------------------------
// Reveal phase
// ---------------------------------------------------------------------------

/// Runs the DKG-DL Reveal phase for one party (WMC24 Figure 1, Reveal).
///
/// Each party `i`:
/// 1. Decrypts `chi_{ji} = CL.Dec(dk_i, c_{chi_ji})` for each dealer `j`.
/// 2. Combines: `x_i = sum_j chi_{ji} mod q`.
/// 3. Computes public share: `X_i = g^{x_i}`.
/// 4. Computes combined ciphertext: `c_{x_i} = hom_sum_j c_{chi_ji}`.
/// 5. Proves `R_Dec-DL` for `(X_i, c_{x_i}, ek_i)` with witness `(x_i, dk_i)`.
///
/// # Arguments
///
/// - `setup`: mutable CL setup.
/// - `my_sk_bytes`: this party's CL secret key (big-endian bytes).
/// - `my_pk`: this party's CL public key.
/// - `received_cts`: CL ciphertexts from each dealer `j` addressed to this party.
/// - `n`: total number of parties.
///
/// # Returns
///
/// The Reveal output with combined share, public share, proof, and combined ct.
pub fn dkg_dl_reveal(
    setup: &mut ClSetup,
    my_sk: &Integer,
    my_pk: &ClHsmqkPublicKey,
    received_cts: &[ClHsmqkCiphertext],
    n: usize,
) -> ClResult<DkgDlRevealOutput> {
    assert_eq!(received_cts.len(), n);

    let sk = setup.sk_from_integer(my_sk)?;

    // Decrypt each ciphertext and sum shares.
    let mut combined_share = k256::Scalar::ZERO;

    // Accumulate the combined ciphertext components for the proof.
    let mut combined_c1 = setup.identity()?;
    let mut combined_c2 = setup.identity()?;

    for ct_j in received_cts {
        // Decrypt: chi_{ji} = CL.Dec(dk_i, c_{chi_ji})
        let m = setup.decrypt(&sk, ct_j)?;

        // The plaintext is already in [0, q), so interpret as a scalar.
        let chi_ji = Secp256k1::scalar_from_integer(&m);
        combined_share += chi_ji;

        // Accumulate ciphertext components: c_{x_i} = hom_sum c_{chi_ji}
        let (c1, c2) = setup.ct_components(ct_j)?;
        combined_c1 = setup.compose(&combined_c1, &c1)?;
        combined_c2 = setup.compose(&combined_c2, &c2)?;
    }

    // Public share: X_i = g^{x_i}
    let public_share = k256::ProjectivePoint::GENERATOR * combined_share;

    // Build combined ciphertext
    let combined_ct = setup.ct_from_components(&combined_c1, &combined_c2)?;

    // Compute partial decryption: pd = c1^{sk}
    // The R_Dec-DL proof proves pk = h^{sk} and pd = c1^{sk}.
    let pd = setup.exp(&combined_c1, my_sk)?;

    // Prove R_Dec-DL
    let proof = RDecDlProof::prove(setup, my_pk, &combined_ct, &pd, my_sk)?;

    Ok(DkgDlRevealOutput {
        combined_share,
        public_share,
        proof,
        combined_ct,
    })
}

// ---------------------------------------------------------------------------
// RevealVf phase
// ---------------------------------------------------------------------------

/// Verifies one party's Reveal output (WMC24 Figure 1, RevealVf).
///
/// Checks the `R_Dec-DL` proof attesting that the partial decryption of the
/// combined ciphertext is consistent with the party's public key.
///
/// # Arguments
///
/// - `setup`: CL setup reference.
/// - `reveal`: the party's Reveal output.
/// - `party_pk`: the party's CL public key.
///
/// # Returns
///
/// `true` if the proof verifies.
pub fn dkg_dl_reveal_verify(
    setup: &ClSetup,
    reveal: &DkgDlRevealOutput,
    party_pk: &ClHsmqkPublicKey,
) -> ClResult<bool> {
    // Reconstruct pd from the combined ciphertext and the public share.
    // The verifier needs the partial decryption element `pd` to verify.
    // pd = c1^{sk} is proved by R_Dec-DL.
    //
    // From the verifier's perspective: given X_i = g^{x_i} and the combined
    // ciphertext c = (c1, c2), the prover claims c2 / c1^{sk} = f^{x_i}.
    // So pd = c1^{sk} = c2 * (f^{x_i})^{-1}.
    let x_i = reveal.combined_share.to_integer();
    let f_xi = setup.power_of_f(&x_i)?;
    let (_, c2) = setup.ct_components(&reveal.combined_ct)?;
    let mut f_xi_inv = f_xi;
    f_xi_inv.neg();
    let pd = setup.compose(&c2, &f_xi_inv)?;

    reveal
        .proof
        .verify(setup, party_pk, &reveal.combined_ct, &pd)
}

// ---------------------------------------------------------------------------
// Aggregate phase
// ---------------------------------------------------------------------------

/// Computes the aggregate public key from all parties' public shares via
/// Lagrange interpolation (WMC24 Figure 1, RevealVf final step).
///
/// `X = prod_i X_i^{L_{i,P}}` where `L_{i,P}` are Lagrange coefficients
/// evaluated at 0 for the set of 1-based party indices.
///
/// # Arguments
///
/// - `public_shares`: the `{X_i}` points from each party's Reveal.
/// - `party_indices_1based`: 1-based indices of the contributing parties.
///
/// # Returns
///
/// The aggregate public key `X = g^x`.
pub fn dkg_dl_aggregate(
    public_shares: &[k256::ProjectivePoint],
    party_indices_1based: &[u16],
) -> k256::ProjectivePoint {
    assert_eq!(public_shares.len(), party_indices_1based.len());
    assert!(!public_shares.is_empty());

    let coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(party_indices_1based);

    let mut aggregate = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for (share, coeff) in public_shares.iter().zip(coeffs.iter()) {
        aggregate += *share * coeff;
    }

    aggregate
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::cl::ClSetup;

    /// Full DKG-DL protocol: Gen + GenVf + Reveal + RevealVf + Aggregate.
    /// 3 parties, threshold t=2 (2-of-3).
    #[test]
    fn dkg_dl_3_parties_full_round() {
        let n = 3;
        let t = 2; // reconstruction threshold: 2-of-2

        let mut setup = ClSetup::new_secp256k1(60001u64).expect("setup");

        // Generate CL key pairs for all parties.
        let mut sk_bytes_vec = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_integer(&sk);
            sk_bytes_vec.push(sk_bytes);
            pks.push(pk);
        }

        // === Gen phase ===
        let mut gen_outputs = Vec::new();
        for i in 0..n {
            let output = dkg_dl_gen(&mut setup, &pks, n, t, i, &mut OsRng).expect("gen");
            gen_outputs.push(output);
        }

        // === GenVf phase ===
        for dealer in 0..n {
            for recipient in 0..n {
                // Reconstruct the share for verification
                let share = DkgDlPedersenShare {
                    index: (recipient + 1) as u16,
                    value: gen_outputs[dealer].my_shares[recipient],
                    randomness: gen_outputs[dealer].my_shares_prime[recipient],
                };

                let ok = dkg_dl_gen_verify(
                    &setup,
                    &gen_outputs[dealer].per_recipient[recipient],
                    &gen_outputs[dealer].commitments,
                    &pks[recipient],
                    &share,
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
            // Collect ciphertexts addressed to party i from all dealers.
            let received_cts: Vec<ClHsmqkCiphertext> = (0..n)
                .map(|dealer| gen_outputs[dealer].per_recipient[i].ct.clone())
                .collect();

            let reveal = dkg_dl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &received_cts, n)
                .expect("reveal");
            reveal_outputs.push(reveal);
        }

        // === RevealVf phase ===
        for i in 0..n {
            let ok =
                dkg_dl_reveal_verify(&setup, &reveal_outputs[i], &pks[i]).expect("reveal_verify");
            assert!(ok, "RevealVf failed for party={i}");
        }

        // === Aggregate ===
        let public_shares: Vec<k256::ProjectivePoint> =
            reveal_outputs.iter().map(|r| r.public_share).collect();
        let indices: Vec<u16> = (1..=n as u16).collect();

        let agg = dkg_dl_aggregate(&public_shares, &indices);

        // Verify: the aggregate should equal g^{sum chi_j}
        let total_secret: k256::Scalar = gen_outputs.iter().map(|g| g.my_secret).sum();
        let expected = k256::ProjectivePoint::GENERATOR * total_secret;
        assert_eq!(agg, expected, "aggregate mismatch");
    }

    /// Test that individual shares are consistent: each party's combined
    /// share equals the sum of shares addressed to them.
    #[test]
    fn dkg_dl_share_consistency() {
        let n = 3;
        let t = 2; // reconstruction threshold: 2-of-2

        let mut setup = ClSetup::new_secp256k1(60002u64).expect("setup");

        let mut sk_bytes_vec = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            sk_bytes_vec.push(setup.sk_to_integer(&sk));
            pks.push(pk);
        }

        let mut gen_outputs = Vec::new();
        for i in 0..n {
            gen_outputs.push(dkg_dl_gen(&mut setup, &pks, n, t, i, &mut OsRng).expect("gen"));
        }

        // For each recipient i, the combined share should equal
        // sum_j gen_outputs[j].my_shares[i]
        for i in 0..n {
            let expected_share: k256::Scalar = gen_outputs.iter().map(|g| g.my_shares[i]).sum();

            let received_cts: Vec<ClHsmqkCiphertext> = (0..n)
                .map(|dealer| gen_outputs[dealer].per_recipient[i].ct.clone())
                .collect();

            let reveal = dkg_dl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &received_cts, n)
                .expect("reveal");

            assert_eq!(
                reveal.combined_share, expected_share,
                "share mismatch for party {i}"
            );
        }
    }

    /// 2-party degenerate case (n=2, t=2).
    #[test]
    fn dkg_dl_2_of_2() {
        let n = 2;
        let t = 2; // reconstruction threshold: 2-of-2

        let mut setup = ClSetup::new_secp256k1(60003u64).expect("setup");

        let mut sk_bytes_vec = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            sk_bytes_vec.push(setup.sk_to_integer(&sk));
            pks.push(pk);
        }

        let mut gen_outputs = Vec::new();
        for i in 0..n {
            gen_outputs.push(dkg_dl_gen(&mut setup, &pks, n, t, i, &mut OsRng).expect("gen"));
        }

        // GenVf
        for d in 0..n {
            for r in 0..n {
                let share = DkgDlPedersenShare {
                    index: (r + 1) as u16,
                    value: gen_outputs[d].my_shares[r],
                    randomness: gen_outputs[d].my_shares_prime[r],
                };
                assert!(
                    dkg_dl_gen_verify(
                        &setup,
                        &gen_outputs[d].per_recipient[r],
                        &gen_outputs[d].commitments,
                        &pks[r],
                        &share,
                    )
                    .expect("verify"),
                    "GenVf failed d={d} r={r}"
                );
            }
        }

        // Reveal
        let mut reveals = Vec::new();
        for i in 0..n {
            let cts: Vec<ClHsmqkCiphertext> = (0..n)
                .map(|d| gen_outputs[d].per_recipient[i].ct.clone())
                .collect();
            reveals.push(
                dkg_dl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &cts, n).expect("reveal"),
            );
        }

        // RevealVf
        for i in 0..n {
            assert!(
                dkg_dl_reveal_verify(&setup, &reveals[i], &pks[i]).expect("verify"),
                "RevealVf failed i={i}"
            );
        }

        // Aggregate
        let public_shares: Vec<k256::ProjectivePoint> =
            reveals.iter().map(|r| r.public_share).collect();
        let indices: Vec<u16> = (1..=n as u16).collect();
        let agg = dkg_dl_aggregate(&public_shares, &indices);

        let total_secret: k256::Scalar = gen_outputs.iter().map(|g| g.my_secret).sum();
        let expected = k256::ProjectivePoint::GENERATOR * total_secret;
        assert_eq!(agg, expected);
    }
}
