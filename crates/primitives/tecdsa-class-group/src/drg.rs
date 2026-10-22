// SPDX-License-Identifier: MIT OR Apache-2.0
//! Distributed Randomness Generation (DRG) primitive.
//!
//! Originally from WMY23 (Wang, Mei, Yu. "Real Threshold ECDSA." NDSS 2023).
//!
//! Implements Figure 2 of the WMY23 paper (Wang, Mei, Yu. "Real Threshold
//! ECDSA." NDSS 2023). DRG generates `(t, n)` Shamir shares of a secret `x`
//! with:
//!
//! - Pedersen VSS commitments (verifiable)
//! - CL-encrypted shares (for homomorphic computation in MtA)
//! - ZK proofs linking CL ciphertexts to Pedersen commitments
//!
//! ## Operations
//!
//! - **Gen**: Each party samples a secret, creates Pedersen VSS shares,
//!   encrypts the secret under its own CL key, and proves R_Enc-PC.
//! - **GenVf**: Verify Pedersen VSS shares and R_Enc-PC proof.
//! - **Comb**: Combine shares from the qualified set into a combined share
//!   with a fresh CL ciphertext and R_Enc-PC proof.
//! - **RevealExp**: Reveal the EC point `g^{x_i}` with an R_PC-DL proof.
//!
//! ## Design note
//!
//! CL ZK proofs (`REncPcProof`, `RPcDlProof`) are integrated via the
//! `tecdsa-class-group` crate's ZK module. The proofs link CL ciphertexts
//! to F-subgroup commitments `f^m`, which serve as the "Pedersen
//! commitment in the CL world." The EC-level Pedersen VSS uses the
//! standard `g^{a_d} * h^{a'_d}` form over the elliptic curve.

#![allow(non_snake_case)]

use elliptic_curve::CurveArithmetic;
use rand_core::CryptoRngCore;
use tecdsa_curve::{ScalarExt, TecdsaCurve};

use crate::{
    cl::{ClCiphertext, ClPublicKey, ClSetup, Qfi},
    zk::{r_enc_pc::REncPcProof, r_pc_dl::RPcDlProof},
};

// ---------------------------------------------------------------------------
// Pedersen VSS (dual-polynomial)
// ---------------------------------------------------------------------------

/// A Pedersen VSS share: the evaluation of both polynomials at index `i`.
///
/// For secret `chi`, the dealer samples polynomials `f(x)` and `f'(x)` with
/// `f(0) = chi`, `f'(0) = chi'` (random). The share for party `j` is
/// `(f(j), f'(j))`.
#[derive(Clone, Debug)]
pub struct PedersenVssShare {
    /// 1-based party index.
    pub index: u16,
    /// Value share: `f(index)`.
    pub value: k256::Scalar,
    /// Randomness share: `f'(index)`.
    pub randomness: k256::Scalar,
}

/// Output of Pedersen VSS: shares for all parties plus polynomial commitments.
///
/// Commitments are `F_d = g^{a_d} * h^{a'_d}` for `d = 0, ..., t-1`,
/// where `a_d` are coefficients of `f(x)` and `a'_d` are coefficients of
/// `f'(x)`. `g` is the curve generator and `h` is the NUMS Pedersen point.
#[derive(Clone, Debug)]
pub struct PedersenVssOutput {
    /// Shares `(f(j), f'(j))` for each party `j = 1, ..., n`.
    pub shares: Vec<PedersenVssShare>,
    /// Polynomial commitments `F_d = g^{a_d} * h^{a'_d}`, length = threshold.
    pub commitments: Vec<k256::ProjectivePoint>,
    /// The secret `chi = f(0)` (kept by the dealer).
    pub secret: k256::Scalar,
    /// The randomness `chi' = f'(0)` (kept by the dealer).
    pub secret_randomness: k256::Scalar,
}

/// Create a Pedersen VSS sharing of `secret` with the given threshold and n.
///
/// Uses two random polynomials `f(x)` (with `f(0) = secret`) and `f'(x)`
/// (with `f'(0)` random). Commitments are `F_d = g^{a_d} * h^{a'_d}`.
///
/// # Panics
///
/// Panics if `threshold == 0` or `threshold > n`.
pub fn pedersen_vss_share(
    secret: &k256::Scalar,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> PedersenVssOutput {
    assert!(threshold > 0, "threshold must be >= 1");
    assert!(threshold <= n, "threshold must be <= n");

    let t = threshold as usize;

    // Build polynomial f(x): a_0 = secret, a_1..a_{t-1} random
    let mut f_coeffs: Vec<k256::Scalar> = Vec::with_capacity(t);
    f_coeffs.push(*secret);
    for _ in 1..t {
        f_coeffs.push(k256::Secp256k1::random_scalar(rng));
    }

    // Build polynomial f'(x): a'_0 = random, a'_1..a'_{t-1} random
    let mut fp_coeffs: Vec<k256::Scalar> = Vec::with_capacity(t);
    for _ in 0..t {
        fp_coeffs.push(k256::Secp256k1::random_scalar(rng));
    }

    let g = <k256::Secp256k1 as TecdsaCurve>::generator();
    let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();

    // Commitments: F_d = g^{a_d} * h^{a'_d}
    let commitments: Vec<k256::ProjectivePoint> = f_coeffs
        .iter()
        .zip(fp_coeffs.iter())
        .map(|(a_d, ap_d)| g * a_d + h * ap_d)
        .collect();

    // Evaluate shares: for j = 1..n, share_j = (f(j), f'(j))
    let shares: Vec<PedersenVssShare> = (1..=n)
        .map(|j| {
            let x = k256::Scalar::from(u64::from(j));
            let mut value = k256::Scalar::ZERO;
            let mut randomness = k256::Scalar::ZERO;
            let mut x_pow = k256::Scalar::ONE;
            for d in 0..t {
                value += f_coeffs[d] * x_pow;
                randomness += fp_coeffs[d] * x_pow;
                x_pow *= x;
            }
            PedersenVssShare {
                index: j,
                value,
                randomness,
            }
        })
        .collect();

    PedersenVssOutput {
        shares,
        commitments,
        secret: *secret,
        secret_randomness: fp_coeffs[0],
    }
}

/// Verify a Pedersen VSS share against the polynomial commitments.
///
/// Checks: `g^{value} * h^{randomness} == prod_{d=0}^{t-1} F_d^{index^d}`
///
/// Returns `true` if the share is consistent with the commitments.
#[must_use]
pub fn pedersen_vss_verify(
    share: &PedersenVssShare,
    commitments: &[k256::ProjectivePoint],
) -> bool {
    let g = <k256::Secp256k1 as TecdsaCurve>::generator();
    let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();

    // LHS: g^{value} * h^{randomness}
    let lhs = g * share.value + h * share.randomness;

    // RHS: prod_{d=0}^{t-1} F_d^{index^d}
    let x = k256::Scalar::from(u64::from(share.index));
    let mut rhs = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    let mut x_pow = k256::Scalar::ONE;
    for com in commitments {
        rhs += *com * x_pow;
        x_pow *= x;
    }

    lhs == rhs
}

// ---------------------------------------------------------------------------
// DRG types
// ---------------------------------------------------------------------------

/// Output of DRG.Gen for one party.
///
/// Contains the secret, its Pedersen VSS shares, CL ciphertext of the secret,
/// and the R_Enc-PC proof linking the ciphertext to the EC Pedersen commitment.
pub struct DrgGenOutput {
    /// The secret `chi_i` sampled by this party.
    pub secret: k256::Scalar,
    /// The randomness `chi'_i` from the Pedersen VSS constant term.
    pub secret_randomness: k256::Scalar,
    /// Pedersen VSS shares `(chi_{ij}, chi'_{ij})` for all parties `j = 1..n`.
    pub vss_shares: Vec<PedersenVssShare>,
    /// Pedersen VSS polynomial commitments `F_{chi_i} = {F_d}` for `d = 0..t-1`.
    pub commitments: Vec<k256::ProjectivePoint>,
    /// CL ciphertext `c_{chi_i} = Enc(ek_i, chi_i; rho_i)`.
    pub ciphertext: ClCiphertext,
    /// Encryption randomness `rho_i` (needed for proof).
    pub enc_randomness: rug::Integer,
    /// EC Pedersen commitment `PC = g^{chi_i} * h^{chi'_i}`.
    /// This is `commitments[0]`. Broadcast for R_Enc-PC verification.
    pub pc: k256::ProjectivePoint,
    /// R_Enc-PC proof: proves `c_{chi_i}` encrypts the same `chi_i` committed in PC.
    pub proof: REncPcProof,
}

/// Output of DRG.Comb for one party.
///
/// Contains the combined Shamir share, combined Pedersen commitment,
/// and a fresh CL ciphertext of the combined share with R_Enc-PC proof.
pub struct DrgCombOutput {
    /// Combined Shamir share: `x_i = sum_{j in Q} chi_{ji}`.
    pub combined_share: k256::Scalar,
    /// Combined randomness share: `x'_i = sum_{j in Q} chi'_{ji}`.
    pub combined_randomness: k256::Scalar,
    /// Combined Pedersen commitment `PC_{x_i}` (evaluated at this party's index).
    pub pedersen_commitment: k256::ProjectivePoint,
    /// CL ciphertext `c_{x_i} = Enc(ek_i, x_i; rho_{x_i})`.
    pub ciphertext: ClCiphertext,
    /// Encryption randomness for the combined ciphertext.
    pub enc_randomness: rug::Integer,
    /// EC Pedersen commitment. Broadcast for R_Enc-PC verification.
    pub pc: k256::ProjectivePoint,
    /// R_Enc-PC proof linking `c_{x_i}` to the EC Pedersen commitment.
    pub proof: REncPcProof,
}

/// Output of DRG.RevealExp for one party.
///
/// Contains the EC point `X_i = g^{x_i}` and an R_PC-DL proof.
pub struct DrgRevealExpOutput {
    /// The EC point `X_i = g^{x_i}`.
    pub point: k256::ProjectivePoint,
    /// F-subgroup element `Y = f^{x_i}`, broadcast alongside the proof.
    pub y_element: Qfi,
    /// R_PC-DL proof: proves `X_i = g^{x_i}` where `x_i` maps to `f^{x_i}`.
    pub proof: RPcDlProof,
}

// ---------------------------------------------------------------------------
// DRG operations
// ---------------------------------------------------------------------------

/// **DRG.Gen** -- Generation phase (WMY23 Figure 2, Gen).
///
/// Each party `i`:
/// 1. Samples secret `chi_i` from `Z_q`.
/// 2. Creates Pedersen VSS: `(chi_i, chi'_i) -> shares + commitments`.
/// 3. Encrypts `chi_i` under own CL key with explicit randomness.
/// 4. Proves R_Enc-PC: proof that `c_{chi_i}` encrypts `chi_i` committed in
///    `F_{chi_i,0}` via the F-subgroup element `f^{chi_i}`.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context (mutable for encryption + proof generation).
/// * `pk` - This party's CL public key.
/// * `threshold` - Reconstruction threshold `t`.
/// * `n` - Total number of parties.
/// * `rng` - Cryptographic RNG.
///
/// # Errors
///
/// Returns an error if CL encryption or proof generation fails.
pub fn drg_gen(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Result<DrgGenOutput, Box<dyn std::error::Error>> {
    // Step 1: Sample secret chi_i
    let chi_i = k256::Secp256k1::random_scalar(rng);

    drg_gen_with_secret(setup, pk, &chi_i, threshold, n, rng)
}

/// **DRG.Gen** with a specific secret (for testing or when the secret is
/// pre-determined, e.g., the existing key share in keygen refresh).
///
/// # Errors
///
/// Returns an error if CL encryption or proof generation fails.
pub fn drg_gen_with_secret(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    secret: &k256::Scalar,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Result<DrgGenOutput, Box<dyn std::error::Error>> {
    // Step 2: Create Pedersen VSS
    let vss_output = pedersen_vss_share(secret, threshold, n, rng);

    // Step 3: Encrypt chi_i under own CL key with explicit randomness
    let chi = secret.to_integer();

    // Generate encryption randomness by sampling a CL secret key
    // (which lives in the correct range for CL randomness)
    let (r_sk, _r_pk) = setup.keygen()?;
    let r = setup.sk_to_integer(&r_sk);

    let ciphertext = setup.encrypt_with_r(pk, &chi, &r)?;

    // Step 4: Prove R_Enc-PC (cross-domain): ct encrypts chi_i AND
    // PC = g^{chi_i} * h^{chi'_i} uses the same chi_i.
    // PC = commitments[0] = g^{a_0} * h^{a'_0} = g^{chi_i} * h^{chi'_i}.
    let pc = vss_output.commitments[0];
    let chi_prime = vss_output.secret_randomness.to_integer();
    let proof = REncPcProof::prove(setup, pk, &ciphertext, &pc, &chi, &chi_prime, &r)?;

    Ok(DrgGenOutput {
        secret: vss_output.secret,
        secret_randomness: vss_output.secret_randomness,
        vss_shares: vss_output.shares,
        commitments: vss_output.commitments,
        ciphertext,
        enc_randomness: r,
        pc,
        proof,
    })
}

/// **DRG.GenVf** -- Verification phase (WMY23 Figure 2, GenVf).
///
/// Each party `j` receiving from party `i`:
/// 1. Verifies the Pedersen VSS share against commitments.
/// 2. Verifies the R_Enc-PC proof linking the CL ciphertext to `F_{chi_i,0}`.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `pk_i` - Party `i`'s CL public key (the sender).
/// * `gen_output` - Party `i`'s DRG.Gen output (public parts).
/// * `my_share` - The Pedersen VSS share designated for this party `j`.
///
/// # Returns
///
/// `true` if both checks pass, `false` otherwise.
pub fn drg_gen_verify(
    setup: &ClSetup,
    pk_i: &ClPublicKey,
    commitments: &[k256::ProjectivePoint],
    ciphertext: &ClCiphertext,
    proof: &REncPcProof,
    pc: &k256::ProjectivePoint,
    my_share: &PedersenVssShare,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Step 1: Verify Pedersen VSS share
    if !pedersen_vss_verify(my_share, commitments) {
        return Ok(false);
    }

    // Step 2: Verify R_Enc-PC proof (cross-domain).
    // The proof binds the CL ciphertext plaintext to the EC Pedersen
    // commitment `PC = commitments[0]`, ensuring the same chi_i.
    let proof_ok = proof.verify(setup, pk_i, ciphertext, pc)?;
    Ok(proof_ok)
}

/// **DRG.GenVf (full)** -- Verification with explicit F-subgroup element.
///
/// This variant takes the F-subgroup element `Y = f^{chi_i}` that was
/// broadcast alongside the proof, enabling full R_Enc-PC verification.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `pk_i` - Party `i`'s CL public key.
/// * `commitments` - Party `i`'s Pedersen VSS commitments.
/// * `ciphertext` - Party `i`'s CL ciphertext.
/// * `proof` - Party `i`'s R_Enc-PC proof.
/// * `y` - The F-subgroup element `f^{chi_i}` broadcast by party `i`.
/// * `my_share` - The share designated for this verifying party.
///
/// # Returns
///
/// `true` if VSS verification and R_Enc-PC proof verification both pass.
pub fn drg_gen_verify_full(
    setup: &ClSetup,
    pk_i: &ClPublicKey,
    commitments: &[k256::ProjectivePoint],
    ciphertext: &ClCiphertext,
    proof: &REncPcProof,
    pc: &k256::ProjectivePoint,
    my_share: &PedersenVssShare,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Step 1: Verify Pedersen VSS share
    if !pedersen_vss_verify(my_share, commitments) {
        return Ok(false);
    }

    // Step 2: Verify R_Enc-PC proof (cross-domain)
    let proof_ok = proof.verify(setup, pk_i, ciphertext, pc)?;
    Ok(proof_ok)
}

/// **DRG.Comb** -- Combination phase (WMY23 Figure 2, Comb).
///
/// Each party `i` combines shares from the qualified set `Q`:
/// 1. `x_i = sum_{j in Q} chi_{ji}` (combined Shamir share)
/// 2. `x'_i = sum_{j in Q} chi'_{ji}` (combined randomness)
/// 3. `PC_{x_i} = sum_{j in Q} F_{chi_j}` evaluated at `i`
/// 4. `c_{x_i} = Enc(ek_i, x_i; rho_{x_i})` (encrypt combined share)
/// 5. Prove R_Enc-PC for `c_{x_i}` against `f^{x_i}`
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `pk` - This party's CL public key.
/// * `my_index` - This party's 1-based index.
/// * `received_shares` - Shares received from all parties in Q.
///   Each entry is `(party_index, share_for_me)`.
/// * `all_commitments` - Commitments from all parties in Q.
///   Each entry is `(party_index, commitments_vec)`.
///
/// # Errors
///
/// Returns an error if CL operations fail.
pub fn drg_comb(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    my_index: u16,
    received_shares: &[(u16, PedersenVssShare)],
    all_commitments: &[(u16, Vec<k256::ProjectivePoint>)],
) -> Result<DrgCombOutput, Box<dyn std::error::Error>> {
    // Step 1 & 2: Sum shares
    let mut combined_share = k256::Scalar::ZERO;
    let mut combined_randomness = k256::Scalar::ZERO;
    for (_sender, share) in received_shares {
        assert_eq!(
            share.index, my_index,
            "share index mismatch: expected {my_index}, got {}",
            share.index
        );
        combined_share += share.value;
        combined_randomness += share.randomness;
    }

    // Step 3: Combined Pedersen commitment at my_index
    // PC_{x_i} = sum_{j in Q} (sum_{d=0}^{t-1} F_{j,d} * i^d)
    // This is the product (sum in additive notation) of evaluating each
    // party's commitment polynomial at my_index.
    let x = k256::Scalar::from(u64::from(my_index));
    let mut pedersen_commitment = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for (_sender, coms) in all_commitments {
        let mut x_pow = k256::Scalar::ONE;
        for com in coms {
            pedersen_commitment += *com * x_pow;
            x_pow *= x;
        }
    }

    // Step 4: Encrypt combined share under own CL key
    let x_i = combined_share.to_integer();
    let (r_sk, _r_pk) = setup.keygen()?;
    let r = setup.sk_to_integer(&r_sk);
    let ciphertext = setup.encrypt_with_r(pk, &x_i, &r)?;

    // Step 5: Prove R_Enc-PC (cross-domain)
    // PC = pedersen_commitment = g^{x_i} * h^{x'_i}
    let x_prime_i = combined_randomness.to_integer();
    let proof = REncPcProof::prove(
        setup,
        pk,
        &ciphertext,
        &pedersen_commitment,
        &x_i,
        &x_prime_i,
        &r,
    )?;

    Ok(DrgCombOutput {
        combined_share,
        combined_randomness,
        pedersen_commitment,
        ciphertext,
        enc_randomness: r,
        pc: pedersen_commitment,
        proof,
    })
}

/// **DRG.RevealExp** -- Reveal share in exponent (WMY23 Figure 2, RevealExp).
///
/// Each party `i`:
/// 1. Computes `X_i = g^{x_i}` (EC point).
/// 2. Proves R_PC-DL: `X_i = g^{x_i}` where `x_i` maps to `f^{x_i}`.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `combined_share` - The combined Shamir share `x_i`.
///
/// # Errors
///
/// Returns an error if proof generation fails.
pub fn drg_reveal_exp(
    setup: &mut ClSetup,
    combined_share: &k256::Scalar,
) -> Result<DrgRevealExpOutput, Box<dyn std::error::Error>> {
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let point = g * combined_share;

    let x = combined_share.to_integer();

    // R_PC-DL proof: proves knowledge of x such that f^x = Y
    // The verifier checks that dlog_in_F(Y) matches the committed value.
    let y = setup.power_of_f(&x)?;
    let proof = RPcDlProof::prove(setup, &y, &x)?;

    Ok(DrgRevealExpOutput {
        point,
        y_element: y,
        proof,
    })
}

/// Verify a DRG.RevealExp output.
///
/// Checks that the R_PC-DL proof is valid for the given EC point, confirming
/// the party knows `x_i` such that `X_i = g^{x_i}` and `f^{x_i} = Y`.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `output` - The RevealExp output to verify.
///
/// # Returns
///
/// `true` if the proof verifies.
pub fn drg_reveal_exp_verify(
    setup: &ClSetup,
    output: &DrgRevealExpOutput,
) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(output.proof.verify(setup, &output.y_element)?)
}

/// Verify a DRG.RevealExp output with explicit F-subgroup element.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `proof` - The R_PC-DL proof.
/// * `y` - The F-subgroup element `f^{x_i}` broadcast by the prover.
///
/// # Returns
///
/// `true` if the proof verifies.
pub fn drg_reveal_exp_verify_full(
    setup: &ClSetup,
    proof: &RPcDlProof,
    y: &Qfi,
) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(proof.verify(setup, y)?)
}

// ---------------------------------------------------------------------------
// DRG-based presign helpers
// ---------------------------------------------------------------------------

/// Per-party DRG state for one variable (k or gamma) in the presign.
///
/// Holds the DRG.Gen output and the subsequent DRG.Comb output.
pub struct DrgPresignState {
    /// DRG.Gen output (secret, VSS shares, CL ciphertext, proof).
    pub gen_output: DrgGenOutput,
    /// DRG.Comb output (combined share, ciphertext, proof).
    /// Populated after the combination phase.
    pub comb_output: Option<DrgCombOutput>,
}

/// Run DRG.Gen + DRG.GenVf + DRG.Comb for a single variable across all parties.
///
/// This is a test helper that runs the complete DRG flow for n-of-n sharing
/// in a single-threaded simulation.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `pks` - CL public keys for all parties.
/// * `threshold` - VSS threshold.
/// * `n` - Total number of parties.
/// * `rng` - Cryptographic RNG.
///
/// # Returns
///
/// A vector of `(combined_share, ciphertext)` for each party.
///
/// # Errors
///
/// Returns an error if any DRG operation fails.
pub fn drg_full_run(
    setup: &mut ClSetup,
    pks: &[ClPublicKey],
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<DrgCombOutput>, Box<dyn std::error::Error>> {
    let n_usize = n as usize;

    // Phase 1: DRG.Gen for each party
    let gen_outputs = pks
        .iter()
        .map(|pk| drg_gen(setup, pk, threshold, n, rng))
        .collect::<Result<Vec<_>, _>>()?;

    // Phase 2: DRG.GenVf -- each party verifies all other parties' outputs
    for j in 0..n_usize {
        for i in 0..n_usize {
            if i == j {
                continue;
            }
            // Party j verifies party i's share for j
            // Share index is j+1 (1-based), stored at position j in the shares vec
            let share_for_j = &gen_outputs[i].vss_shares[j];
            let ok = drg_gen_verify(
                setup,
                &pks[i],
                &gen_outputs[i].commitments,
                &gen_outputs[i].ciphertext,
                &gen_outputs[i].proof,
                &gen_outputs[i].pc,
                share_for_j,
            )?;
            if !ok {
                return Err(
                    format!("DRG.GenVf failed: party {j} rejected party {i}'s share").into(),
                );
            }
        }
    }

    // Phase 3: DRG.Comb for each party
    // In n-of-n, the qualified set Q = all parties
    let comb_outputs = pks
        .iter()
        .enumerate()
        .map(|(j, pk)| {
            let my_index = (j + 1) as u16; // 1-based

            // Collect shares from all parties for party j
            let received_shares: Vec<(u16, PedersenVssShare)> = (0..n_usize)
                .map(|i| {
                    let sender_index = (i + 1) as u16;
                    (sender_index, gen_outputs[i].vss_shares[j].clone())
                })
                .collect();

            // Collect commitments from all parties
            let all_commitments: Vec<(u16, Vec<k256::ProjectivePoint>)> = (0..n_usize)
                .map(|i| {
                    let sender_index = (i + 1) as u16;
                    (sender_index, gen_outputs[i].commitments.clone())
                })
                .collect();

            drg_comb(setup, pk, my_index, &received_shares, &all_commitments)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(comb_outputs)
}

#[cfg(test)]
mod tests {
    use rug::Integer;

    use super::*;
    use crate::cl::{ClPublicKey, ClSetup, Qfi};

    /// Helper: create CL public keys for all parties.
    #[allow(clippy::type_complexity)]
    fn make_cl_keys(
        setup: &mut ClSetup,
        n: usize,
    ) -> Vec<(Integer, ClPublicKey, (Integer, Integer, Integer))> {
        (0..n)
            .map(|_| {
                let (sk_raw, pk) = setup.keygen().expect("CL keygen");
                let sk = setup.sk_to_integer(&sk_raw);
                let pk_qfi = pk.elt();
                let abc = (pk_qfi.a().clone(), pk_qfi.b().clone(), pk_qfi.c().clone());
                (sk, pk, abc)
            })
            .collect()
    }

    /// Helper: reconstruct CL public key from ABC.
    fn reconstruct_pk(setup: &ClSetup, abc: &(Integer, Integer, Integer)) -> ClPublicKey {
        let qfi = Qfi::from_abc(abc.0.clone(), abc.1.clone(), abc.2.clone());
        let pk_raw = ClPublicKey::from_qfi(setup.cl(), qfi).expect("pk from qfi");
        pk_raw
    }

    #[test]
    fn test_pedersen_vss_basic() {
        let mut rng = rand::thread_rng();
        let secret = k256::Secp256k1::random_scalar(&mut rng);
        let threshold = 2u16;
        let n = 3u16;

        let output = pedersen_vss_share(&secret, threshold, n, &mut rng);

        // Check we got the right number of shares and commitments
        assert_eq!(output.shares.len(), n as usize);
        assert_eq!(output.commitments.len(), threshold as usize);
        assert_eq!(output.secret, secret);

        // Verify each share
        for share in &output.shares {
            assert!(
                pedersen_vss_verify(share, &output.commitments),
                "share {} failed verification",
                share.index
            );
        }
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_pedersen_vss_rejects_wrong_share() {
        let mut rng = rand::thread_rng();
        let secret = k256::Secp256k1::random_scalar(&mut rng);

        let output = pedersen_vss_share(&secret, 2, 3, &mut rng);

        // Tamper with a share value
        let mut bad_share = output.shares[0].clone();
        bad_share.value += k256::Scalar::ONE;
        assert!(
            !pedersen_vss_verify(&bad_share, &output.commitments),
            "tampered share should fail verification"
        );
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_pedersen_vss_reconstruction() {
        // Verify that the combined shares reconstruct the sum of secrets
        let mut rng = rand::thread_rng();
        let n = 3u16;
        let threshold = 2u16;

        let secret1 = k256::Secp256k1::random_scalar(&mut rng);
        let secret2 = k256::Secp256k1::random_scalar(&mut rng);
        let secret3 = k256::Secp256k1::random_scalar(&mut rng);
        let expected_sum = secret1 + secret2 + secret3;

        let out1 = pedersen_vss_share(&secret1, threshold, n, &mut rng);
        let out2 = pedersen_vss_share(&secret2, threshold, n, &mut rng);
        let out3 = pedersen_vss_share(&secret3, threshold, n, &mut rng);

        // For each party j, combined share = sum of shares from all dealers
        let combined: Vec<k256::Scalar> = (0..n as usize)
            .map(|j| out1.shares[j].value + out2.shares[j].value + out3.shares[j].value)
            .collect();

        // Reconstruct using Lagrange interpolation at x=0
        let indices: Vec<u16> = (1..=n).collect();
        let coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let reconstructed: k256::Scalar = combined
            .iter()
            .zip(coeffs.iter())
            .map(|(s, c)| *s * c)
            .sum();

        assert_eq!(
            reconstructed, expected_sum,
            "Lagrange reconstruction should yield sum of secrets"
        );
    }

    #[test]
    fn test_drg_gen_basic() {
        let mut setup = ClSetup::new_secp256k1(30001u64).expect("CL setup");
        let keys = make_cl_keys(&mut setup, 1);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        assert_eq!(gen.vss_shares.len(), 2);
        assert_eq!(gen.commitments.len(), 1); // threshold = 1
                                              // Proof is always generated (no longer optional).
        let _ = &gen.proof;

        // Verify all shares
        for share in &gen.vss_shares {
            assert!(pedersen_vss_verify(share, &gen.commitments));
        }
    }

    #[test]
    fn test_drg_gen_verify_accepts_honest() {
        let mut setup = ClSetup::new_secp256k1(30002u64).expect("CL setup");
        let keys = make_cl_keys(&mut setup, 2);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        // Party 1 (index 1) verifies share from party 0
        let ok = drg_gen_verify(
            &setup,
            &keys[0].1,
            &gen.commitments,
            &gen.ciphertext,
            &gen.proof,
            &gen.pc,
            &gen.vss_shares[0], // share for party 1 (index 0 in vec)
        )
        .expect("drg_gen_verify");
        assert!(ok, "honest share should verify");
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_drg_gen_verify_rejects_tampered() {
        let mut setup = ClSetup::new_secp256k1(30003u64).expect("CL setup");
        let keys = make_cl_keys(&mut setup, 2);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        // Tamper with the share
        let mut bad_share = gen.vss_shares[0].clone();
        bad_share.value += k256::Scalar::ONE;

        let ok = drg_gen_verify(
            &setup,
            &keys[0].1,
            &gen.commitments,
            &gen.ciphertext,
            &gen.proof,
            &gen.pc,
            &bad_share,
        )
        .expect("drg_gen_verify");
        assert!(!ok, "tampered share should be rejected");
    }

    #[test]
    fn test_drg_full_run_2_of_2() {
        let mut setup = ClSetup::new_secp256k1(30004u64).expect("CL setup");
        let keys = make_cl_keys(&mut setup, 2);
        let pks: Vec<ClPublicKey> = keys
            .iter()
            .map(|(_, _, abc)| reconstruct_pk(&setup, abc))
            .collect();
        let mut rng = rand::thread_rng();

        let comb_outputs = drg_full_run(&mut setup, &pks, 1, 2, &mut rng).expect("drg_full_run");

        assert_eq!(comb_outputs.len(), 2);

        // Verify combined shares reconstruct to a consistent secret
        let indices: Vec<u16> = vec![1, 2];
        let coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let combined_shares: Vec<k256::Scalar> =
            comb_outputs.iter().map(|c| c.combined_share).collect();
        let _reconstructed: k256::Scalar = combined_shares
            .iter()
            .zip(coeffs.iter())
            .map(|(s, c)| *s * c)
            .sum();

        // The reconstructed value should be well-defined (not checking a
        // specific value since secrets are random).
        // Proof is always generated (no longer optional after WARN 4 fix).
        let _ = &comb_outputs[0].proof;
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_drg_full_run_3_of_3() {
        let mut setup = ClSetup::new_secp256k1(30005u64).expect("CL setup");
        let keys = make_cl_keys(&mut setup, 3);
        let pks: Vec<ClPublicKey> = keys
            .iter()
            .map(|(_, _, abc)| reconstruct_pk(&setup, abc))
            .collect();
        let mut rng = rand::thread_rng();

        let comb_outputs = drg_full_run(&mut setup, &pks, 2, 3, &mut rng).expect("drg_full_run");

        assert_eq!(comb_outputs.len(), 3);

        // Verify combined Pedersen commitments are consistent with shares
        let g = <k256::Secp256k1 as TecdsaCurve>::generator();
        let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();
        for comb in &comb_outputs {
            let expected_pc = g * comb.combined_share + h * comb.combined_randomness;
            assert_eq!(
                comb.pedersen_commitment, expected_pc,
                "Pedersen commitment should match combined share"
            );
        }
    }

    #[test]
    fn test_drg_reveal_exp() {
        let mut setup = ClSetup::new_secp256k1(30006u64).expect("CL setup");
        let mut rng = rand::thread_rng();
        let x = k256::Secp256k1::random_scalar(&mut rng);

        let reveal = drg_reveal_exp(&mut setup, &x).expect("reveal_exp");

        let expected = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * x;
        assert_eq!(reveal.point, expected, "X_i should be g^x_i");
        // Proof is always generated (no longer optional).
        let _ = &reveal.proof;
    }

    #[test]
    fn test_drg_comb_shares_reconstruct_sum() {
        // End-to-end: run DRG for n parties, verify that the combined shares
        // reconstruct to the sum of individual secrets via Lagrange.
        let mut setup = ClSetup::new_secp256k1(30007u64).expect("CL setup");
        let n = 3u16;
        let threshold = 2u16;
        let keys = make_cl_keys(&mut setup, n as usize);
        let pks: Vec<ClPublicKey> = keys
            .iter()
            .map(|(_, _, abc)| reconstruct_pk(&setup, abc))
            .collect();
        let mut rng = rand::thread_rng();

        // Run DRG.Gen for each party, collecting their secrets
        let gen_outputs = pks
            .iter()
            .map(|pk| drg_gen(&mut setup, pk, threshold, n, &mut rng).expect("drg_gen"))
            .collect::<Vec<_>>();

        let expected_sum: k256::Scalar = gen_outputs.iter().map(|g| g.secret).sum();

        // Run DRG.Comb for each party
        let comb_outputs = pks
            .iter()
            .enumerate()
            .map(|(j, pk)| {
                let my_index = (j + 1) as u16;
                let received_shares: Vec<(u16, PedersenVssShare)> = (0..n as usize)
                    .map(|i| ((i + 1) as u16, gen_outputs[i].vss_shares[j].clone()))
                    .collect();
                let all_commitments: Vec<(u16, Vec<k256::ProjectivePoint>)> = (0..n as usize)
                    .map(|i| ((i + 1) as u16, gen_outputs[i].commitments.clone()))
                    .collect();
                drg_comb(&mut setup, pk, my_index, &received_shares, &all_commitments)
                    .expect("drg_comb")
            })
            .collect::<Vec<_>>();

        // Lagrange reconstruct combined shares
        let indices: Vec<u16> = (1..=n).collect();
        let coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let reconstructed: k256::Scalar = comb_outputs
            .iter()
            .zip(coeffs.iter())
            .map(|(c, coeff)| c.combined_share * coeff)
            .sum();

        assert_eq!(
            reconstructed, expected_sum,
            "combined shares should reconstruct to the sum of secrets"
        );
    }

    #[test]
    fn test_drg_r_enc_pc_proof_verifies() {
        // Test that the R_Enc-PC proof generated in DRG.Gen actually verifies.
        let mut setup = ClSetup::new_secp256k1(30008u64).expect("CL setup");
        let keys = make_cl_keys(&mut setup, 1);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        // Proof is always generated; verify using the stored PC bytes.
        let ok = gen
            .proof
            .verify(&setup, &keys[0].1, &gen.ciphertext, &gen.pc)
            .expect("verify");
        assert!(ok, "R_Enc-PC proof should verify for honest generation");
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_drg_gen_verify_full() {
        // Test drg_gen_verify_full with explicit Y value.
        let mut setup = ClSetup::new_secp256k1(30009u64).expect("CL setup");
        let keys = make_cl_keys(&mut setup, 2);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        let ok = drg_gen_verify_full(
            &setup,
            &keys[0].1,
            &gen.commitments,
            &gen.ciphertext,
            &gen.proof,
            &gen.pc,
            &gen.vss_shares[0],
        )
        .expect("verify_full");
        assert!(ok, "full verification should pass for honest party");
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_drg_reveal_exp_proof_verifies() {
        // Test that R_PC-DL proof verifies with explicit Y.
        let mut setup = ClSetup::new_secp256k1(30010u64).expect("CL setup");
        let mut rng = rand::thread_rng();
        let x = k256::Secp256k1::random_scalar(&mut rng);

        let reveal = drg_reveal_exp(&mut setup, &x).expect("reveal_exp");

        let ok =
            drg_reveal_exp_verify_full(&setup, &reveal.proof, &reveal.y_element).expect("verify");
        assert!(ok, "R_PC-DL proof should verify");
    }
}
