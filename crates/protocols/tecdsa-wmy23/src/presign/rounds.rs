// SPDX-License-Identifier: GPL-3.0-or-later
//! WMY23 presign round functions.
//!
//! Provides two implementations:
//!
//! ## Simplified presign (original, for backward compatibility)
//!
//! Uses direct CL encryption without DRG/Pedersen-VSS.
//!
//! 1. Sample k_i, gamma_i; commit to Gamma_i = gamma_i * G.
//! 2. Decommit Gamma_i; run MtAwc step 1 (Alice encrypts secrets).
//! 3. Run MtAwc step 2 (Bob responds).
//! 4. Alice decrypts, compute delta_i / sigma_i, reconstruct R.
//!
//! ## DRG-based presign (WMY23 Figure 3)
//!
//! Uses Distributed Randomness Generation with Pedersen VSS and CL ZK proofs.
//!
//! 1. DRG.Gen for k_i and gamma_i: Pedersen VSS shares + CL ciphertexts +
//!    R_Enc-PC proofs. Broadcast commitments, send shares P2P.
//! 2. DRG.GenVf + DRG.Comb: verify received shares, combine into (t,n)
//!    shares. Encrypt combined shares, broadcast R_Enc-PC proofs.
//! 3. MtAwc step 2 (Bob): homomorphic multiplication using DRG ciphertexts.
//! 4. MtAwc step 3 (Alice): decrypt, reconstruct delta and R.
//!
//! ## v0.2.2 refactor
//!
//! With bicycl-rs v0.2.2, all CL types including `ClSetup` are `Send`.
//! The key share stores CL types directly, and presign round functions
//! use `&key_share.cl_pks[j]` directly instead of reconstructing from
//! serialised abc strings.  `ClSetup` can be stored in state machines
//! and reused across rounds.

#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_class_group::cl::{ClCiphertext, ClSetup};
use tecdsa_curve::TecdsaCurve;

use crate::{
    key_share::Wmy23KeyShare,
    mtawc::{self, MtAwcAliceState, MtAwcBobOutput},
    presign::Wmy23Presignature,
};

/// Per-party state after Round 1.
pub struct PresignR1State {
    /// Party index (0-based).
    pub index: usize,
    /// Nonce share k_i.
    pub k_i: k256::Scalar,
    /// Gamma share gamma_i.
    pub gamma_i: k256::Scalar,
    /// Gamma point Gamma_i = gamma_i * G.
    pub gamma_point_i: k256::ProjectivePoint,
    /// Commitment nonce.
    pub nonce: [u8; 32],
    /// Number of signing parties.
    pub n: usize,
}

/// Round 1 broadcast: commitment to Gamma_i.
#[derive(Clone, Debug)]
pub struct PresignR1Bcast {
    pub commitment: [u8; 32],
}

/// Round 2 data: decommitment + MtAwc step 1 ciphertexts.
///
/// For each pair (i, j) where i is this party (Alice):
/// - c_gamma\[j\] = Enc(pk_i, gamma_i) -- sent to Bob j
/// - c_x\[j\] = Enc(pk_i, x_i) -- sent to Bob j
///
/// The Alice states are kept locally for Round 4 decryption.
pub struct PresignR2Data {
    /// Commitment nonce.
    pub nonce: [u8; 32],
    /// Gamma point Gamma_i (compressed bytes via GroupEncoding).
    pub gamma_point_bytes: Vec<u8>,
    /// MtAwc ciphertexts for gamma_i (one per party, None for self).
    pub c_gamma: Vec<Option<ClCiphertext>>,
    /// MtAwc ciphertexts for x_i (one per party, None for self).
    pub c_x: Vec<Option<ClCiphertext>>,
    /// MtAwc Alice states for gamma MtA (kept locally).
    pub gamma_alice_states: Vec<Option<MtAwcAliceState>>,
    /// MtAwc Alice states for key MtA (kept locally).
    pub x_alice_states: Vec<Option<MtAwcAliceState>>,
}

/// Round 3 data: MtAwc Bob outputs for each counterparty.
pub struct PresignR3Data {
    /// For each other party j: MtAwc Bob output for k_i * gamma_j.
    /// This party is Bob (secret = k_i), party j is Alice (secret = gamma_j).
    pub gamma_bob_outputs: Vec<Option<MtAwcBobOutput>>,
    /// For each other party j: MtAwc Bob output for k_i * x_j.
    /// This party is Bob (secret = k_i), party j is Alice (secret = x_j).
    pub x_bob_outputs: Vec<Option<MtAwcBobOutput>>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deserialize a compressed EC point from bytes.
fn point_from_bytes(
    bytes: &[u8],
    label: &str,
) -> Result<k256::ProjectivePoint, Box<dyn std::error::Error>> {
    let repr = k256::CompressedPoint::try_from(bytes)
        .map_err(|e| format!("invalid point bytes ({label}): {e}"))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| format!("invalid EC point: {label}").into())
}

// ---------------------------------------------------------------------------
// Phase 3: Share Revelation (WMY23 Figure 5, Phase 3)
// ---------------------------------------------------------------------------

/// Generate a zero-sharing: `n` random scalars that sum to zero mod q.
///
/// This implements the Shamir zero-sharing `{theta_{ij}} <- SS.Share(0)` from
/// WMY23 Figure 5. The shares are used to blind the delta shares so that
/// individual shares reveal no information, while the global sum is preserved.
///
/// # Arguments
///
/// * `n` - Number of shares to generate (must be >= 1).
/// * `rng` - Cryptographic random number generator.
///
/// # Returns
///
/// A vector of `n` scalars summing to `Scalar::ZERO`.
pub fn share_zero(n: usize, rng: &mut impl CryptoRngCore) -> Vec<k256::Scalar> {
    assert!(n >= 1, "share_zero requires n >= 1");
    let mut shares = Vec::with_capacity(n);
    let mut sum = k256::Scalar::ZERO;
    for _ in 0..(n - 1) {
        let s = k256::Secp256k1::random_scalar(rng);
        sum += s;
        shares.push(s);
    }
    // Last share cancels the sum.
    shares.push(-sum);
    shares
}

/// Per-party Phase 3 output: structured delta shares for all parties.
///
/// Contains the delta shares `delta_{ij}` for party `i` to all parties `j`,
/// plus the proof element `D_i = Gamma^{k_i}`.
pub struct Phase3Output {
    /// Structured delta shares `delta_{ij}` for each party `j`.
    /// `delta_shares[i] = k_i * gamma_i + theta_{ii}` (self share)
    /// `delta_shares[j] = alpha_{ij} + beta_{ji} + theta_{ij}` (cross shares, j != i)
    pub delta_shares: Vec<k256::Scalar>,
    /// Proof element `D_i = Gamma^{k_i}` (for verification in Phase 3).
    pub big_d_i: k256::ProjectivePoint,
}

// ---------------------------------------------------------------------------
// Round 1
// ---------------------------------------------------------------------------

/// Round 1: Sample k_i, gamma_i; commit to Gamma_i.
pub fn presign_round1(
    index: usize,
    n: usize,
    rng: &mut impl CryptoRngCore,
) -> (PresignR1State, PresignR1Bcast) {
    let k_i = k256::Secp256k1::random_scalar(rng);
    let gamma_i = k256::Secp256k1::random_scalar(rng);
    let gamma_point_i = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * gamma_i;

    let gamma_point_bytes = gamma_point_i.to_bytes();

    // Commit: H(nonce || gamma_point_bytes)
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let commitment: [u8; 32] = Sha256::new()
        .chain_update(nonce)
        .chain_update(gamma_point_bytes)
        .finalize()
        .into();

    let state = PresignR1State {
        index,
        k_i,
        gamma_i,
        gamma_point_i,
        nonce,
        n,
    };

    (state, PresignR1Bcast { commitment })
}

// ---------------------------------------------------------------------------
// Round 2
// ---------------------------------------------------------------------------

/// Round 2: Decommit Gamma_i and run MtAwc step 1 (Alice side).
///
/// For each pair (i, j) where i = this party (Alice):
/// - Encrypt k_i under own CL key (for gamma MtA, paper convention)
/// - Encrypt x_i under own CL key (for key MtA)
///
/// Bob j will use his gamma_j to compute homomorphic products for the
/// gamma MtA (producing k_i * gamma_j), and k_j for the key MtA.
pub fn presign_round2(
    state: &PresignR1State,
    key_share: &Wmy23KeyShare,
    setup: &mut ClSetup,
) -> Result<PresignR2Data, Box<dyn std::error::Error>> {
    let n = state.n;
    let my_idx = state.index;

    // Use our own CL public key directly from the key share
    let my_pk = &key_share.cl_pks[my_idx];

    let mut c_gamma: Vec<Option<ClCiphertext>> = Vec::with_capacity(n);
    let mut c_x: Vec<Option<ClCiphertext>> = Vec::with_capacity(n);
    let mut gamma_alice_states: Vec<Option<MtAwcAliceState>> = Vec::with_capacity(n);
    let mut x_alice_states: Vec<Option<MtAwcAliceState>> = Vec::with_capacity(n);

    for j in 0..n {
        if j == my_idx {
            c_gamma.push(None);
            c_x.push(None);
            gamma_alice_states.push(None);
            x_alice_states.push(None);
            continue;
        }

        // MtAwc step 1 for k_i: Alice (me) encrypts k_i under own key
        // (paper convention: Alice holds k, Bob holds gamma)
        let (gamma_state, gamma_ct) = mtawc::mtawc_alice_step1(setup, my_pk, &state.k_i)?;

        // MtAwc step 1 for x_i: Alice (me) encrypts x_i under own key
        let (x_state, x_ct) = mtawc::mtawc_alice_step1(setup, my_pk, &key_share.secret_share)?;

        c_gamma.push(Some(gamma_ct));
        c_x.push(Some(x_ct));
        gamma_alice_states.push(Some(gamma_state));
        x_alice_states.push(Some(x_state));
    }

    Ok(PresignR2Data {
        nonce: state.nonce,
        gamma_point_bytes: state.gamma_point_i.to_bytes().to_vec(),
        c_gamma,
        c_x,
        gamma_alice_states,
        x_alice_states,
    })
}

// ---------------------------------------------------------------------------
// Round 3
// ---------------------------------------------------------------------------

/// Round 3: Bob side of MtAwc.
///
/// For each pair (j, i) where i = this party (Bob):
/// - Gamma MtA: Bob uses gamma_i against Alice j's ciphertext of k_j
///   (producing k_j * gamma_i, matching the paper convention)
/// - Key MtA: Bob uses k_i against Alice j's ciphertext of x_j
///   (producing x_j * k_i)
pub fn presign_round3_bob(
    r1_state: &PresignR1State,
    key_share: &Wmy23KeyShare,
    r2_datas: &[PresignR2Data],
    setup: &mut ClSetup,
    rng: &mut impl CryptoRngCore,
) -> Result<PresignR3Data, Box<dyn std::error::Error>> {
    let n = r1_state.n;
    let my_idx = r1_state.index;
    let k_i = &r1_state.k_i;
    let gamma_i = &r1_state.gamma_i;

    let mut gamma_bob_outputs: Vec<Option<MtAwcBobOutput>> = Vec::with_capacity(n);
    let mut x_bob_outputs: Vec<Option<MtAwcBobOutput>> = Vec::with_capacity(n);

    for j in 0..n {
        if j == my_idx {
            gamma_bob_outputs.push(None);
            x_bob_outputs.push(None);
            continue;
        }

        // Party j is Alice. We (party my_idx) are Bob.
        // Alice (party j) encrypted k_j (gamma MtA) and x_j (key MtA)
        // under party j's CL key.
        let pk_j = &key_share.cl_pks[j];

        // MtAwc Bob for gamma_i * k_j (paper convention: Bob holds gamma)
        let c_gamma_j = r2_datas[j].c_gamma[my_idx]
            .as_ref()
            .ok_or_else(|| format!("missing gamma ciphertext from party {j}"))?;
        let gamma_bob = mtawc::mtawc_bob(setup, pk_j, c_gamma_j, gamma_i, rng)?;

        // MtAwc Bob for k_i * x_j (key MtA unchanged)
        let c_x_j = r2_datas[j].c_x[my_idx]
            .as_ref()
            .ok_or_else(|| format!("missing x ciphertext from party {j}"))?;
        let x_bob = mtawc::mtawc_bob(setup, pk_j, c_x_j, k_i, rng)?;

        gamma_bob_outputs.push(Some(gamma_bob));
        x_bob_outputs.push(Some(x_bob));
    }

    Ok(PresignR3Data {
        gamma_bob_outputs,
        x_bob_outputs,
    })
}

// ---------------------------------------------------------------------------
// Round 4
// ---------------------------------------------------------------------------

/// Round 4: Alice decrypts, computes structured delta shares (Phase 3),
/// sigma_i, and reconstructs R.
///
/// **Phase 3 (WMY23 Figure 5):** After MtAwc, each party constructs
/// structured delta shares using zero-sharing:
///
/// 1. Generate zero-sharing: `{theta_{ij}}` with `sum_j theta_{ij} = 0`
/// 2. `delta_{ii} = k_i * gamma_i + theta_{ii}` (self share)
/// 3. `delta_{ij} = alpha_{ij} + beta_{ji} + theta_{ij}` (cross shares)
/// 4. Compute `D_i = Gamma^{k_i}` (proof element for verification)
/// 5. Broadcast `{delta_{ij}}_j` and `D_i`
///
/// The zero-sharing preserves the global invariant:
/// `sum_i delta_i = sum_i (k_i * gamma_i + sum_j alpha_{ij} + sum_j beta_{ji}) = k * gamma`
/// because `sum_j theta_{ij} = 0` for each party `i`.
///
/// For each pair where this party is Alice:
/// - Decrypt Bob's response to get alpha (gamma MtA) and mu (key MtA)
///
/// Then compute structured delta shares and sigma_i, reconstruct R.
///
/// # Phase 3 verification (WMY23 Figure 5, Step 5)
///
/// After computing `delta_i` and `D_i = Gamma^{k_i}`, verify:
///
/// ```text
/// g^{delta_{i,P}} * prod_{l in P\{i}} (B_{il}/B_{li})^{L_{l,P}} == D_i
/// ```
///
/// where `B_{il} = g^{beta}` from the gamma MtA in which party `i` was
/// Alice and party `l` was Bob, and `B_{li} = g^{beta}` from the gamma
/// MtA in which party `l` was Alice and party `i` was Bob.
///
/// The robustness claim of WMY23 is challenged by TX25 (Section 5).
/// See crate-level security warning in `lib.rs`.
///
/// # Arguments
///
/// * `all_delta_i` - Mutable slice for storing each party's delta_i (sum of
///   structured delta shares). Must be pre-populated with all other parties'
///   values before this function can reconstruct the global delta.
/// * `all_phase3` - Optional output slice for storing per-party `Phase3Output`
///   (structured delta shares + D_i). Pass `None` to skip Phase 3 output
///   storage. Used for verification in the full protocol.
pub fn presign_round4_finalize(
    r1_state: &PresignR1State,
    r1_bcasts: &[PresignR1Bcast],
    r2_datas: &[PresignR2Data],
    r3_datas: &[PresignR3Data],
    key_share: &Wmy23KeyShare,
    all_delta_i: &mut [k256::Scalar],
    all_phase3: Option<&mut [Option<Phase3Output>]>,
    setup: &mut ClSetup,
    rng: &mut impl CryptoRngCore,
) -> Result<Wmy23Presignature, Box<dyn std::error::Error>> {
    let n = r1_state.n;
    let my_idx = r1_state.index;
    let k_i = r1_state.k_i;
    let gamma_i = r1_state.gamma_i;

    // Verify all gamma point commitments (constant-time comparison)
    for j in 0..n {
        let expected: [u8; 32] = Sha256::new()
            .chain_update(r2_datas[j].nonce)
            .chain_update(&r2_datas[j].gamma_point_bytes)
            .finalize()
            .into();
        if bool::from(!expected.ct_eq(&r1_bcasts[j].commitment)) {
            return Err(format!("gamma commitment failed for party {j}").into());
        }
    }

    // Use CL secret key and public key directly from key share
    let my_pk = &key_share.cl_pks[my_idx];

    // Collect per-counterparty MtAwc shares
    let mut alphas: Vec<k256::Scalar> = vec![k256::Scalar::ZERO; n]; // alpha_{ij}: I am Alice (k_i)
    let mut betas: Vec<k256::Scalar> = vec![k256::Scalar::ZERO; n]; // beta_{ji}: I am Bob (gamma_i)
    let mut mu_sum = k256::Scalar::ZERO; // sum of mu_{ij} (I am Alice for key MtA)
    let mut nu_sum = k256::Scalar::ZERO; // sum of nu_{ji} (I am Bob for key MtA)

    for j in 0..n {
        if j == my_idx {
            continue;
        }

        // ---- Gamma MtA: I am Alice (k_i), party j is Bob (gamma_j) ----
        // Product: k_i * gamma_j = alphas[j] + beta_Bob_j
        let gamma_bob_out = r3_datas[j].gamma_bob_outputs[my_idx]
            .as_ref()
            .ok_or("missing gamma bob output")?;

        let gamma_alice_state = r2_datas[my_idx].gamma_alice_states[j]
            .as_ref()
            .ok_or("missing gamma alice state")?;

        let alpha_out = mtawc::mtawc_alice_step2_no_gb_check(
            setup,
            my_pk,
            &key_share.cl_sk,
            &gamma_bob_out.c_alpha,
            &gamma_bob_out.g_beta,
            gamma_alice_state,
        )?;
        alphas[j] = alpha_out.alpha;

        // ---- Key MtA: I am Alice (x_i), party j is Bob (k_j) ----
        let x_bob_out = r3_datas[j].x_bob_outputs[my_idx]
            .as_ref()
            .ok_or("missing x bob output")?;

        let x_alice_state = r2_datas[my_idx].x_alice_states[j]
            .as_ref()
            .ok_or("missing x alice state")?;

        let mu_out = mtawc::mtawc_alice_step2_no_gb_check(
            setup,
            my_pk,
            &key_share.cl_sk,
            &x_bob_out.c_alpha,
            &x_bob_out.g_beta,
            x_alice_state,
        )?;
        mu_sum += mu_out.alpha;

        // ---- Gamma MtA: I am Bob (gamma_i), party j is Alice (k_j) ----
        // Product: k_j * gamma_i = alpha_Alice_j + betas[j]
        let my_gamma_bob = r3_datas[my_idx].gamma_bob_outputs[j]
            .as_ref()
            .ok_or("missing my gamma bob output")?;
        betas[j] = my_gamma_bob.beta;

        // ---- Key MtA: I am Bob (k_i), party j is Alice (x_j) ----
        let my_x_bob = r3_datas[my_idx].x_bob_outputs[j]
            .as_ref()
            .ok_or("missing my x bob output")?;
        nu_sum += my_x_bob.beta;
    }

    // --- Phase 3: Zero-sharing + structured delta shares ---
    // WMY23 Figure 5, Phase 3, Step 3: {theta_{ij}} <- SS.Share(0)
    let theta = share_zero(n, rng);

    let mut delta_shares = Vec::with_capacity(n);
    for j in 0..n {
        if j == my_idx {
            // delta_{ii} = k_i * gamma_i + theta_{ii}
            delta_shares.push(k_i * gamma_i + theta[j]);
        } else {
            // delta_{ij} = alpha_{ij} + beta_{ji} + theta_{ij}
            delta_shares.push(alphas[j] + betas[j] + theta[j]);
        }
    }

    // Reconstruct Gamma = sum(Gamma_j)
    let mut gamma_sum = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for j in 0..n {
        let gamma_point_j = point_from_bytes(
            &r2_datas[j].gamma_point_bytes,
            &format!("gamma point party {j}"),
        )?;
        gamma_sum += gamma_point_j;
    }

    // WMY23 Figure 5, Phase 3, Step 1: D_i = Gamma^{k_i}
    let big_d_i = gamma_sum * k_i;

    // Store Phase 3 output if requested
    if let Some(phase3_out) = all_phase3 {
        phase3_out[my_idx] = Some(Phase3Output {
            delta_shares,
            big_d_i,
        });
    }

    // delta_i = sum of this party's structured delta shares
    // (equals k_i * gamma_i + sum(alpha_{ij}) + sum(beta_{ji}) by construction,
    //  since sum(theta_{ij}) = 0)
    let alpha_sum: k256::Scalar = alphas.iter().copied().sum();
    let beta_sum: k256::Scalar = betas.iter().copied().sum();
    let delta_i = k_i * gamma_i + alpha_sum + beta_sum;
    all_delta_i[my_idx] = delta_i;

    // Phase 3 verification (WMY23 Figure 5, Step 5):
    //   g^{delta_{i,P}} * prod_{l in P\{i}} (B_{il}/B_{li})^{L_{l,P}} == D_i
    //
    // For the simplified (n,n) presign all Lagrange weights are 1.
    // B_{il} = g^{beta} where i was Alice (gamma MtA), l was Bob.
    // B_{li} = g^{beta} where l was Alice (gamma MtA), i was Bob.
    //
    // The robustness claim of WMY23 is challenged by TX25 (Section 5).
    // See crate-level security warning in lib.rs.
    {
        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let mut lhs = g * delta_i;
        for j in 0..n {
            if j == my_idx {
                continue;
            }
            // B_{ij}: I am Alice, j is Bob => Bob j's g_beta for me
            let b_ij = r3_datas[j].gamma_bob_outputs[my_idx]
                .as_ref()
                .ok_or("B_{ij}: missing gamma bob output")?
                .g_beta;
            // B_{ji}: j is Alice, I am Bob => my g_beta for Alice j
            let b_ji = r3_datas[my_idx].gamma_bob_outputs[j]
                .as_ref()
                .ok_or("B_{ji}: missing gamma bob output")?
                .g_beta;
            lhs += b_ij - b_ji;
        }
        if bool::from(!lhs.to_bytes().ct_eq(&big_d_i.to_bytes())) {
            return Err(format!(
                "Phase 3 B_{{ij}}/B_{{ji}} verification failed for party {my_idx}"
            )
            .into());
        }
    }

    // sigma_i = k_i * x_i + sum(mu_{ij}) + sum(nu_{ji})
    let sigma_i = k_i * key_share.secret_share + mu_sum + nu_sum;

    // Reconstruct delta = sum(delta_j)
    let delta: k256::Scalar = all_delta_i.iter().copied().sum();

    // Compute delta^{-1}
    let delta_inv = delta
        .invert()
        .into_option()
        .ok_or("delta is zero, cannot invert")?;

    // R = delta^{-1} * Gamma = (k*gamma)^{-1} * gamma*G = (1/k)*G
    let big_r = gamma_sum * delta_inv;

    // r = x_coord(R) mod q
    let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine());

    Ok(Wmy23Presignature {
        k_i,
        big_r,
        r_x,
        sigma_i,
        n_signers: n,
    })
}

// ===========================================================================
// DRG-based presign (WMY23 Figure 3)
// ===========================================================================

use tecdsa_class_group::drg::{
    drg_comb, drg_gen, drg_gen_verify, DrgCombOutput, DrgGenOutput, PedersenVssShare,
};

/// Per-party state after DRG-based Round 1.
///
/// Contains the DRG.Gen outputs for both `k_i` (nonce share) and
/// `gamma_i` (mask share), plus a hash commitment to `Gamma_i`.
pub struct DrgPresignR1State {
    /// Party index (0-based).
    pub index: usize,
    /// Number of signing parties.
    pub n: usize,
    /// DRG.Gen output for the nonce share `k_i`.
    pub k_gen: DrgGenOutput,
    /// DRG.Gen output for the mask share `gamma_i`.
    pub gamma_gen: DrgGenOutput,
    /// Gamma point `Gamma_i = gamma_i * G`.
    pub gamma_point_i: k256::ProjectivePoint,
    /// Commitment nonce for Gamma_i.
    pub nonce: [u8; 32],
}

/// DRG-based Round 1 broadcast: commitment + DRG public data.
pub struct DrgPresignR1Bcast {
    /// Hash commitment `H(nonce || Gamma_i_bytes)`.
    pub commitment: [u8; 32],
    /// Pedersen VSS commitments for k_i.
    pub k_commitments: Vec<k256::ProjectivePoint>,
    /// Pedersen VSS commitments for gamma_i.
    pub gamma_commitments: Vec<k256::ProjectivePoint>,
}

/// DRG-based Round 1 P2P data: VSS shares for one recipient.
pub struct DrgPresignR1P2P {
    /// Pedersen VSS share of k for this recipient.
    pub k_share: PedersenVssShare,
    /// Pedersen VSS share of gamma for this recipient.
    pub gamma_share: PedersenVssShare,
}

/// DRG-based Round 1: DRG.Gen for k_i and gamma_i.
///
/// Each party:
/// 1. Samples `k_i` and `gamma_i`.
/// 2. Runs DRG.Gen for each, producing Pedersen VSS shares and CL ciphertexts.
/// 3. Commits to `Gamma_i = gamma_i * G`.
///
/// Returns: per-party state, broadcast data, and P2P data for each other party.
///
/// # Errors
///
/// Returns an error if CL operations fail.
// Returns (state, broadcast, per-party P2P) for round 1; the tuple maps
// directly to the round's outputs, so a type alias would not aid clarity.
#[allow(clippy::type_complexity)]
pub fn drg_presign_round1(
    index: usize,
    n: usize,
    threshold: u16,
    key_share: &Wmy23KeyShare,
    setup: &mut ClSetup,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        DrgPresignR1State,
        DrgPresignR1Bcast,
        Vec<Option<DrgPresignR1P2P>>,
    ),
    Box<dyn std::error::Error>,
> {
    // Use own CL public key directly from key share
    let my_pk = &key_share.cl_pks[index];

    // DRG.Gen for k_i
    let k_gen = drg_gen(setup, my_pk, threshold, n as u16, rng)?;

    // DRG.Gen for gamma_i
    let gamma_gen = drg_gen(setup, my_pk, threshold, n as u16, rng)?;

    // Gamma_i = gamma_i * G
    let gamma_point_i =
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * gamma_gen.secret;
    let gamma_point_bytes = gamma_point_i.to_bytes();

    // Commit: H(nonce || gamma_point_bytes)
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let commitment: [u8; 32] = Sha256::new()
        .chain_update(nonce)
        .chain_update(gamma_point_bytes)
        .finalize()
        .into();

    // P2P shares: for each party j != index
    let mut p2p: Vec<Option<DrgPresignR1P2P>> = Vec::with_capacity(n);
    for j in 0..n {
        if j == index {
            p2p.push(None);
        } else {
            p2p.push(Some(DrgPresignR1P2P {
                k_share: k_gen.vss_shares[j].clone(),
                gamma_share: gamma_gen.vss_shares[j].clone(),
            }));
        }
    }

    let state = DrgPresignR1State {
        index,
        n,
        k_gen,
        gamma_gen,
        gamma_point_i,
        nonce,
    };

    let bcast = DrgPresignR1Bcast {
        commitment,
        k_commitments: state.k_gen.commitments.clone(),
        gamma_commitments: state.gamma_gen.commitments.clone(),
    };

    Ok((state, bcast, p2p))
}

/// Per-party state after DRG-based Round 2.
pub struct DrgPresignR2State {
    /// DRG.Comb output for the nonce share `k`.
    pub k_comb: DrgCombOutput,
    /// DRG.Comb output for the mask share `gamma`.
    pub gamma_comb: DrgCombOutput,
    /// Lagrange-weighted nonce share: `hat_k_i = lambda_i * k_comb.combined_share`.
    /// This is the effective additive contribution to `k = sum hat_k_i`.
    pub hat_k_i: k256::Scalar,
    /// Lagrange-weighted mask share: `hat_gamma_i = lambda_i * gamma_comb.combined_share`.
    pub hat_gamma_i: k256::Scalar,
    /// Decommitment nonce.
    pub nonce: [u8; 32],
    /// Gamma point bytes (for decommitment). `Gamma_i = g^{hat_gamma_i}`.
    pub gamma_point_bytes: Vec<u8>,
}

/// DRG-based Round 2 broadcast: decommitment + MtAwc Alice step 1.
pub struct DrgPresignR2Bcast {
    /// Decommitment nonce.
    pub nonce: [u8; 32],
    /// Gamma point bytes.
    pub gamma_point_bytes: Vec<u8>,
    /// MtAwc ciphertexts for gamma_i (one per party, None for self).
    /// Alice encrypts gamma_i under own CL key.
    pub c_gamma: Vec<Option<ClCiphertext>>,
    /// MtAwc ciphertexts for x_i (one per party, None for self).
    pub c_x: Vec<Option<ClCiphertext>>,
    /// MtAwc Alice states for gamma MtA (kept locally by the sender).
    pub gamma_alice_states: Vec<Option<MtAwcAliceState>>,
    /// MtAwc Alice states for key MtA (kept locally by the sender).
    pub x_alice_states: Vec<Option<MtAwcAliceState>>,
}

/// DRG-based Round 2: DRG.GenVf + DRG.Comb + MtAwc Alice step 1.
///
/// Each party:
/// 1. Verifies received Pedersen VSS shares from all other parties.
/// 2. Combines shares via DRG.Comb for both k and gamma.
/// 3. Runs MtAwc Alice step 1 (encrypt gamma_i and x_i under own key).
///
/// # Errors
///
/// Returns an error if verification or CL operations fail.
pub fn drg_presign_round2(
    r1_state: &DrgPresignR1State,
    r1_bcasts: &[DrgPresignR1Bcast],
    r1_p2ps: &[Vec<Option<DrgPresignR1P2P>>],
    r1_states: &[DrgPresignR1State],
    key_share: &Wmy23KeyShare,
    setup: &mut ClSetup,
) -> Result<(DrgPresignR2State, DrgPresignR2Bcast), Box<dyn std::error::Error>> {
    let n = r1_state.n;
    let my_idx = r1_state.index;
    let my_index_1based = (my_idx + 1) as u16;

    // Step 1: DRG.GenVf -- verify all received shares
    for i in 0..n {
        if i == my_idx {
            continue;
        }
        // Get the share that party i sent to us (party my_idx)
        let p2p = r1_p2ps[i][my_idx]
            .as_ref()
            .ok_or_else(|| format!("missing P2P data from party {i}"))?;

        // Use party i's CL public key directly from key share
        let pk_i = &key_share.cl_pks[i];

        // Verify k share with full R_Enc-PC proof verification.
        let k_ok = drg_gen_verify(
            setup,
            pk_i,
            &r1_bcasts[i].k_commitments,
            &r1_states[i].k_gen.ciphertext,
            &r1_states[i].k_gen.proof,
            &r1_states[i].k_gen.y_element,
            &p2p.k_share,
        )?;
        if !k_ok {
            return Err(format!("DRG.GenVf: k share from party {i} failed").into());
        }

        // Verify gamma share with full R_Enc-PC proof verification.
        let gamma_ok = drg_gen_verify(
            setup,
            pk_i,
            &r1_bcasts[i].gamma_commitments,
            &r1_states[i].gamma_gen.ciphertext,
            &r1_states[i].gamma_gen.proof,
            &r1_states[i].gamma_gen.y_element,
            &p2p.gamma_share,
        )?;
        if !gamma_ok {
            return Err(format!("DRG.GenVf: gamma share from party {i} failed").into());
        }
    }

    // Step 2: DRG.Comb -- combine shares for k and gamma
    let my_pk = &key_share.cl_pks[my_idx];

    // Collect received k shares (including own)
    let mut k_received: Vec<(u16, PedersenVssShare)> = Vec::with_capacity(n);
    let mut k_commitments_all: Vec<(u16, Vec<k256::ProjectivePoint>)> = Vec::with_capacity(n);
    let mut gamma_received: Vec<(u16, PedersenVssShare)> = Vec::with_capacity(n);
    let mut gamma_commitments_all: Vec<(u16, Vec<k256::ProjectivePoint>)> = Vec::with_capacity(n);

    for i in 0..n {
        let sender_1based = (i + 1) as u16;
        if i == my_idx {
            // Own shares
            k_received.push((sender_1based, r1_state.k_gen.vss_shares[my_idx].clone()));
            gamma_received.push((sender_1based, r1_state.gamma_gen.vss_shares[my_idx].clone()));
        } else {
            let p2p = r1_p2ps[i][my_idx]
                .as_ref()
                .ok_or_else(|| format!("missing P2P from party {i}"))?;
            k_received.push((sender_1based, p2p.k_share.clone()));
            gamma_received.push((sender_1based, p2p.gamma_share.clone()));
        }
        k_commitments_all.push((sender_1based, r1_bcasts[i].k_commitments.clone()));
        gamma_commitments_all.push((sender_1based, r1_bcasts[i].gamma_commitments.clone()));
    }

    let k_comb = drg_comb(
        setup,
        my_pk,
        my_index_1based,
        &k_received,
        &k_commitments_all,
    )?;
    let gamma_comb = drg_comb(
        setup,
        my_pk,
        my_index_1based,
        &gamma_received,
        &gamma_commitments_all,
    )?;

    // Compute Lagrange coefficient for this party.
    let signer_indices: Vec<u16> = (1..=(n as u16)).collect();
    let lagrange_coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&signer_indices);
    let lambda_i = lagrange_coeffs[my_idx];

    // Lagrange-weighted shares
    let hat_k_i = lambda_i * k_comb.combined_share;
    let hat_gamma_i = lambda_i * gamma_comb.combined_share;

    // Step 3: MtAwc Alice step 1 -- encrypt hat_k_i and x_i
    // Paper convention: Alice encrypts k, Bob uses gamma.
    let mut c_gamma: Vec<Option<ClCiphertext>> = Vec::with_capacity(n);
    let mut c_x: Vec<Option<ClCiphertext>> = Vec::with_capacity(n);
    let mut gamma_alice_states: Vec<Option<MtAwcAliceState>> = Vec::with_capacity(n);
    let mut x_alice_states: Vec<Option<MtAwcAliceState>> = Vec::with_capacity(n);

    for j in 0..n {
        if j == my_idx {
            c_gamma.push(None);
            c_x.push(None);
            gamma_alice_states.push(None);
            x_alice_states.push(None);
            continue;
        }

        // MtAwc step 1 for gamma MtA: encrypt hat_k_i under own key
        // (paper convention: Alice holds k, Bob holds gamma)
        let (gamma_state, gamma_ct) = mtawc::mtawc_alice_step1(setup, my_pk, &hat_k_i)?;
        c_gamma.push(Some(gamma_ct));
        gamma_alice_states.push(Some(gamma_state));

        // MtAwc step 1 for x: encrypt x_i under own key
        let (x_state, x_ct) = mtawc::mtawc_alice_step1(setup, my_pk, &key_share.secret_share)?;
        c_x.push(Some(x_ct));
        x_alice_states.push(Some(x_state));
    }

    let r2_state = DrgPresignR2State {
        k_comb,
        gamma_comb,
        hat_k_i,
        hat_gamma_i,
        nonce: r1_state.nonce,
        gamma_point_bytes: r1_state.gamma_point_i.to_bytes().to_vec(),
    };

    let r2_bcast = DrgPresignR2Bcast {
        nonce: r1_state.nonce,
        gamma_point_bytes: r1_state.gamma_point_i.to_bytes().to_vec(),
        c_gamma,
        c_x,
        gamma_alice_states,
        x_alice_states,
    };

    Ok((r2_state, r2_bcast))
}

/// DRG-based Round 3 data: MtAwc Bob outputs.
pub struct DrgPresignR3Data {
    /// For each other party j: MtAwc Bob output for k_i * gamma_j.
    pub gamma_bob_outputs: Vec<Option<MtAwcBobOutput>>,
    /// For each other party j: MtAwc Bob output for k_i * x_j.
    pub x_bob_outputs: Vec<Option<MtAwcBobOutput>>,
}

/// DRG-based Round 3: MtAwc Bob step.
///
/// For each pair (j, i) where i = this party (Bob):
/// - Gamma MtA: Bob uses hat_gamma_i against Alice j's ciphertext of
///   hat_k_j (producing hat_k_j * hat_gamma_i, paper convention).
/// - Key MtA: Bob uses hat_k_i against Alice j's ciphertext of x_j
///   (producing x_j * hat_k_i).
///
/// # Errors
///
/// Returns an error if CL operations fail.
pub fn drg_presign_round3_bob(
    r2_state: &DrgPresignR2State,
    r1_state: &DrgPresignR1State,
    key_share: &Wmy23KeyShare,
    r2_bcasts: &[DrgPresignR2Bcast],
    setup: &mut ClSetup,
    rng: &mut impl CryptoRngCore,
) -> Result<DrgPresignR3Data, Box<dyn std::error::Error>> {
    let n = r1_state.n;
    let my_idx = r1_state.index;
    let hat_k_i = &r2_state.hat_k_i;
    let hat_gamma_i = &r2_state.hat_gamma_i;

    let mut gamma_bob_outputs: Vec<Option<MtAwcBobOutput>> = Vec::with_capacity(n);
    let mut x_bob_outputs: Vec<Option<MtAwcBobOutput>> = Vec::with_capacity(n);

    for j in 0..n {
        if j == my_idx {
            gamma_bob_outputs.push(None);
            x_bob_outputs.push(None);
            continue;
        }

        // Use party j's CL public key directly from key share
        let pk_j = &key_share.cl_pks[j];

        // MtAwc Bob for hat_gamma_i * hat_k_j
        // (paper convention: Alice holds k, Bob holds gamma)
        let c_gamma_j = r2_bcasts[j].c_gamma[my_idx]
            .as_ref()
            .ok_or_else(|| format!("missing gamma ciphertext from party {j}"))?;
        let gamma_bob = mtawc::mtawc_bob(setup, pk_j, c_gamma_j, hat_gamma_i, rng)?;

        // MtAwc Bob for hat_k_i * x_j (key MtA unchanged)
        let c_x_j = r2_bcasts[j].c_x[my_idx]
            .as_ref()
            .ok_or_else(|| format!("missing x ciphertext from party {j}"))?;
        let x_bob = mtawc::mtawc_bob(setup, pk_j, c_x_j, hat_k_i, rng)?;

        gamma_bob_outputs.push(Some(gamma_bob));
        x_bob_outputs.push(Some(x_bob));
    }

    Ok(DrgPresignR3Data {
        gamma_bob_outputs,
        x_bob_outputs,
    })
}

/// DRG-based Round 4: Alice decrypt + Phase 3 share revelation + finalize.
///
/// **Phase 3 (WMY23 Figure 5):** After MtAwc, each party constructs
/// structured delta shares using zero-sharing for cheater identification:
///
/// 1. Generate zero-sharing: `{theta_{ij}}` with `sum_j theta_{ij} = 0`
/// 2. `delta_{ii} = hat_k_i * hat_gamma_i + theta_{ii}` (self share)
/// 3. `delta_{ij} = alpha_{ij} + beta_{ji} + theta_{ij}` (cross shares)
/// 4. Compute `D_i = Gamma^{hat_k_i}` (proof element)
/// 5. Broadcast `{delta_{ij}}_j` and `D_i`
///
/// # Phase 3 verification (WMY23 Figure 5, Step 5)
///
/// After computing `delta_i` and `D_i = Gamma^{hat_k_i}`, verify:
///
/// ```text
/// g^{delta_{i,P}} * prod_{l in P\{i}} (B_{il}/B_{li})^{L_{l,P}} == D_i
/// ```
///
/// where `B_{il} = g^{beta}` from the gamma MtA in which party `i` was
/// Alice and party `l` was Bob, and `B_{li} = g^{beta}` from the gamma
/// MtA in which party `l` was Alice and party `i` was Bob.
///
/// The robustness claim of WMY23 is challenged by TX25 (Section 5).
/// See crate-level security warning in `lib.rs`.
///
/// # Arguments
///
/// * `all_delta_i` - Mutable slice for storing each party's delta_i.
/// * `all_phase3` - Optional output for storing `Phase3Output` (structured
///   delta shares + D_i).
///
/// # Errors
///
/// Returns an error if decryption, R reconstruction, or Phase 3
/// verification fails.
pub fn drg_presign_round4_finalize(
    r1_state: &DrgPresignR1State,
    r1_bcasts: &[DrgPresignR1Bcast],
    r2_state: &DrgPresignR2State,
    r2_bcasts: &[DrgPresignR2Bcast],
    r3_datas: &[DrgPresignR3Data],
    key_share: &Wmy23KeyShare,
    all_delta_i: &mut [k256::Scalar],
    all_phase3: Option<&mut [Option<Phase3Output>]>,
    setup: &mut ClSetup,
    rng: &mut impl CryptoRngCore,
) -> Result<Wmy23Presignature, Box<dyn std::error::Error>> {
    let n = r1_state.n;
    let my_idx = r1_state.index;
    let hat_k_i = r2_state.hat_k_i;
    let hat_gamma_i = r2_state.hat_gamma_i;

    // Verify all gamma point commitments
    for j in 0..n {
        let expected: [u8; 32] = Sha256::new()
            .chain_update(r2_bcasts[j].nonce)
            .chain_update(&r2_bcasts[j].gamma_point_bytes)
            .finalize()
            .into();
        if bool::from(!expected.ct_eq(&r1_bcasts[j].commitment)) {
            return Err(format!("gamma commitment failed for party {j}").into());
        }
    }

    // Use CL secret key and public key directly from key share
    let my_pk = &key_share.cl_pks[my_idx];

    // Collect per-counterparty MtAwc shares
    let mut alphas: Vec<k256::Scalar> = vec![k256::Scalar::ZERO; n];
    let mut betas: Vec<k256::Scalar> = vec![k256::Scalar::ZERO; n];
    let mut mu_sum = k256::Scalar::ZERO;
    let mut nu_sum = k256::Scalar::ZERO;

    for j in 0..n {
        if j == my_idx {
            continue;
        }

        // ---- Gamma MtA: I am Alice (hat_k_i), party j is Bob (hat_gamma_j) ----
        // Product: hat_k_i * hat_gamma_j = alphas[j] + beta_Bob_j
        let gamma_bob_out = r3_datas[j].gamma_bob_outputs[my_idx]
            .as_ref()
            .ok_or("missing gamma bob output")?;

        let alpha_out = mtawc::mtawc_alice_step2_no_gb_check(
            setup,
            my_pk,
            &key_share.cl_sk,
            &gamma_bob_out.c_alpha,
            &gamma_bob_out.g_beta,
            r2_bcasts[my_idx].gamma_alice_states[j]
                .as_ref()
                .ok_or("missing gamma alice state")?,
        )?;
        alphas[j] = alpha_out.alpha;

        // ---- Key MtA: I am Alice (x_i), party j is Bob (hat_k_j) ----
        let x_bob_out = r3_datas[j].x_bob_outputs[my_idx]
            .as_ref()
            .ok_or("missing x bob output")?;

        let mu_out = mtawc::mtawc_alice_step2_no_gb_check(
            setup,
            my_pk,
            &key_share.cl_sk,
            &x_bob_out.c_alpha,
            &x_bob_out.g_beta,
            r2_bcasts[my_idx].x_alice_states[j]
                .as_ref()
                .ok_or("missing x alice state")?,
        )?;
        mu_sum += mu_out.alpha;

        // ---- Gamma MtA: I am Bob (hat_gamma_i), party j is Alice (hat_k_j) ----
        // Product: hat_k_j * hat_gamma_i = alpha_Alice_j + betas[j]
        let my_gamma_bob = r3_datas[my_idx].gamma_bob_outputs[j]
            .as_ref()
            .ok_or("missing my gamma bob output")?;
        betas[j] = my_gamma_bob.beta;

        // ---- Key MtA: I am Bob (hat_k_i), party j is Alice (x_j) ----
        let my_x_bob = r3_datas[my_idx].x_bob_outputs[j]
            .as_ref()
            .ok_or("missing my x bob output")?;
        nu_sum += my_x_bob.beta;
    }

    // --- Phase 3: Zero-sharing + structured delta shares ---
    // WMY23 Figure 5, Phase 3, Step 3: {theta_{ij}} <- SS.Share(0)
    let theta = share_zero(n, rng);

    let mut delta_shares = Vec::with_capacity(n);
    for j in 0..n {
        if j == my_idx {
            // delta_{ii} = hat_k_i * hat_gamma_i + theta_{ii}
            delta_shares.push(hat_k_i * hat_gamma_i + theta[j]);
        } else {
            // delta_{ij} = alpha_{ij} + beta_{ji} + theta_{ij}
            delta_shares.push(alphas[j] + betas[j] + theta[j]);
        }
    }

    // Reconstruct Gamma = sum(Gamma_j)
    let mut gamma_sum = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for j in 0..n {
        let gamma_point_j = point_from_bytes(
            &r2_bcasts[j].gamma_point_bytes,
            &format!("gamma point party {j}"),
        )?;
        gamma_sum += gamma_point_j;
    }

    // WMY23 Figure 5, Phase 3, Step 1: D_i = Gamma^{hat_k_i}
    let big_d_i = gamma_sum * hat_k_i;

    // Store Phase 3 output if requested
    if let Some(phase3_out) = all_phase3 {
        phase3_out[my_idx] = Some(Phase3Output {
            delta_shares,
            big_d_i,
        });
    }

    // delta_i = hat_k_i * hat_gamma_i + sum(alpha_{ij}) + sum(beta_{ji})
    // (equals sum of structured delta shares, since sum(theta) = 0)
    let alpha_sum: k256::Scalar = alphas.iter().copied().sum();
    let beta_sum: k256::Scalar = betas.iter().copied().sum();
    let delta_i = hat_k_i * hat_gamma_i + alpha_sum + beta_sum;
    all_delta_i[my_idx] = delta_i;

    // Phase 3 verification (WMY23 Figure 5, Step 5):
    //   g^{delta_{i,P}} * prod_{l in P\{i}} (B_{il}/B_{li})^{L_{l,P}} == D_i
    //
    // For the DRG presign, Lagrange weights are already folded into
    // hat_k_i / hat_gamma_i, so the additive-share equation applies
    // directly (all L_l = 1 in the MtA layer).
    // B_{il} = g^{beta} where i was Alice (gamma MtA), l was Bob.
    // B_{li} = g^{beta} where l was Alice (gamma MtA), i was Bob.
    //
    // The robustness claim of WMY23 is challenged by TX25 (Section 5).
    // See crate-level security warning in lib.rs.
    {
        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let mut lhs = g * delta_i;
        for j in 0..n {
            if j == my_idx {
                continue;
            }
            // B_{ij}: I am Alice, j is Bob => Bob j's g_beta for me
            let b_ij = r3_datas[j].gamma_bob_outputs[my_idx]
                .as_ref()
                .ok_or("B_{ij}: missing gamma bob output")?
                .g_beta;
            // B_{ji}: j is Alice, I am Bob => my g_beta for Alice j
            let b_ji = r3_datas[my_idx].gamma_bob_outputs[j]
                .as_ref()
                .ok_or("B_{ji}: missing gamma bob output")?
                .g_beta;
            lhs += b_ij - b_ji;
        }
        if bool::from(!lhs.to_bytes().ct_eq(&big_d_i.to_bytes())) {
            return Err(format!(
                "Phase 3 B_{{ij}}/B_{{ji}} verification failed for party {my_idx}"
            )
            .into());
        }
    }

    // sigma_i = hat_k_i * x_i + sum(mu_{ij}) + sum(nu_{ji})
    let sigma_i = hat_k_i * key_share.secret_share + mu_sum + nu_sum;

    // Reconstruct delta = sum(delta_j)
    let delta: k256::Scalar = all_delta_i.iter().copied().sum();

    // delta^{-1}
    let delta_inv = delta
        .invert()
        .into_option()
        .ok_or("delta is zero, cannot invert")?;

    // R = delta^{-1} * Gamma = (k*gamma)^{-1} * gamma*G = (1/k)*G
    let big_r = gamma_sum * delta_inv;

    // r = x_coord(R) mod q
    let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine());

    // Store hat_k_i in the presignature (the Lagrange-weighted nonce share).
    Ok(Wmy23Presignature {
        k_i: hat_k_i,
        big_r,
        r_x,
        sigma_i,
        n_signers: n,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_zero_sums_to_zero() {
        let mut rng = rand::thread_rng();
        for n in [1, 2, 3, 5, 10] {
            let shares = share_zero(n, &mut rng);
            assert_eq!(shares.len(), n);
            let sum: k256::Scalar = shares.iter().copied().sum();
            assert_eq!(
                sum,
                k256::Scalar::ZERO,
                "share_zero({n}) should produce shares summing to zero"
            );
        }
    }

    #[test]
    fn test_share_zero_randomness() {
        let mut rng = rand::thread_rng();
        // Two calls should produce different shares (with overwhelming probability)
        let shares1 = share_zero(5, &mut rng);
        let shares2 = share_zero(5, &mut rng);
        assert_ne!(
            shares1, shares2,
            "two independent zero-sharings should differ"
        );
    }

    #[test]
    fn test_share_zero_single_element() {
        let mut rng = rand::thread_rng();
        let shares = share_zero(1, &mut rng);
        assert_eq!(shares.len(), 1);
        assert_eq!(
            shares[0],
            k256::Scalar::ZERO,
            "single-element zero-sharing must be zero"
        );
    }
}
