// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 presign round functions (DRG-based, WMY23 Figure 5).
//!
//! Implements the paper's three presign phases as message-driven round
//! functions consumed by [`crate::presign::Wmy23PresignMachine`]:
//!
//! 1. **DRG (Phase 1):** `drg_presign_round1` runs DRG.Gen for the nonce
//!    `k_i` and mask `gamma_i` (Pedersen VSS shares + CL ciphertext +
//!    R_Enc-PC proof), broadcast the public material and send VSS shares
//!    P2P. `drg_presign_round2` runs DRG.GenVf on every received share
//!    (Pedersen VSS check + cross-domain R_Enc-PC proof verification) and
//!    DRG.Comb to derive the combined `(t, n)` shares.
//! 2. **MtAwc (Phase 2):** `drg_presign_round2` also emits the MtAwc
//!    Alice ciphertexts; `drg_presign_round3_bob` answers them
//!    homomorphically (Bob side).
//! 3. **Share revelation (Phase 3):** `drg_presign_round4_compute`
//!    decrypts the MtAwc responses, builds the zero-shared structured
//!    delta shares and `D_i = Gamma^{hat_k_i}`; `drg_presign_finalize`
//!    reconstructs `delta`, checks `g^delta == prod_j D_j` and outputs
//!    `R = Gamma^{1/delta}`.
//!
//! ## Party indexing
//!
//! All round functions identify quorum members by their 0-based position
//! in the signing set. `signer_ids` carries the *global* 1-based keygen
//! indices of the quorum in the same order: CL public keys are addressed
//! as `cl_pks[signer_ids[i] - 1]`, and the signing-key share is
//! Lagrange-weighted over `signer_ids` (so strict subsets of the keygen
//! set can sign). The fresh DRG sharings of `k` and `gamma` are internal
//! to the quorum and use local 1-based indices.

#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_class_group::{
    cl::{ClCiphertext, ClSetup},
    drg::{drg_comb, drg_gen, drg_gen_verify, DrgCombOutput, DrgGenOutput, PedersenVssShare},
    zk::r_enc_pc::REncPcProof,
};
use tecdsa_curve::TecdsaCurve;

use crate::{
    key_share::Wmy23KeyShare,
    mtawc::{self, MtAwcAliceState, MtAwcBobOutput},
    presign::Wmy23Presignature,
};

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

/// The 0-based global keygen index for the party at local position `pos`.
fn global_idx(signer_ids: &[u16], pos: usize) -> usize {
    debug_assert!(signer_ids[pos] >= 1, "signer ids are 1-based");
    (signer_ids[pos] - 1) as usize
}

// ---------------------------------------------------------------------------
// Phase 3 helpers: Share Revelation (WMY23 Figure 5, Phase 3)
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
/// plus the proof element `D_i = Gamma^{hat_k_i}`.
pub struct Phase3Output {
    /// Structured delta shares `delta_{ij}` for each party `j`.
    /// `delta_shares[i] = hat_k_i * hat_gamma_i + theta_{ii}` (self share)
    /// `delta_shares[j] = alpha_{ij} + beta_{ji} + theta_{ij}` (cross shares)
    pub delta_shares: Vec<k256::Scalar>,
    /// Proof element `D_i = Gamma^{hat_k_i}` (broadcast in Phase 3).
    pub big_d_i: k256::ProjectivePoint,
}

// ===========================================================================
// DRG-based presign (WMY23 Figure 5)
// ===========================================================================

/// Per-party state after DRG-based Round 1.
///
/// Contains the DRG.Gen outputs for both `k_i` (nonce share) and
/// `gamma_i` (mask share), plus a hash commitment to `Gamma_i`.
pub struct DrgPresignR1State {
    /// Party index (0-based, local to the signing quorum).
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

/// DRG-based Round 1 broadcast: commitment + DRG.Gen public data.
///
/// Carries everything a verifier needs for DRG.GenVf: the Pedersen VSS
/// polynomial commitments, the dealer's CL ciphertext of its secret, and
/// the R_Enc-PC proof linking the two. The EC Pedersen commitment `PC`
/// used by the proof is `commitments[0]`; verifiers recompute its bytes
/// locally rather than trusting a separate field.
#[derive(Clone)]
pub struct DrgPresignR1Bcast {
    /// Hash commitment `H(nonce || Gamma_i_bytes)`.
    pub commitment: [u8; 32],
    /// Pedersen VSS commitments for k_i.
    pub k_commitments: Vec<k256::ProjectivePoint>,
    /// Pedersen VSS commitments for gamma_i.
    pub gamma_commitments: Vec<k256::ProjectivePoint>,
    /// CL ciphertext `Enc(ek_i, k_i)`.
    pub k_ciphertext: ClCiphertext,
    /// R_Enc-PC proof for the k ciphertext.
    pub k_proof: REncPcProof,
    /// CL ciphertext `Enc(ek_i, gamma_i)`.
    pub gamma_ciphertext: ClCiphertext,
    /// R_Enc-PC proof for the gamma ciphertext.
    pub gamma_proof: REncPcProof,
}

/// DRG-based Round 1 P2P data: VSS shares for one recipient.
#[derive(Clone)]
pub struct DrgPresignR1P2P {
    /// Pedersen VSS share of k for this recipient.
    pub k_share: PedersenVssShare,
    /// Pedersen VSS share of gamma for this recipient.
    pub gamma_share: PedersenVssShare,
}

/// DRG-based Round 1: DRG.Gen for k_i and gamma_i (WMY23 Fig. 5, Phase 1a).
///
/// Each party:
/// 1. Samples `k_i` and `gamma_i`.
/// 2. Runs DRG.Gen for each, producing Pedersen VSS shares, a CL
///    ciphertext under its own key, and an R_Enc-PC proof.
/// 3. Commits to `Gamma_i = gamma_i * G`.
///
/// Returns: per-party state, broadcast data, and P2P data for each other
/// party (indexed by local position, `None` at `index`).
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
    signer_ids: &[u16],
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
    // Use own CL public key, addressed by global keygen index.
    let my_pk = &key_share.cl_pks[global_idx(signer_ids, index)];

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

    let bcast = DrgPresignR1Bcast {
        commitment,
        k_commitments: k_gen.commitments.clone(),
        gamma_commitments: gamma_gen.commitments.clone(),
        k_ciphertext: k_gen.ciphertext.clone(),
        k_proof: k_gen.proof.clone(),
        gamma_ciphertext: gamma_gen.ciphertext.clone(),
        gamma_proof: gamma_gen.proof.clone(),
    };

    let state = DrgPresignR1State {
        index,
        n,
        k_gen,
        gamma_gen,
        gamma_point_i,
        nonce,
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
    /// Lagrange-weighted signing-key share: `hat_x_i = lambda_i * x_i`,
    /// where `lambda_i` is taken over the quorum's *global* keygen indices.
    /// With threshold (Shamir) key shares this is the effective additive
    /// contribution to the joint key `x = sum hat_x_i` over the active quorum.
    pub hat_x_i: k256::Scalar,
    /// Decommitment nonce.
    pub nonce: [u8; 32],
    /// Gamma point bytes (for decommitment): `Gamma_i = g^{gamma_i}`.
    pub gamma_point_bytes: Vec<u8>,
    /// MtAwc Alice states for the gamma MtA (one per counterparty, kept
    /// locally until Round 4 decryption).
    pub gamma_alice_states: Vec<Option<MtAwcAliceState>>,
    /// MtAwc Alice states for the key MtA (kept locally).
    pub x_alice_states: Vec<Option<MtAwcAliceState>>,
}

/// DRG-based Round 2 broadcast: decommitment + MtAwc Alice step 1
/// ciphertexts (one fresh ciphertext per counterparty).
pub struct DrgPresignR2Bcast {
    /// Decommitment nonce.
    pub nonce: [u8; 32],
    /// Gamma point bytes.
    pub gamma_point_bytes: Vec<u8>,
    /// MtAwc ciphertexts of `hat_k_i` (one per party, None for self).
    /// Alice encrypts under her own CL key.
    pub c_gamma: Vec<Option<ClCiphertext>>,
    /// MtAwc ciphertexts of `hat_x_i` (one per party, None for self).
    pub c_x: Vec<Option<ClCiphertext>>,
}

/// DRG-based Round 2: DRG.GenVf + DRG.Comb + MtAwc Alice step 1
/// (WMY23 Fig. 5, Phase 1b + start of Phase 2).
///
/// Each party:
/// 1. Verifies every received Pedersen VSS share against the dealer's
///    broadcast commitments, and the dealer's R_Enc-PC proof against its
///    broadcast CL ciphertext (DRG.GenVf).
/// 2. Combines shares via DRG.Comb for both k and gamma.
/// 3. Runs MtAwc Alice step 1 (encrypt `hat_k_i` and `hat_x_i` under own key).
///
/// # Arguments
///
/// * `r1_state` - This party's Round 1 state.
/// * `r1_bcasts` - Round 1 broadcasts of all parties (local order).
/// * `received_p2p` - VSS shares received by this party, indexed by sender
///   (local order, `None` at this party's own position).
/// * `signer_ids` - Global 1-based keygen indices of the quorum.
///
/// # Errors
///
/// Returns an error if any verification or CL operation fails.
pub fn drg_presign_round2(
    r1_state: &DrgPresignR1State,
    r1_bcasts: &[DrgPresignR1Bcast],
    received_p2p: &[Option<DrgPresignR1P2P>],
    signer_ids: &[u16],
    key_share: &Wmy23KeyShare,
    setup: &mut ClSetup,
) -> Result<(DrgPresignR2State, DrgPresignR2Bcast), Box<dyn std::error::Error>> {
    let n = r1_state.n;
    let my_idx = r1_state.index;
    let my_index_1based = (my_idx + 1) as u16;

    // Step 1: DRG.GenVf -- verify all received shares against the senders'
    // broadcast commitments, ciphertexts and R_Enc-PC proofs.
    for i in 0..n {
        if i == my_idx {
            continue;
        }
        let p2p = received_p2p[i]
            .as_ref()
            .ok_or_else(|| format!("missing P2P data from party {i}"))?;

        // Use party i's CL public key (global keygen index).
        let pk_i = &key_share.cl_pks[global_idx(signer_ids, i)];
        let bcast_i = &r1_bcasts[i];

        // The R_Enc-PC statement commits to PC = commitments[0]; recompute
        // its bytes from the broadcast commitments instead of trusting a
        // separately transmitted copy.
        let k_pc_bytes = bcast_i
            .k_commitments
            .first()
            .ok_or_else(|| format!("party {i}: empty k commitments"))?
            .to_bytes()
            .to_vec();
        let k_ok = drg_gen_verify(
            setup,
            pk_i,
            &bcast_i.k_commitments,
            &bcast_i.k_ciphertext,
            &bcast_i.k_proof,
            &k_pc_bytes,
            &p2p.k_share,
        )?;
        if !k_ok {
            return Err(format!("DRG.GenVf: k share from party {i} failed").into());
        }

        let gamma_pc_bytes = bcast_i
            .gamma_commitments
            .first()
            .ok_or_else(|| format!("party {i}: empty gamma commitments"))?
            .to_bytes()
            .to_vec();
        let gamma_ok = drg_gen_verify(
            setup,
            pk_i,
            &bcast_i.gamma_commitments,
            &bcast_i.gamma_ciphertext,
            &bcast_i.gamma_proof,
            &gamma_pc_bytes,
            &p2p.gamma_share,
        )?;
        if !gamma_ok {
            return Err(format!("DRG.GenVf: gamma share from party {i} failed").into());
        }
    }

    // Step 2: DRG.Comb -- combine shares for k and gamma
    let my_pk = &key_share.cl_pks[global_idx(signer_ids, my_idx)];

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
            let p2p = received_p2p[i]
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

    // Lagrange weighting.
    //
    // The fresh DRG sharings of k and gamma live on the quorum's *local*
    // indices {1..n}, so their combined Shamir shares are weighted with
    // local-coefficient lambdas.
    let local_indices: Vec<u16> = (1..=(n as u16)).collect();
    let local_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&local_indices);
    let hat_k_i = local_lambdas[my_idx] * k_comb.combined_share;
    let hat_gamma_i = local_lambdas[my_idx] * gamma_comb.combined_share;

    // The signing-key share x_i is a t-of-n Shamir share at this party's
    // *global* keygen evaluation point, so it is weighted with the Lagrange
    // coefficient over the quorum's global indices.
    let global_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(signer_ids);
    let hat_x_i = global_lambdas[my_idx] * key_share.secret_share;

    // Step 3: MtAwc Alice step 1 -- encrypt hat_k_i and hat_x_i
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

        // MtAwc step 1 for x: encrypt the Lagrange-weighted key share hat_x_i
        let (x_state, x_ct) = mtawc::mtawc_alice_step1(setup, my_pk, &hat_x_i)?;
        c_x.push(Some(x_ct));
        x_alice_states.push(Some(x_state));
    }

    let r2_state = DrgPresignR2State {
        k_comb,
        gamma_comb,
        hat_k_i,
        hat_gamma_i,
        hat_x_i,
        nonce: r1_state.nonce,
        gamma_point_bytes: r1_state.gamma_point_i.to_bytes().to_vec(),
        gamma_alice_states,
        x_alice_states,
    };

    let r2_bcast = DrgPresignR2Bcast {
        nonce: r1_state.nonce,
        gamma_point_bytes: r1_state.gamma_point_i.to_bytes().to_vec(),
        c_gamma,
        c_x,
    };

    Ok((r2_state, r2_bcast))
}

/// DRG-based Round 3 data: MtAwc Bob outputs.
///
/// In the entry for this party's own outputs the `beta` fields are real
/// secrets; when this struct is reconstructed from *received* messages
/// only `c_alpha` and `g_beta` are meaningful (beta is never transmitted).
pub struct DrgPresignR3Data {
    /// For each other party j: MtAwc Bob output for the gamma MtA.
    pub gamma_bob_outputs: Vec<Option<MtAwcBobOutput>>,
    /// For each other party j: MtAwc Bob output for the key MtA.
    pub x_bob_outputs: Vec<Option<MtAwcBobOutput>>,
}

/// DRG-based Round 3: MtAwc Bob step (WMY23 Fig. 5, Phase 2).
///
/// For each pair (j, i) where i = this party (Bob):
/// - Gamma MtA: Bob uses hat_gamma_i against Alice j's ciphertext of
///   hat_k_j (producing hat_k_j * hat_gamma_i, paper convention).
/// - Key MtA: Bob uses hat_k_i against Alice j's ciphertext of hat_x_j
///   (producing hat_x_j * hat_k_i).
///
/// # Errors
///
/// Returns an error if CL operations fail.
pub fn drg_presign_round3_bob(
    r2_state: &DrgPresignR2State,
    r1_state: &DrgPresignR1State,
    signer_ids: &[u16],
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

        // Use party j's CL public key (global keygen index).
        let pk_j = &key_share.cl_pks[global_idx(signer_ids, j)];

        // MtAwc Bob for hat_gamma_i * hat_k_j
        // (paper convention: Alice holds k, Bob holds gamma)
        let c_gamma_j = r2_bcasts[j].c_gamma[my_idx]
            .as_ref()
            .ok_or_else(|| format!("missing gamma ciphertext from party {j}"))?;
        let gamma_bob = mtawc::mtawc_bob(setup, pk_j, c_gamma_j, hat_gamma_i, rng)?;

        // MtAwc Bob for hat_k_i * hat_x_j (key MtA)
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

/// Per-party state after the Round 4 (Phase 3) local computation.
pub struct DrgPresignR4State {
    /// Number of signing parties.
    pub n: usize,
    /// This party's revealed delta share `delta_i`.
    pub delta_i: k256::Scalar,
    /// This party's share of `k * x`.
    pub sigma_i: k256::Scalar,
    /// `Gamma = sum_j Gamma_j = g^gamma`.
    pub gamma_sum: k256::ProjectivePoint,
    /// `D_i = Gamma^{hat_k_i}` (broadcast alongside delta_i).
    pub big_d_i: k256::ProjectivePoint,
    /// Lagrange-weighted nonce share (stored into the presignature).
    pub hat_k_i: k256::Scalar,
}

/// DRG-based Round 4 local step: Alice decrypt + Phase 3 share revelation
/// (WMY23 Figure 5, Phase 3).
///
/// 1. Verify all `Gamma_j` decommitments against the Round 1 commitments.
/// 2. Decrypt the MtAwc responses (alpha and mu shares).
/// 3. Generate the zero-sharing `{theta_{ij}}` and the structured delta
///    shares; compute `delta_i`, `sigma_i` and `D_i = Gamma^{hat_k_i}`.
/// 4. Self-check `g^{delta_i} * prod_j (B_{ij}/B_{ji}) == D_i`.
///
/// The returned `delta_i` and `big_d_i` are broadcast; the global
/// reconstruction happens in [`drg_presign_finalize`] once all parties'
/// values are collected.
///
/// The robustness claim of WMY23 is challenged by TX25 (Section 5).
/// See crate-level security warning in `lib.rs`.
///
/// # Arguments
///
/// * `r1_commitments` - Round 1 hash commitments of all parties.
/// * `r3_datas` - MtAwc Bob outputs: entry `my_idx` must be this party's
///   own [`DrgPresignR3Data`] (with real betas); entries for other
///   parties only need `c_alpha`/`g_beta` at this party's position.
///
/// # Errors
///
/// Returns an error if a decommitment check, decryption, or the Phase 3
/// self-verification fails.
#[allow(clippy::too_many_arguments)]
pub fn drg_presign_round4_compute(
    r1_state: &DrgPresignR1State,
    r1_commitments: &[[u8; 32]],
    r2_state: &DrgPresignR2State,
    r2_bcasts: &[DrgPresignR2Bcast],
    r3_datas: &[DrgPresignR3Data],
    signer_ids: &[u16],
    key_share: &Wmy23KeyShare,
    setup: &mut ClSetup,
    rng: &mut impl CryptoRngCore,
) -> Result<(DrgPresignR4State, Phase3Output), Box<dyn std::error::Error>> {
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
        if bool::from(!expected.ct_eq(&r1_commitments[j])) {
            return Err(format!("gamma commitment failed for party {j}").into());
        }
    }

    // Use CL secret key and public key directly from key share
    let my_pk = &key_share.cl_pks[global_idx(signer_ids, my_idx)];

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
            r2_state.gamma_alice_states[j]
                .as_ref()
                .ok_or("missing gamma alice state")?,
        )?;
        alphas[j] = alpha_out.alpha;

        // ---- Key MtA: I am Alice (hat_x_i), party j is Bob (hat_k_j) ----
        let x_bob_out = r3_datas[j].x_bob_outputs[my_idx]
            .as_ref()
            .ok_or("missing x bob output")?;

        let mu_out = mtawc::mtawc_alice_step2_no_gb_check(
            setup,
            my_pk,
            &key_share.cl_sk,
            &x_bob_out.c_alpha,
            &x_bob_out.g_beta,
            r2_state.x_alice_states[j]
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

        // ---- Key MtA: I am Bob (hat_k_i), party j is Alice (hat_x_j) ----
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

    // delta_i = hat_k_i * hat_gamma_i + sum(alpha_{ij}) + sum(beta_{ji})
    // (equals sum of structured delta shares, since sum(theta) = 0)
    let alpha_sum: k256::Scalar = alphas.iter().copied().sum();
    let beta_sum: k256::Scalar = betas.iter().copied().sum();
    let delta_i = hat_k_i * hat_gamma_i + alpha_sum + beta_sum;

    // Phase 3 verification (WMY23 Figure 5, Step 5):
    //   g^{delta_{i,P}} * prod_{l in P\{i}} (B_{il}/B_{li})^{L_{l,P}} == D_i
    //
    // Lagrange weights are already folded into hat_k_i / hat_gamma_i, so
    // the additive-share equation applies directly (all L_l = 1 in the
    // MtA layer).
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

    // sigma_i = hat_k_i * hat_x_i + sum(mu_{ij}) + sum(nu_{ji}), where hat_x_i
    // is the Lagrange-weighted key share (matches what was encrypted in R2).
    let sigma_i = hat_k_i * r2_state.hat_x_i + mu_sum + nu_sum;

    let r4_state = DrgPresignR4State {
        n,
        delta_i,
        sigma_i,
        gamma_sum,
        big_d_i,
        hat_k_i,
    };

    let phase3 = Phase3Output {
        delta_shares,
        big_d_i,
    };

    Ok((r4_state, phase3))
}

/// DRG-based finalization: reconstruct `delta` and `R` from the revealed
/// shares (WMY23 Figure 5, Output Phase).
///
/// Checks the global consistency relation `g^delta == prod_j D_j`
/// (`prod_j D_j = Gamma^k = g^{k*gamma} = g^delta`) before inverting.
///
/// # Arguments
///
/// * `all_delta_i` - The revealed `delta_j` of every party (local order).
/// * `all_big_d` - The broadcast `D_j = Gamma^{hat_k_j}` of every party.
///
/// # Errors
///
/// Returns an error if the consistency check fails or `delta` is zero.
pub fn drg_presign_finalize(
    r4_state: &DrgPresignR4State,
    all_delta_i: &[k256::Scalar],
    all_big_d: &[k256::ProjectivePoint],
) -> Result<Wmy23Presignature, Box<dyn std::error::Error>> {
    let n = r4_state.n;
    if all_delta_i.len() != n || all_big_d.len() != n {
        return Err("finalize: wrong number of revealed shares".into());
    }

    // Reconstruct delta = sum(delta_j)
    let delta: k256::Scalar = all_delta_i.iter().copied().sum();

    // Output-phase consistency check: prod_j D_j = Gamma^{sum hat_k_j}
    // = g^{gamma * k} = g^{delta}.
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let d_prod = all_big_d.iter().fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, d| acc + d,
    );
    if bool::from(!(g * delta).to_bytes().ct_eq(&d_prod.to_bytes())) {
        return Err("share revelation check failed: g^delta != prod D_j".into());
    }

    // delta^{-1}
    let delta_inv = delta
        .invert()
        .into_option()
        .ok_or("delta is zero, cannot invert")?;

    // R = delta^{-1} * Gamma = (k*gamma)^{-1} * gamma*G = (1/k)*G
    let big_r = r4_state.gamma_sum * delta_inv;

    // r = x_coord(R) mod q
    let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine());

    Ok(Wmy23Presignature {
        k_i: r4_state.hat_k_i,
        big_r,
        r_x,
        sigma_i: r4_state.sigma_i,
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
