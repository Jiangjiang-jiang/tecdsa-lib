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
use subtle::ConstantTimeEq;
use tecdsa_class_group::{
    cl::{ClCiphertext, ClSetup},
    drg::{drg_comb, drg_gen, drg_gen_verify, DrgCombOutput, DrgGenOutput, PedersenVssShare},
    zk::r_enc_pc::REncPcProof,
};
use tecdsa_curve::{conv::scalar_to_bytes, TecdsaCurve};

use crate::{
    key_share::Wmy23KeyShare,
    keygen::rounds::RDlPcProof,
    mtawc::{self, MtAwcBobOutput},
    presign::Wmy23Presignature,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The 0-based global keygen index for the party at local position `pos`.
fn global_idx(signer_ids: &[u16], pos: usize) -> usize {
    debug_assert!(signer_ids[pos] >= 1, "signer ids are 1-based");
    (signer_ids[pos] - 1) as usize
}

/// Recompute the combined Pedersen commitment `PC_{x_i}` at `index_1based`
/// from the VSS polynomial commitments of all dealers (DRG.CombVf).
///
/// `PC_{x_i} = prod_{dealer} prod_d F_{dealer,d}^{index^d}` (additive EC
/// notation), matching `drg::drg_comb`'s combined commitment construction.
fn combined_pc_at(
    all_commitments: &[Vec<k256::ProjectivePoint>],
    index_1based: u16,
) -> k256::ProjectivePoint {
    let x = k256::Scalar::from(u64::from(index_1based));
    let mut pc = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for coms in all_commitments {
        let mut x_pow = k256::Scalar::ONE;
        for com in coms {
            pc += *com * x_pow;
            x_pow *= x;
        }
    }
    pc
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
}

/// DRG-based Round 1 broadcast: DRG.Gen public data (WMY23 Fig. 5, Phase 1a).
///
/// Carries everything a verifier needs for DRG.GenVf: the Pedersen VSS
/// polynomial commitments, the dealer's CL ciphertext of its secret, and
/// the R_Enc-PC proof linking the two. The EC Pedersen commitment `PC`
/// used by the proof is `commitments[0]`; verifiers recompute its bytes
/// locally rather than trusting a separate field.
///
/// Unlike the previous implementation, no separate hash commitment to
/// `Gamma_i` is broadcast: `gamma_i` is already pinned by the broadcast VSS
/// commitments `F_{gamma_i}`, and the combined `Gamma` is opened via
/// `DRG.RevealExp` in Round 2 (WMY23 Fig. 5, Phase 2), matching the paper.
#[derive(Clone)]
pub struct DrgPresignR1Bcast {
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
}

/// DRG-based Round 2 broadcast (WMY23 Fig. 5, Phase 1b + start of Phase 2).
///
/// This is a single broadcast (identical to every recipient), matching the
/// paper's `Broadcast (pub_{k_i}, pi_{k_i}, pub_{gamma_i}, pi_{gamma_i})`
/// and `RevealExp(...) -> (Gamma_i, pi_{Gamma_i})`. The MtAwc receiver
/// ciphertext is the bound `DRG.Comb` output `c_{k_i}` itself: senders scale
/// it by the receiver's (public) Lagrange coefficient and feed it into
/// MtAwc, so no fresh, unproven ciphertext is created.
#[derive(Clone)]
pub struct DrgPresignR2Bcast {
    /// `DRG.Comb` ciphertext `c_{k_i} = Enc(ek_i, k_i)` of the combined nonce
    /// share, reused as the MtAwc receiver ciphertext (WMY23 Fig. 5).
    pub k_comb_ct: ClCiphertext,
    /// R_Enc-PC proof binding `c_{k_i}` to the combined commitment `PC_{k_i}`.
    pub k_comb_proof: REncPcProof,
    /// Combined Pedersen commitment `PC_{k_i}` bytes (for R_Enc-PC + CombVf).
    pub k_comb_pc_bytes: Vec<u8>,
    /// `DRG.Comb` ciphertext `c_{gamma_i}` of the combined mask share.
    pub gamma_comb_ct: ClCiphertext,
    /// R_Enc-PC proof binding `c_{gamma_i}` to `PC_{gamma_i}`.
    pub gamma_comb_proof: REncPcProof,
    /// Combined Pedersen commitment `PC_{gamma_i}` bytes.
    pub gamma_comb_pc_bytes: Vec<u8>,
    /// `DRG.RevealExp` output `Gamma_i = g^{gamma_i}` for the *combined*
    /// mask share (WMY23 Fig. 5, Phase 2).
    pub g_gamma_point: k256::ProjectivePoint,
    /// R_DL-PC proof binding `Gamma_i` to `PC_{gamma_i}` (DRG.ExpVf).
    pub gamma_reveal_proof: RDlPcProof,
}

/// DRG-based Round 2: DRG.GenVf + DRG.Comb + MtAwc Alice step 1
/// (WMY23 Fig. 5, Phase 1b + start of Phase 2).
///
/// Each party:
/// 1. Verifies every received Pedersen VSS share against the dealer's
///    broadcast commitments, and the dealer's R_Enc-PC proof against its
///    broadcast CL ciphertext (DRG.GenVf).
/// 2. Combines shares via DRG.Comb for both k and gamma.
/// 3. Runs DRG.RevealExp on the combined gamma share (opens
///    `Gamma_i = g^{gamma_i}` with an R_DL-PC proof) and broadcasts the bound
///    `DRG.Comb` ciphertexts `c_{k_i}`, `c_{gamma_i}` with their R_Enc-PC
///    proofs. The bound `c_{k_i}` is reused as the MtAwc receiver ciphertext.
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

    // Step 3 (WMY23 Fig. 5, Phase 2): DRG.RevealExp of the *combined* mask
    // share. We open Gamma_i = g^{gamma_i} (combined) with an R_DL-PC proof
    // binding it to PC_{gamma_i}. This is what lets MtAwc receivers run the
    // algebraic Step-3 check against (g^{hat_gamma_j})^{hat_k_i} later, and
    // it reconstructs Gamma = prod_j Gamma_j^{L_j} = g^{gamma}.
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let g_gamma_point = g * gamma_comb.combined_share;
    let mut reveal_rng = rand::thread_rng();
    let gamma_reveal_proof = RDlPcProof::prove(
        &gamma_comb.combined_share,
        &gamma_comb.combined_randomness,
        &g_gamma_point,
        &gamma_comb.pedersen_commitment,
        &mut reveal_rng,
    );

    // The MtAwc receiver ciphertext is the bound DRG.Comb output itself: it
    // is broadcast once (Phase 1b) with its R_Enc-PC proof, and senders scale
    // it by the receiver's public Lagrange coefficient. No fresh ciphertext.
    let r2_bcast = DrgPresignR2Bcast {
        k_comb_ct: k_comb.ciphertext.clone(),
        k_comb_proof: k_comb.proof.clone(),
        k_comb_pc_bytes: k_comb.pc_bytes.clone(),
        gamma_comb_ct: gamma_comb.ciphertext.clone(),
        gamma_comb_proof: gamma_comb.proof.clone(),
        gamma_comb_pc_bytes: gamma_comb.pc_bytes.clone(),
        g_gamma_point,
        gamma_reveal_proof,
    };

    let r2_state = DrgPresignR2State {
        k_comb,
        gamma_comb,
        hat_k_i,
        hat_gamma_i,
        hat_x_i,
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

/// DRG-based Round 3: MtAwc Bob (sender) step (WMY23 Fig. 5, Phase 2).
///
/// The nonce-share holder is *always* the MtAwc receiver (Alice), matching
/// the paper. For each Alice `j != i`, this party (Bob `i`) scales Alice's
/// broadcast `DRG.Comb` ciphertext `c_{k_j}` by Alice's public Lagrange
/// coefficient to obtain `Enc(ek_j, hat_k_j)` and then:
/// - Gamma MtA: applies `hat_gamma_i`, producing `hat_k_j * hat_gamma_i`.
/// - Key MtA: applies `hat_x_i`, producing `hat_k_j * hat_x_i`.
///
/// Both conversions therefore consume the *same* bound `c_{k_j}` ciphertext
/// (WMY23 `c_alpha_ji <- gamma_i (x) c_kj (+) Enc(-beta)` and
/// `c_mu_ji <- x_i (x) c_kj (+) Enc(-nu)`); no fresh ciphertext is encrypted.
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
    let hat_gamma_i = &r2_state.hat_gamma_i;
    let hat_x_i = &r2_state.hat_x_i;

    // Lagrange coefficients over the quorum's local indices {1..n}, used to
    // scale each receiver's combined-k ciphertext into Enc(hat_k_j).
    let local_indices: Vec<u16> = (1..=(n as u16)).collect();
    let local_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&local_indices);

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

        // Scale Alice j's bound DRG.Comb ciphertext c_{k_j} by Alice's public
        // Lagrange coefficient: c_{hat_k_j} = lambda_j (x) c_{k_j}.
        let lambda_j_bytes = scalar_to_bytes::<k256::Secp256k1>(&local_lambdas[j]);
        let c_hat_k_j =
            setup.scal_ciphertext_bytes(pk_j, &r2_bcasts[j].k_comb_ct, &lambda_j_bytes)?;

        // Gamma MtA: hat_k_j * hat_gamma_i  (Alice j holds k, Bob i holds gamma)
        let gamma_bob = mtawc::mtawc_bob(setup, pk_j, &c_hat_k_j, hat_gamma_i, rng)?;

        // Key MtA: hat_k_j * hat_x_i  (Alice j holds k, Bob i holds x).
        // Same receiver ciphertext c_{hat_k_j} as the gamma MtA.
        let x_bob = mtawc::mtawc_bob(setup, pk_j, &c_hat_k_j, hat_x_i, rng)?;

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
    /// Local (0-based) position of this party within the quorum.
    pub index: usize,
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
    /// Commitment randomness for `hat_k_i`: `hat_k_i' = lambda_i * k_i'`.
    /// Used as the NIZKDL-2PC witness in identifiable online signing.
    pub hat_k_randomness: k256::Scalar,
    /// `hat_x_i` (Lagrange-weighted key share); folded into `sigma_i` but
    /// also retained for the online-signing self-share `s_{ii}`.
    pub hat_x_i: k256::Scalar,
    /// `mu_{ij}` (this party's kx-MtA alpha shares as k-holder), `None` at
    /// own index. WMY23 Vi material for online signing.
    pub mu_shares: Vec<Option<k256::Scalar>>,
    /// `N_{ij} = g^{nu_{ij}}` (counterparty MtAwc shares-in-exponent), `None`
    /// at own index. WMY23 Vi material for online signing.
    pub nu_points: Vec<Option<k256::ProjectivePoint>>,
    /// `PC_{hat_k_j} = lambda_j * PC_{k_j} = g^{hat_k_j} h^{hat_k_j'}` for
    /// every party `j` (statement element for the online NIZKDL-2PC).
    pub pc_hat_k: Vec<k256::ProjectivePoint>,
    /// `hat_X_j = g^{hat_x_j} = X_j^{global_lambda_j}` for every party `j`
    /// (statement element for the online NIZKDL-2PC / Eq. (3)).
    pub xhat_points: Vec<k256::ProjectivePoint>,
    /// R_DL-PC proof that `D_i = Gamma^{hat_k_i}` with `hat_k_i` committed in
    /// `PC_{hat_k_i}` (WMY23 Fig. 5, Phase 3: `pi_{D_i}`). Broadcast so every
    /// party can bind `D_i` to the committed nonce share.
    pub d_proof: RDlPcProof,
    /// Full gamma-MtAwc share-in-exponent matrix `B[bob][alice] = g^{beta}`
    /// (`None` on the diagonal), assembled from the broadcast Round-3 data.
    /// Used for the Phase-3 cross-verification (Eq. (2)) of *every* party.
    pub gamma_beta: Vec<Vec<Option<k256::ProjectivePoint>>>,
}

/// DRG-based Round 4 local step: CombVf/ExpVf + MtAwc receiver checks +
/// Phase 3 share revelation (WMY23 Figure 5, Phases 1b/2/3).
///
/// 1. For every party: DRG.CombVf (verify the broadcast `c_{k_j}`,
///    `c_{gamma_j}` against the recomputed combined commitments via R_Enc-PC)
///    and DRG.ExpVf (verify `Gamma_j = g^{gamma_j}` via R_DL-PC).
/// 2. As MtAwc receiver, decrypt the responses and run the WMY23 Figure 1
///    Step-3 algebraic check against `(g^{hat_gamma_j})^{hat_k_i}` (gamma MtA)
///    and `(g^{hat_x_j})^{hat_k_i}` (key MtA). A failed check identifies the
///    sender as a cheater.
/// 3. Generate the zero-sharing `{theta_{ij}}` and the structured delta
///    shares; compute `delta_i`, `sigma_i`, `D_i = Gamma^{hat_k_i}` and the
///    `pi_{D_i}` proof (R_DL-PC, base `Gamma`), plus the broadcast `B`-matrix.
/// 4. Local sanity self-check `g^{delta_i} * prod_j (B_{ij}/B_{ji}) == D_i`.
///
/// The returned `delta_i`, `big_d_i` and `d_proof` are broadcast in Round 4;
/// every party then cross-verifies *every* party's share via
/// [`verify_phase3_party`] (WMY23 Eq. (2)) before [`drg_presign_finalize`]
/// reconstructs `R`. That cross-verification (added on top of the broadcast
/// MtAwc material) closes the concurrent-exclusion gap exploited by TX25.
///
/// # Arguments
///
/// * `r1_bcasts` - Round 1 broadcasts of all parties (for the VSS
///   commitments used to recompute the combined commitments in CombVf).
/// * `r3_datas` - MtAwc Bob outputs: entry `my_idx` must be this party's
///   own [`DrgPresignR3Data`] (with real betas); entries for other
///   parties only need `c_alpha`/`g_beta` at this party's position.
///
/// # Errors
///
/// Returns an error if CombVf/ExpVf, a decryption, the MtAwc Step-3 check,
/// or the Phase 3 self-verification fails.
#[allow(clippy::too_many_arguments)]
pub fn drg_presign_round4_compute(
    r1_state: &DrgPresignR1State,
    r1_bcasts: &[DrgPresignR1Bcast],
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

    // Lagrange coefficients: k/gamma over local quorum indices {1..n};
    // x over the quorum's global keygen indices.
    let local_indices: Vec<u16> = (1..=(n as u16)).collect();
    let local_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&local_indices);
    let global_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(signer_ids);

    // --- DRG.CombVf + DRG.ExpVf for every party (WMY23 Fig. 5, Phase 1b/2) ---
    // Recompute the combined Pedersen commitments PC_{k_j}, PC_{gamma_j} from
    // the broadcast VSS commitments, then verify the R_Enc-PC proofs binding
    // the combined ciphertexts and the R_DL-PC proof binding Gamma_j.
    let k_coms_all: Vec<Vec<k256::ProjectivePoint>> =
        r1_bcasts.iter().map(|b| b.k_commitments.clone()).collect();
    let gamma_coms_all: Vec<Vec<k256::ProjectivePoint>> =
        r1_bcasts.iter().map(|b| b.gamma_commitments.clone()).collect();
    let mut k_comb_pcs: Vec<k256::ProjectivePoint> = Vec::with_capacity(n);
    for j in 0..n {
        let idx_1based = (j + 1) as u16;
        let pk_j = &key_share.cl_pks[global_idx(signer_ids, j)];
        let b = &r2_bcasts[j];

        // CombVf (k): recomputed PC must match, R_Enc-PC must verify.
        let pc_kj = combined_pc_at(&k_coms_all, idx_1based);
        if pc_kj.to_bytes().as_slice() != b.k_comb_pc_bytes.as_slice() {
            return Err(format!("CombVf: PC_k mismatch for party {j}").into());
        }
        if !b
            .k_comb_proof
            .verify(setup, pk_j, &b.k_comb_ct, &b.k_comb_pc_bytes)?
        {
            return Err(format!("CombVf: R_Enc-PC (k) failed for party {j}").into());
        }
        k_comb_pcs.push(pc_kj);

        // CombVf (gamma).
        let pc_gj = combined_pc_at(&gamma_coms_all, idx_1based);
        if pc_gj.to_bytes().as_slice() != b.gamma_comb_pc_bytes.as_slice() {
            return Err(format!("CombVf: PC_gamma mismatch for party {j}").into());
        }
        if !b
            .gamma_comb_proof
            .verify(setup, pk_j, &b.gamma_comb_ct, &b.gamma_comb_pc_bytes)?
        {
            return Err(format!("CombVf: R_Enc-PC (gamma) failed for party {j}").into());
        }

        // ExpVf: Gamma_j = g^{gamma_j} bound to PC_{gamma_j} via R_DL-PC.
        if !b
            .gamma_reveal_proof
            .verify(&b.g_gamma_point, &pc_gj)
            .map_err(|e| format!("ExpVf error for party {j}: {e}"))?
        {
            return Err(format!("ExpVf: R_DL-PC failed for party {j}").into());
        }
    }

    // Collect per-counterparty MtAwc shares
    let mut alphas: Vec<k256::Scalar> = vec![k256::Scalar::ZERO; n];
    let mut betas: Vec<k256::Scalar> = vec![k256::Scalar::ZERO; n];
    let mut mu_sum = k256::Scalar::ZERO;
    let mut nu_sum = k256::Scalar::ZERO;
    // Raw kx-MtA shares retained for the identifiable online signing
    // (WMY23 Figs 7-9): mu_{ij} (this party's alpha as k-holder) and
    // N_{ij} = g^{nu_{ij}} (the counterparty's MtAwc share-in-exponent).
    let mut mu_shares: Vec<Option<k256::Scalar>> = vec![None; n];
    let mut nu_points: Vec<Option<k256::ProjectivePoint>> = vec![None; n];

    for j in 0..n {
        if j == my_idx {
            continue;
        }

        // g^{hat_gamma_j} = Gamma_j^{local_lambda_j}; g^{hat_x_j} = X_j^{global_lambda_j}.
        let g_hat_gamma_j = r2_bcasts[j].g_gamma_point * local_lambdas[j];
        let x_j = key_share.public_shares[global_idx(signer_ids, j)];
        let g_hat_x_j = x_j * global_lambdas[j];

        // ---- Gamma MtA: I am Alice (hat_k_i), party j is Bob (hat_gamma_j) ----
        // Product: hat_k_i * hat_gamma_j = alphas[j] + beta_Bob_j.
        // Step-3 check: g^alpha * g^beta == (g^{hat_gamma_j})^{hat_k_i}.
        let gamma_bob_out = r3_datas[j].gamma_bob_outputs[my_idx]
            .as_ref()
            .ok_or("missing gamma bob output")?;
        let alpha_out = mtawc::mtawc_alice_decrypt_and_check(
            setup,
            &key_share.cl_sk,
            &gamma_bob_out.c_alpha,
            &gamma_bob_out.g_beta,
            &hat_k_i,
            &g_hat_gamma_j,
        )
        .map_err(|e| format!("gamma MtAwc check failed (sender {j}): {e}"))?;
        alphas[j] = alpha_out.alpha;

        // ---- Key MtA: I am Alice (hat_k_i), party j is Bob (hat_x_j) ----
        // Product: hat_k_i * hat_x_j = mu_{ij} + nu_Bob_j.
        // Step-3 check: g^mu * g^nu == (g^{hat_x_j})^{hat_k_i}.
        let x_bob_out = r3_datas[j].x_bob_outputs[my_idx]
            .as_ref()
            .ok_or("missing x bob output")?;
        let mu_out = mtawc::mtawc_alice_decrypt_and_check(
            setup,
            &key_share.cl_sk,
            &x_bob_out.c_alpha,
            &x_bob_out.g_beta,
            &hat_k_i,
            &g_hat_x_j,
        )
        .map_err(|e| format!("key MtAwc check failed (sender {j}): {e}"))?;
        mu_sum += mu_out.alpha;
        // mu_{ij} = this party's (Alice) kx share; N_{ij} = g^{nu_{ij}} is
        // Bob j's share-in-exponent (the MtAwc g^beta we just checked).
        mu_shares[j] = Some(mu_out.alpha);
        nu_points[j] = Some(x_bob_out.g_beta);

        // ---- Gamma MtA: I am Bob (hat_gamma_i), party j is Alice (hat_k_j) ----
        // Product: hat_k_j * hat_gamma_i = alpha_Alice_j + betas[j]
        let my_gamma_bob = r3_datas[my_idx].gamma_bob_outputs[j]
            .as_ref()
            .ok_or("missing my gamma bob output")?;
        betas[j] = my_gamma_bob.beta;

        // ---- Key MtA: I am Bob (hat_x_i), party j is Alice (hat_k_j) ----
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

    // Reconstruct Gamma = prod_j Gamma_j^{L_j} = g^{sum hat_gamma_j} = g^gamma,
    // where Gamma_j = g^{gamma_j} is the (combined) RevealExp point and L_j is
    // the quorum-local Lagrange coefficient (so the weighting matches hat_k_i).
    let mut gamma_sum = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for j in 0..n {
        gamma_sum += r2_bcasts[j].g_gamma_point * local_lambdas[j];
    }

    // WMY23 Figure 5, Phase 3, Step 1: D_i = Gamma^{hat_k_i}
    let big_d_i = gamma_sum * hat_k_i;

    // delta_i = hat_k_i * hat_gamma_i + sum(alpha_{ij}) + sum(beta_{ji})
    // (equals sum of structured delta shares, since sum(theta) = 0)
    let alpha_sum: k256::Scalar = alphas.iter().copied().sum();
    let beta_sum: k256::Scalar = betas.iter().copied().sum();
    let delta_i = hat_k_i * hat_gamma_i + alpha_sum + beta_sum;

    // Local sanity self-check (WMY23 Figure 5, Step 5):
    //   g^{delta_{i,P}} * prod_{l in P\{i}} (B_{il}/B_{li})^{L_{l,P}} == D_i
    //
    // Lagrange weights are already folded into hat_k_i / hat_gamma_i, so
    // the additive-share equation applies directly (all L_l = 1 in the
    // MtA layer). B_{il} = g^{beta} where i was Alice (gamma MtA), l was Bob;
    // B_{li} = g^{beta} where l was Alice, i was Bob. The *authoritative*
    // (identifiable) check is the per-party cross-verification in
    // `verify_phase3_party`, run by everyone over the broadcast B-matrix.
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

    // hat_k_i' = lambda_i * k_i' is the commitment randomness for hat_k_i:
    //   PC_{hat_k_i} = lambda_i * PC_{k_i} = g^{hat_k_i} h^{hat_k_i'}.
    let hat_k_randomness = local_lambdas[my_idx] * r2_state.k_comb.combined_randomness;

    // Per-party online-signing statement elements:
    //   PC_{hat_k_j} = lambda_j * PC_{k_j};  hat_X_j = X_j^{global_lambda_j}.
    let pc_hat_k: Vec<k256::ProjectivePoint> = (0..n)
        .map(|j| k_comb_pcs[j] * local_lambdas[j])
        .collect();
    let xhat_points: Vec<k256::ProjectivePoint> = (0..n)
        .map(|j| key_share.public_shares[global_idx(signer_ids, j)] * global_lambdas[j])
        .collect();

    // WMY23 Fig. 5, Phase 3: pi_{D_i} = NIZKDL-PC.Prove((PC_{hat_k_i}, Gamma, D_i); (hat_k_i, hat_k_i')).
    // Binds D_i = Gamma^{hat_k_i} to the committed nonce share so that *every*
    // party (not just the dealer) can verify D_i during share revelation.
    let d_proof = RDlPcProof::prove_with_base(
        &gamma_sum,
        &hat_k_i,
        &hat_k_randomness,
        &big_d_i,
        &pc_hat_k[my_idx],
        rng,
    );

    // Assemble the full gamma-MtAwc beta-in-exponent matrix from the broadcast
    // Round-3 data: gamma_beta[bob][alice] = B that `bob` produced for `alice`.
    // Available for every (bob, alice) pair because Round 3 is now broadcast.
    let mut gamma_beta: Vec<Vec<Option<k256::ProjectivePoint>>> =
        vec![vec![None; n]; n];
    for bob in 0..n {
        for alice in 0..n {
            if bob == alice {
                continue;
            }
            if let Some(out) = r3_datas[bob].gamma_bob_outputs[alice].as_ref() {
                gamma_beta[bob][alice] = Some(out.g_beta);
            }
        }
    }

    let r4_state = DrgPresignR4State {
        n,
        index: my_idx,
        delta_i,
        sigma_i,
        gamma_sum,
        big_d_i,
        hat_k_i,
        hat_k_randomness,
        hat_x_i: r2_state.hat_x_i,
        mu_shares,
        nu_points,
        pc_hat_k,
        xhat_points,
        d_proof,
        gamma_beta,
    };

    let phase3 = Phase3Output {
        delta_shares,
        big_d_i,
    };

    Ok((r4_state, phase3))
}

/// WMY23 Figure 5, Phase 3 cross-verification of party `j`'s revealed
/// pseudo-nonce share (paper Section V-D, Equation (2)).
///
/// Every party runs this on *every* `j` (not just a self-check), which is
/// what makes the share-revelation phase identifiable and closes the
/// concurrent-exclusion gap exploited by TX25. It checks:
///
/// 1. `pi_{D_j}` (R_DL-PC, base `Gamma`): `D_j = Gamma^{hat_k_j}` with
///    `hat_k_j` committed in `PC_{hat_k_j}` — binds `D_j` to party `j`'s
///    committed nonce share.
/// 2. Equation (2): `g^{delta_j} * prod_{l != j} (B_{jl}/B_{lj}) == D_j`,
///    where `B_{jl} = gamma_beta[l][j]` (the share-in-exponent Bob `l`
///    produced for Alice `j`) and `B_{lj} = gamma_beta[j][l]`.
///
/// Returns `true` iff both pass. A `false` result imputes the fault to party
/// `j` (per the paper's argument: `j` is responsible for the `B`'s feeding
/// its own `delta_j`, having had the chance to complain in Phase 2).
#[must_use]
pub fn verify_phase3_party(
    r4_state: &DrgPresignR4State,
    j: usize,
    delta_j: &k256::Scalar,
    big_d_j: &k256::ProjectivePoint,
    d_proof_j: &RDlPcProof,
) -> bool {
    let n = r4_state.n;
    if j >= n {
        return false;
    }

    // 1. pi_{D_j}: D_j = Gamma^{hat_k_j} bound to PC_{hat_k_j} (base Gamma).
    match d_proof_j.verify_with_base(&r4_state.gamma_sum, big_d_j, &r4_state.pc_hat_k[j]) {
        Ok(true) => {}
        _ => return false,
    }

    // 2. Equation (2): g^{delta_j} * prod_{l!=j}(B_{jl}/B_{lj}) == D_j.
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let mut lhs = g * delta_j;
    for l in 0..n {
        if l == j {
            continue;
        }
        // B_{jl}: j is Alice, l is Bob  => Bob l's beta for Alice j.
        let Some(b_jl) = r4_state.gamma_beta[l][j] else {
            return false;
        };
        // B_{lj}: l is Alice, j is Bob  => Bob j's beta for Alice l.
        let Some(b_lj) = r4_state.gamma_beta[j][l] else {
            return false;
        };
        lhs += b_jl - b_lj;
    }
    bool::from(lhs.to_bytes().ct_eq(&big_d_j.to_bytes()))
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

    // Nonce share in exponent to base R: R_j = R^{hat_k_j} = D_j^{1/delta}
    // (since D_j = Gamma^{hat_k_j} and R = Gamma^{1/delta}). Computable by all
    // parties from the verified, broadcast D_j and delta. WMY23 Vi material.
    let big_r_shares: Vec<k256::ProjectivePoint> =
        all_big_d.iter().map(|d| *d * delta_inv).collect();

    Ok(Wmy23Presignature {
        k_i: r4_state.hat_k_i,
        big_r,
        r_x,
        sigma_i: r4_state.sigma_i,
        n_signers: n,
        index: r4_state.index,
        hat_k_randomness: r4_state.hat_k_randomness,
        hat_x_i: r4_state.hat_x_i,
        mu_shares: r4_state.mu_shares.clone(),
        nu_points: r4_state.nu_points.clone(),
        pc_hat_k: r4_state.pc_hat_k.clone(),
        big_r_shares,
        xhat_points: r4_state.xhat_points.clone(),
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
