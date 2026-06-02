// SPDX-License-Identifier: GPL-3.0-or-later
//! Scaled Decryption primitive (Protocol 4.1 from Trout).
//!
//! Given:
//! - `{A_j = Enc(alpha_j, a_j)}`: CL encryptions summing to Enc(alpha, a)
//! - `{B_j = Com(beta_j, b_j)}`: CL commitments summing to Com(beta, b)
//!
//! Computes `c = a * b mod q` without revealing `a` or `b`.
//!
//! Each party i computes:
//!   `F_i = b_i * A_2 + beta_i * A_1 - alpha_i * B`
//!
//! The combined `F = sum F_i = f^{a*b}` and `c = DLog_F(F)` gives `a*b mod q`.

use crate::bicycl_glue::{BicyclCiphertext, BicyclPublicKey, BicyclQfi, ClResult, ClSetup};
use crate::zk::r_aff_com::RAffComProof;

/// Per-party secret inputs for scaled decryption.
pub struct ScaledDecryptPartyInput {
    /// CL encryption randomness alpha_i (big-endian bytes).
    pub alpha_i: Vec<u8>,
    /// CL commitment randomness beta_i (big-endian bytes).
    pub beta_i: Vec<u8>,
    /// Commitment value b_i (big-endian bytes, mod q).
    pub b_i: Vec<u8>,
}

/// Aggregated public ciphertext and commitment.
pub struct ScaledDecryptPublic {
    /// First component of aggregated encryption: A_1 = prod(c1_j).
    pub a1: BicyclQfi,
    /// Second component of aggregated encryption: A_2 = prod(c2_j).
    pub a2: BicyclQfi,
    /// Aggregated commitment: B = prod(B_j).
    pub b_agg: BicyclQfi,
}

/// Output of a single party's scaled decryption contribution.
pub struct ScaledDecryptShare {
    /// This party's contribution F_i.
    pub f_i: BicyclQfi,
    /// R_affCom proof for F_i (only in IA variant).
    pub pi_aff_com: Option<RAffComProof>,
}

/// Compute a single party's contribution F_i.
///
/// `F_i = exp(A_2, b_i) * exp(A_1, beta_i) * neg(exp(B, alpha_i))`
pub fn compute_f_share(
    setup: &ClSetup,
    input: &ScaledDecryptPartyInput,
    public: &ScaledDecryptPublic,
) -> ClResult<BicyclQfi> {
    let a2_bi = setup.exp_bytes(&public.a2, &input.b_i)?;
    let a1_betai = setup.exp_bytes(&public.a1, &input.beta_i)?;
    let b_alphai = setup.exp_bytes(&public.b_agg, &input.alpha_i)?;
    let b_alphai_inv = setup.neg_qfi(&b_alphai)?;

    let tmp = setup.compose(&a2_bi, &a1_betai)?;
    let f_i = setup.compose(&tmp, &b_alphai_inv)?;
    Ok(f_i)
}

/// Compute F_i with R_affCom proof for identifiable abort.
pub fn compute_f_share_with_proof(
    setup: &mut ClSetup,
    cl_pk: &BicyclPublicKey,
    input: &ScaledDecryptPartyInput,
    public: &ScaledDecryptPublic,
    ct_in: &BicyclCiphertext,
    u_com_i: &BicyclQfi,
) -> ClResult<ScaledDecryptShare> {
    let f_i = compute_f_share(setup, input, public)?;

    let identity = setup.identity()?;
    let ct_out = setup.ct_from_components(&identity, &f_i)?;

    let pi_aff_com = RAffComProof::prove(
        setup,
        cl_pk,
        ct_in,
        &ct_out,
        u_com_i,
        &input.b_i,
        &[0u8],
        &input.alpha_i,
        &input.beta_i,
    )?;

    Ok(ScaledDecryptShare {
        f_i,
        pi_aff_com: Some(pi_aff_com),
    })
}

/// Aggregate F_i shares and extract the product `a*b mod q`.
pub fn aggregate_and_solve(setup: &ClSetup, f_shares: &[BicyclQfi]) -> ClResult<Vec<u8>> {
    let id = setup.identity()?;
    let mut f_agg = id;
    for fi in f_shares {
        f_agg = setup.compose(&f_agg, fi)?;
    }
    setup.dlog_in_F_bytes(&f_agg)
}

/// Aggregate ciphertext components from all parties.
pub fn aggregate_ciphertext_components(
    setup: &ClSetup,
    components: &[(BicyclQfi, BicyclQfi)],
) -> ClResult<(BicyclQfi, BicyclQfi)> {
    let mut a1 = setup.identity()?;
    let mut a2 = setup.identity()?;
    for (c1, c2) in components {
        a1 = setup.compose(&a1, c1)?;
        a2 = setup.compose(&a2, c2)?;
    }
    Ok((a1, a2))
}

/// Aggregate commitment elements from all parties.
pub fn aggregate_commitments(setup: &ClSetup, commitments: &[BicyclQfi]) -> ClResult<BicyclQfi> {
    let id = setup.identity()?;
    let mut b = id;
    for bj in commitments {
        b = setup.compose(&b, bj)?;
    }
    Ok(b)
}

/// Run complete scaled decryption locally (for testing/simulation).
pub fn scaled_decrypt_local(
    setup: &ClSetup,
    inputs: &[ScaledDecryptPartyInput],
    public: &ScaledDecryptPublic,
) -> ClResult<Vec<u8>> {
    let f_shares: Vec<BicyclQfi> = inputs
        .iter()
        .map(|input| compute_f_share(setup, input, public))
        .collect::<ClResult<Vec<_>>>()?;
    aggregate_and_solve(setup, &f_shares)
}
