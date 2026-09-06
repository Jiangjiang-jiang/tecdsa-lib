// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 *identifiable* online signing round functions (WMY23 Figs 7-9).
//!
//! Each party `i` broadcasts an additive partial signature
//! `s_i = m * hat_k_i + r * sigma_i` together with, for every counterparty
//! `j`, the MtAwc share-in-exponent `M_{ij} = R^{mu_{ij}}`, the peer share
//! `N_{ij} = g^{nu_{ij}}`, and a NIZKDL-2PC proof (`R_DL-2PC`, Fig. 13) that
//! `M_{ij}` is consistent with `i`'s committed nonce share `PC_{hat_k_i}` and
//! the key share `hat_X_j = g^{hat_x_j}`.
//!
//! Every party then runs the per-party verification (WMY23 Fig. 8): it
//! checks all of party `i`'s NIZKDL-2PC proofs and the share-consistency
//! equation (the additive-share form of WMY23 Equation (3)):
//!
//! ```text
//! R^{s_i} * prod_{j != i} (M_{ji} / M_{ij})^{r}  ==  R_i^{m} * hat_X_i^{r}
//! ```
//!
//! where `R_i = R^{hat_k_i}`. Reconstruction is `s = sum_i s_i = k(m + r x)`.
//! A party whose proofs or equation fail is identified as a cheater, so the
//! online phase achieves identifiable abort rather than a silent failure.

#![allow(non_snake_case)]

use elliptic_curve::CurveArithmetic;
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    nizk::{RDl2PcProof, RDl2PcStatement},
    presign::Wmy23Presignature,
};

type Point = k256::ProjectivePoint;
type Scalar = k256::Scalar;

/// One party's online-signing contribution (WMY23 Fig. 7).
///
/// Vectors are indexed by quorum-local position; entries at the sender's own
/// `index` are `None`.
#[derive(Clone, Debug)]
pub struct SignContribution {
    /// Sender's quorum-local index.
    pub index: usize,
    /// Additive partial signature `s_i = m * hat_k_i + r * sigma_i`.
    pub s_i: Scalar,
    /// `M_{ij} = R^{mu_{ij}}` for each counterparty `j` (`None` at `index`).
    pub m_row: Vec<Option<Point>>,
    /// `N_{ij} = g^{nu_{ij}}` for each counterparty `j` (`None` at `index`).
    pub n_row: Vec<Option<Point>>,
    /// NIZKDL-2PC proof for each `M_{ij}` (`None` at `index`).
    pub proofs: Vec<Option<RDl2PcProof>>,
}

/// The fixed second base `B = 1/g = -G` used by the `R_DL-2PC` relation.
fn base_b() -> Point {
    -<k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR
}

/// Compute this party's contribution (WMY23 Fig. 7, Phase 1a).
///
/// Produces the additive partial signature and, for each counterparty `j`,
/// `M_{ij}`, `N_{ij}` and the NIZKDL-2PC proof binding `M_{ij}` to the
/// committed nonce share.
pub fn compute_contribution(
    presig: &Wmy23Presignature,
    message: &DataToSign<k256::Secp256k1>,
    rng: &mut impl CryptoRngCore,
) -> SignContribution {
    let m = *message.digest();
    let r = presig.r_x;
    let big_r = presig.big_r;
    let i = presig.index;
    let n = presig.n_signers;
    let b = base_b();

    // s_i = m * hat_k_i + r * sigma_i (additive share of s = k(m + r x)).
    let s_i = m * presig.k_i + r * presig.sigma_i;

    let mut m_row: Vec<Option<Point>> = vec![None; n];
    let mut n_row: Vec<Option<Point>> = vec![None; n];
    let mut proofs: Vec<Option<RDl2PcProof>> = vec![None; n];

    for j in 0..n {
        if j == i {
            continue;
        }
        // mu_{ij}: this party's key-MtAwc share as nonce-share holder.
        // Missing entries (e.g. a synthetic presignature) are skipped.
        let (Some(mu_ij), Some(n_ij)) = (presig.mu_shares[j], presig.nu_points[j]) else {
            continue;
        };
        let m_ij = big_r * mu_ij; // M_{ij} = R^{mu_{ij}}
        let st = RDl2PcStatement {
            pc: presig.pc_hat_k[i],
            x: presig.xhat_points[j],
            b,
            n: n_ij,
            r: big_r,
            m: m_ij,
        };
        let proof = RDl2PcProof::prove(&st, &presig.k_i, &presig.hat_k_randomness, &mu_ij, rng);
        m_row[j] = Some(m_ij);
        n_row[j] = Some(n_ij);
        proofs[j] = Some(proof);
    }

    SignContribution {
        index: i,
        s_i,
        m_row,
        n_row,
        proofs,
    }
}

/// Verify party `i`'s NIZKDL-2PC proofs (WMY23 Fig. 8, proof step).
///
/// Each `M_{ij}` is bound (via `R_DL-2PC`) to `i`'s committed nonce share
/// `PC_{hat_k_i}` and the peer key share `hat_X_j`, so a failure here is
/// unambiguously attributable to party `i`.
///
/// `presig` is the verifier's own presignature; its `pc_hat_k`,
/// `xhat_points` and `big_r_shares` vectors are identical across parties
/// (they are derived from the broadcast presign transcript), so they pin the
/// statement for party `i` independently of `i`'s own claims.
#[must_use]
pub fn verify_contribution_proofs(
    presig: &Wmy23Presignature,
    contribs: &[SignContribution],
    i: usize,
) -> bool {
    let n = presig.n_signers;
    if contribs.len() != n || i >= n {
        return false;
    }
    let big_r = presig.big_r;
    let b = base_b();
    let ci = &contribs[i];
    for j in 0..n {
        if j == i {
            continue;
        }
        let (Some(m_ij), Some(n_ij), Some(proof)) =
            (ci.m_row[j], ci.n_row[j], ci.proofs[j].as_ref())
        else {
            return false;
        };
        let st = RDl2PcStatement {
            pc: presig.pc_hat_k[i],
            x: presig.xhat_points[j],
            b,
            n: n_ij,
            r: big_r,
            m: m_ij,
        };
        if !proof.verify(&st) {
            return false;
        }
    }
    true
}

/// Verify party `i`'s share-consistency equation (WMY23 Eq. (3), additive
/// form):
///
/// ```text
/// s_i*R + r*sum_{j!=i}(M_{ji} - M_{ij}) == m*R_i + r*hat_X_i
/// ```
///
/// This must only be run once every party's NIZKDL-2PC proofs have verified
/// (so every `M_{ab}` is well-formed). With all `M`'s well-formed, an
/// equation failure can only stem from an inconsistent partial signature
/// `s_i`, so the fault is attributable to party `i`.
#[must_use]
pub fn verify_contribution_equation(
    presig: &Wmy23Presignature,
    message: &DataToSign<k256::Secp256k1>,
    contribs: &[SignContribution],
    i: usize,
) -> bool {
    let n = presig.n_signers;
    if contribs.len() != n || i >= n {
        return false;
    }
    let m = *message.digest();
    let r = presig.r_x;
    let big_r = presig.big_r;
    let ci = &contribs[i];

    let mut lhs = big_r * ci.s_i;
    for j in 0..n {
        if j == i {
            continue;
        }
        let (Some(m_ij), Some(m_ji)) = (ci.m_row[j], contribs[j].m_row[i]) else {
            return false;
        };
        lhs += (m_ji - m_ij) * r;
    }
    let rhs = presig.big_r_shares[i] * m + presig.xhat_points[i] * r;
    lhs == rhs
}

/// Convenience wrapper: party `i`'s contribution is valid iff its
/// NIZKDL-2PC proofs *and* its share-consistency equation hold.
///
/// For correct cheater *attribution* prefer running
/// [`verify_contribution_proofs`] across all parties first, and only then
/// [`verify_contribution_equation`] (see [`crate::sign`]).
#[must_use]
pub fn verify_contribution(
    presig: &Wmy23Presignature,
    message: &DataToSign<k256::Secp256k1>,
    contribs: &[SignContribution],
    i: usize,
) -> bool {
    verify_contribution_proofs(presig, contribs, i)
        && verify_contribution_equation(presig, message, contribs, i)
}

/// Reconstruct the final ECDSA signature `s = sum_i s_i` (WMY23 Fig. 9).
///
/// # Errors
///
/// Returns an error if the assembled signature fails ECDSA verification.
pub fn combine_signatures(
    presig: &Wmy23Presignature,
    contribs: &[SignContribution],
    message: &DataToSign<k256::Secp256k1>,
    public_key: &Point,
) -> Result<Signature<k256::Secp256k1>, Box<dyn std::error::Error>> {
    let s_raw: Scalar = contribs.iter().map(|c| c.s_i).sum();
    let s = low_s_normalize::<k256::Secp256k1>(s_raw);
    let sig = Signature { r: presig.r_x, s };
    verify_ecdsa::<k256::Secp256k1>(&sig, public_key, message)?;
    Ok(sig)
}

/// x-coordinate helper kept for parity with the presignature `r` value.
#[must_use]
pub fn r_from_point(big_r: &Point) -> Scalar {
    <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine())
}
