// SPDX-License-Identifier: GPL-3.0-or-later
//! TX25 online sign round logic (zero-sharing, Lagrange, assembly, cheater ID).

use std::collections::BTreeMap;

use elliptic_curve::PrimeField;
use sha2::{Digest, Sha256};

use tecdsa_core::TecdsaError;
use tecdsa_curve::zk::ddh::DdhStatement;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};
use tecdsa_protocol::{AbortReason, IaReport, PartyId};

use crate::presign::Tx25Presignature;

use super::msg::OnlineRoundMsg;

// ---------------------------------------------------------------------------
// Zero-sharing polynomial
// ---------------------------------------------------------------------------

/// Generate evaluations of a random (t-1)-degree polynomial with f(0) = 0.
///
/// The polynomial has the form f(x) = a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1},
/// so f(0) = 0 by construction.
///
/// Returns a map from party_id -> f(party_id) mod q.
pub(crate) fn zero_poly_eval(
    t: u16,
    party_ids: &[u16],
    rng: &mut impl rand_core::CryptoRngCore,
) -> BTreeMap<u16, k256::Scalar> {
    // Sample t-1 random coefficients for x^1 ... x^{t-1}.
    let degree = t.saturating_sub(1);
    let coeffs: Vec<k256::Scalar> = (0..degree)
        .map(|_| k256::Secp256k1::random_scalar(rng))
        .collect();

    let mut result = BTreeMap::new();
    for &pid in party_ids {
        let x = k256::Scalar::from(u64::from(pid));
        let mut val = k256::Scalar::ZERO;
        let mut x_pow = x; // x^1
        for coeff in &coeffs {
            val += *coeff * x_pow;
            x_pow *= x;
        }
        result.insert(pid, val);
    }
    result
}

// ---------------------------------------------------------------------------
// Lagrange coefficients
// ---------------------------------------------------------------------------

/// Compute the Lagrange coefficient lambda_{i, S} for party i over the set S.
///
/// lambda_{i, S} = product_{j in S, j != i} j / (j - i)
///
/// All arithmetic in Z_q (k256::Scalar).
pub(crate) fn lagrange_coeff(party_ids: &[u16], i: u16) -> k256::Scalar {
    let mut num = k256::Scalar::ONE;
    let mut den = k256::Scalar::ONE;
    let xi = k256::Scalar::from(u64::from(i));

    for &j in party_ids {
        if j == i {
            continue;
        }
        let xj = k256::Scalar::from(u64::from(j));
        num *= xj;
        den *= xj - xi;
    }

    // den^{-1} * num
    let den_inv = den.invert();
    // If invert returns CtOption with is_none, it means den == 0
    // which should never happen if party_ids are distinct.
    let den_inv_val: k256::Scalar = Option::from(den_inv)
        .expect("Lagrange denominator must be non-zero for distinct party ids");
    num * den_inv_val
}

// ---------------------------------------------------------------------------
// Message hashing
// ---------------------------------------------------------------------------

/// Hash a message to a scalar using SHA-256, truncated/reduced to the
/// secp256k1 scalar field.
pub(crate) fn hash_message_to_scalar(message: &[u8]) -> k256::Scalar {
    let hash: [u8; 32] = Sha256::digest(message).into();
    let mut repr = k256::FieldBytes::default();
    repr.copy_from_slice(&hash);
    // Try direct repr; if >= q, clear top bit.
    if let Some(s) = Option::from(k256::Scalar::from_repr(repr)) {
        return s;
    }
    repr[0] &= 0x7F;
    Option::from(k256::Scalar::from_repr(repr))
        .expect("scalar reduction must succeed after clearing top bit")
}

// ---------------------------------------------------------------------------
// Signature assembly
// ---------------------------------------------------------------------------

/// Assemble the ECDSA signature from all parties' delta and chi shares.
///
/// numerator   = sum_{j,nu in S} lambda_{j,S} * lambda_{nu,S} * chi_{j,nu}
/// denominator = sum_{j,nu in S} lambda_{j,S} * lambda_{nu,S} * delta_{j,nu}
/// s = numerator / denominator mod q
///
/// Returns `None` if denominator is zero.
pub(crate) fn assemble_signature(
    party_ids: &[u16],
    all_deltas: &BTreeMap<u16, BTreeMap<u16, k256::Scalar>>,
    all_chis: &BTreeMap<u16, BTreeMap<u16, k256::Scalar>>,
) -> Option<k256::Scalar> {
    let mut numerator = k256::Scalar::ZERO;
    let mut denominator = k256::Scalar::ZERO;

    // Precompute Lagrange coefficients.
    let lambdas: BTreeMap<u16, k256::Scalar> = party_ids
        .iter()
        .map(|&pid| (pid, lagrange_coeff(party_ids, pid)))
        .collect();

    for &j in party_ids {
        let lam_j = lambdas[&j];
        let chis_j = all_chis.get(&j)?;
        let deltas_j = all_deltas.get(&j)?;

        for &nu in party_ids {
            let lam_nu = lambdas[&nu];
            let weight = lam_j * lam_nu;

            if let Some(&chi_jnu) = chis_j.get(&nu) {
                numerator += weight * chi_jnu;
            }
            if let Some(&delta_jnu) = deltas_j.get(&nu) {
                denominator += weight * delta_jnu;
            }
        }
    }

    // s = numerator / denominator
    let den_inv = denominator.invert();
    let den_inv_val: k256::Scalar = Option::from(den_inv)?;
    Some(numerator * den_inv_val)
}

// ---------------------------------------------------------------------------
// Cheater identification
// ---------------------------------------------------------------------------

/// Identify and remove cheaters, then re-assemble the signature.
///
/// For each party j, recomputes D_j and Gamma_j from public data and
/// verifies the DDH proof.  Cheaters are removed from the signing set.
///
/// Returns `(output, ia_report)` if successful after cheater removal,
/// or an error if not enough honest parties remain.
pub(crate) fn identify_cheaters(
    party_ids: &[u16],
    presignature: &Tx25Presignature,
    a_point: k256::ProjectivePoint,
    public_key: k256::ProjectivePoint,
    message: &DataToSign<k256::Secp256k1>,
    received: &BTreeMap<u16, OnlineRoundMsg>,
    all_deltas: &BTreeMap<u16, BTreeMap<u16, k256::Scalar>>,
    all_chis: &BTreeMap<u16, BTreeMap<u16, k256::Scalar>>,
) -> tecdsa_core::Result<(Option<Signature<k256::Secp256k1>>, Option<IaReport>)> {
    let r_point = presignature.r_point;
    let r_x = presignature.r_x;
    let g = k256::Secp256k1::generator();

    // Precompute Lagrange coefficients for the full set.
    let lambdas: BTreeMap<u16, k256::Scalar> = party_ids
        .iter()
        .map(|&pid| (pid, lagrange_coeff(party_ids, pid)))
        .collect();

    let mut cheaters = Vec::new();

    for &j in party_ids {
        let msg_j = match received.get(&j) {
            Some(m) => m,
            None => {
                cheaters.push(j);
                continue;
            }
        };

        // Recompute D_j from public data:
        // D_j = sum_{nu in S} lambda_{nu,S} * (delta_{j,nu} * G - B_{j,nu} + B_{nu,j})
        let mut d_recomputed = k256::ProjectivePoint::IDENTITY;

        for &nu in party_ids {
            let lam_nu = lambdas[&nu];

            let delta_jnu = msg_j
                .delta_shares
                .get(&nu)
                .copied()
                .unwrap_or(k256::Scalar::ZERO);

            // B_{j,nu} from presignature public data.
            let b_jnu = presignature
                .b_points
                .get(&(j, nu))
                .copied()
                .unwrap_or(k256::ProjectivePoint::IDENTITY);

            // B_{nu,j} from presignature public data.
            let b_nuj = presignature
                .b_points
                .get(&(nu, j))
                .copied()
                .unwrap_or(k256::ProjectivePoint::IDENTITY);

            // lambda_{nu} * (delta_{j,nu} * G - B_{j,nu} + B_{nu,j})
            let term = (g * delta_jnu - b_jnu + b_nuj) * lam_nu;
            d_recomputed += term;
        }

        // Recompute Gamma_j from public data:
        // Gamma_j = sum_{nu in S} lambda_{nu,S} * (chi_{j,nu} * G - r * B_hat_{j,nu} + r * B_hat_{nu,j})
        let mut gamma_recomputed = k256::ProjectivePoint::IDENTITY;

        for &nu in party_ids {
            let lam_nu = lambdas[&nu];

            let chi_jnu = all_chis
                .get(&j)
                .and_then(|m| m.get(&nu))
                .copied()
                .unwrap_or(k256::Scalar::ZERO);

            let bhat_jnu = presignature
                .b_hat_points
                .get(&(j, nu))
                .copied()
                .unwrap_or(k256::ProjectivePoint::IDENTITY);

            let bhat_nuj = presignature
                .b_hat_points
                .get(&(nu, j))
                .copied()
                .unwrap_or(k256::ProjectivePoint::IDENTITY);

            // lambda_{nu} * (chi_{j,nu} * G - r * B_hat_{j,nu} + r * B_hat_{nu,j})
            let term = (g * chi_jnu - bhat_jnu * r_x + bhat_nuj * r_x) * lam_nu;
            gamma_recomputed += term;
        }

        // Verify DDH proof psi_j for (R, D_j, A, Gamma_j).
        let stmt = DdhStatement::<k256::Secp256k1> {
            g: r_point,
            a: a_point,
            b: d_recomputed,
            c: gamma_recomputed,
        };

        if !msg_j.ddh_proof.verify(&stmt) {
            cheaters.push(j);
        }
    }

    if !cheaters.is_empty() {
        // Remove cheaters and try again.
        let remaining: Vec<u16> = party_ids
            .iter()
            .filter(|pid| !cheaters.contains(pid))
            .copied()
            .collect();

        let t = presignature.threshold;
        if remaining.len() >= (t + 1) as usize {
            // Re-filter deltas and chis to only include remaining parties.
            let mut filtered_deltas: BTreeMap<u16, BTreeMap<u16, k256::Scalar>> = BTreeMap::new();
            let mut filtered_chis: BTreeMap<u16, BTreeMap<u16, k256::Scalar>> = BTreeMap::new();

            for &pid in &remaining {
                if let Some(d) = all_deltas.get(&pid) {
                    let filtered: BTreeMap<u16, k256::Scalar> = d
                        .iter()
                        .filter(|(k, _)| remaining.contains(k))
                        .map(|(&k, &v)| (k, v))
                        .collect();
                    filtered_deltas.insert(pid, filtered);
                }
                if let Some(c) = all_chis.get(&pid) {
                    let filtered: BTreeMap<u16, k256::Scalar> = c
                        .iter()
                        .filter(|(k, _)| remaining.contains(k))
                        .map(|(&k, &v)| (k, v))
                        .collect();
                    filtered_chis.insert(pid, filtered);
                }
            }

            if let Some(s_raw) = assemble_signature(&remaining, &filtered_deltas, &filtered_chis) {
                let s = low_s_normalize::<k256::Secp256k1>(s_raw);
                let sig = Signature { r: r_x, s };

                if verify_ecdsa::<k256::Secp256k1>(&sig, &public_key, message).is_ok() {
                    let report = IaReport {
                        blamed: cheaters.iter().map(|&pid| PartyId(pid)).collect(),
                        reason: AbortReason::ProtocolSpecific(
                            "DDH proof verification failed during cheater identification".into(),
                        ),
                    };
                    return Ok((Some(sig), Some(report)));
                }
            }
        }

        // Not enough honest parties or re-assembly still failed.
        let _report = IaReport {
            blamed: cheaters.iter().map(|&pid| PartyId(pid)).collect(),
            reason: AbortReason::ProtocolSpecific(
                "signature assembly failed after cheater removal".into(),
            ),
        };
        return Err(TecdsaError::Other(format!(
            "online sign failed: {} cheaters identified, not enough honest parties remain",
            cheaters.len()
        )));
    }

    // No cheaters identified but signature still fails -- should not happen.
    Err(TecdsaError::Other(
        "signature verification failed but no cheaters identified".into(),
    ))
}
