#![allow(non_snake_case)]

use elliptic_curve::CurveArithmetic;
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::nizk::{RDl2PcProof, RDl2PcStatement};
use crate::presign::Wmy23Presignature;

type Point = k256::ProjectivePoint;
type Scalar = k256::Scalar;

#[derive(Clone, Debug)]
pub struct SignContribution {
    pub index: usize,
    pub s_i: Scalar,
    pub m_row: Vec<Option<Point>>,
    pub n_row: Vec<Option<Point>>,
    pub proofs: Vec<Option<RDl2PcProof>>,
}

fn base_b() -> Point {
    -<k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR
}

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

    let s_i = m * presig.k_i + r * presig.sigma_i;

    let mut m_row: Vec<Option<Point>> = vec![None; n];
    let mut n_row: Vec<Option<Point>> = vec![None; n];
    let mut proofs: Vec<Option<RDl2PcProof>> = vec![None; n];

    for j in 0..n {
        if j == i {
            continue;
        }
        let (Some(mu_ij), Some(n_ij)) = (presig.mu_shares[j], presig.nu_points[j]) else {
            continue;
        };
        let m_ij = big_r * mu_ij;
        let st = RDl2PcStatement {
            pc: presig.pc_hat_k[i],
            x: presig.xhat_points[j],
            b,
            n: n_ij,
            r: big_r,
            m: m_ij,
        };
        let proof =
            RDl2PcProof::prove(&st, &presig.k_i, &presig.hat_k_randomness, &mu_ij, rng);
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

pub fn combine_signatures(
    presig: &Wmy23Presignature,
    contribs: &[SignContribution],
    message: &DataToSign<k256::Secp256k1>,
    public_key: &Point,
) -> Result<Signature<k256::Secp256k1>, Box<dyn std::error::Error>> {
    let s_raw: Scalar = contribs.iter().map(|c| c.s_i).sum();
    let s = low_s_normalize::<k256::Secp256k1>(s_raw);
    let sig = Signature {
        r: presig.r_x,
        s,
    };
    verify_ecdsa::<k256::Secp256k1>(&sig, public_key, message)?;
    Ok(sig)
}

#[must_use]
pub fn r_from_point(big_r: &Point) -> Scalar {
    <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine())
}
