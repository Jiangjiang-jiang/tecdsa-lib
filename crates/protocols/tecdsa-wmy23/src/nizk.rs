// SPDX-License-Identifier: MIT OR Apache-2.0
//! EC-group NIZK for the WMY23 `R_DL-2PC` relation (paper Fig. 13).
//!
//! `R_DL-2PC` ties together a Pedersen commitment, a "multiply in the
//! exponent" relation, and a discrete-log-to-base-`R` relation. It is the
//! proof attached to each MtAwc share-in-exponent during *identifiable*
//! online signing (WMY23 Figures 7-9), letting every party check that a
//! peer's broadcast `M_{ij} = R^{mu_{ij}}` is consistent with its committed
//! nonce share and the public key share.
//!
//! Relation (statement `x`, witness `w`):
//!
//! ```text
//! R_DL-2PC = { ((PC, X, B, N, R, M), (k, k', mu)) :
//!                PC = g^k h^{k'}        (Pedersen commitment to k)
//!              ∧ X^k B^{mu} = N         (mul-in-exponent; here B = 1/g)
//!              ∧ M = R^{mu} }           (dlog to base R)
//! ```
//!
//! Sigma-protocol (Fiat-Shamir, paper Fig. 13):
//!
//! ```text
//! r1, r2, r3 <- Z_q
//! T1 = g^{r1} h^{r2},  T2 = X^{r1} B^{r3},  T3 = R^{r3}
//! c  = H(PC, X, B, N, R, M, T1, T2, T3)
//! u1 = r1 + c k,  u2 = r2 + c k',  u3 = r3 + c mu
//! verify:  g^{u1} h^{u2} = T1 PC^c
//!        ∧ X^{u1} B^{u3} = T2 N^c
//!        ∧ R^{u3}        = T3 M^c
//! ```

#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, ops::Reduce, CurveArithmetic};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;

type Point = k256::ProjectivePoint;
type Scalar = k256::Scalar;

/// A non-interactive proof for the `R_DL-2PC` relation (paper Fig. 13).
#[derive(Clone, Debug)]
pub struct RDl2PcProof {
    /// Commitment `T1 = g^{r1} h^{r2}`.
    pub t1: Point,
    /// Commitment `T2 = X^{r1} B^{r3}`.
    pub t2: Point,
    /// Commitment `T3 = R^{r3}`.
    pub t3: Point,
    /// Response `u1 = r1 + c k`.
    pub u1: Scalar,
    /// Response `u2 = r2 + c k'`.
    pub u2: Scalar,
    /// Response `u3 = r3 + c mu`.
    pub u3: Scalar,
}

/// The statement `(PC, X, B, N, R, M)` of the `R_DL-2PC` relation.
#[derive(Clone, Copy, Debug)]
pub struct RDl2PcStatement {
    /// Pedersen commitment `PC = g^k h^{k'}` to the nonce share `k`.
    pub pc: Point,
    /// Base `X` (here `g^{hat_x_j}`, the peer's key share in exponent).
    pub x: Point,
    /// Base `B` (here `1/g = -G`).
    pub b: Point,
    /// Target `N = X^k B^{mu}` (here `g^{nu_{ij}}`).
    pub n: Point,
    /// Base `R` (the signature nonce point).
    pub r: Point,
    /// Target `M = R^{mu}` (here `R^{mu_{ij}}`).
    pub m: Point,
}

fn challenge(st: &RDl2PcStatement, t1: &Point, t2: &Point, t3: &Point) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"WMY23-R_DL-2PC");
    for p in [&st.pc, &st.x, &st.b, &st.n, &st.r, &st.m, t1, t2, t3] {
        h.update(p.to_bytes());
    }
    let digest = h.finalize();
    Scalar::reduce(&k256::U256::from_be_slice(&digest))
}

impl RDl2PcProof {
    /// Generate a proof for `statement` with witness `(k, k_prime, mu)`.
    pub fn prove(
        st: &RDl2PcStatement,
        k: &Scalar,
        k_prime: &Scalar,
        mu: &Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();

        let r1 = k256::Secp256k1::random_scalar(rng);
        let r2 = k256::Secp256k1::random_scalar(rng);
        let r3 = k256::Secp256k1::random_scalar(rng);

        let t1 = g * r1 + h * r2;
        let t2 = st.x * r1 + st.b * r3;
        let t3 = st.r * r3;

        let c = challenge(st, &t1, &t2, &t3);

        let u1 = r1 + c * k;
        let u2 = r2 + c * k_prime;
        let u3 = r3 + c * mu;

        Self {
            t1,
            t2,
            t3,
            u1,
            u2,
            u3,
        }
    }

    /// Verify the proof against `statement`.
    #[must_use]
    pub fn verify(&self, st: &RDl2PcStatement) -> bool {
        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();

        let c = challenge(st, &self.t1, &self.t2, &self.t3);

        // g^{u1} h^{u2} == T1 PC^c
        if g * self.u1 + h * self.u2 != self.t1 + st.pc * c {
            return false;
        }
        // X^{u1} B^{u3} == T2 N^c
        if st.x * self.u1 + st.b * self.u3 != self.t2 + st.n * c {
            return false;
        }
        // R^{u3} == T3 M^c
        if st.r * self.u3 != self.t3 + st.m * c {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an honest statement+witness: `M = R^{mu}`, `N = X^k B^{mu}`,
    /// `PC = g^k h^{k'}`, with `B = -G`.
    fn honest(rng: &mut impl CryptoRngCore) -> (RDl2PcStatement, Scalar, Scalar, Scalar) {
        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();
        let b = -g;

        let k = k256::Secp256k1::random_scalar(rng);
        let k_prime = k256::Secp256k1::random_scalar(rng);
        let mu = k256::Secp256k1::random_scalar(rng);

        // Pick arbitrary bases X, R.
        let x = g * k256::Secp256k1::random_scalar(rng);
        let r = g * k256::Secp256k1::random_scalar(rng);

        let pc = g * k + h * k_prime;
        let n = x * k + b * mu;
        let m = r * mu;

        (RDl2PcStatement { pc, x, b, n, r, m }, k, k_prime, mu)
    }

    #[test]
    fn honest_proof_verifies() {
        let mut rng = rand::thread_rng();
        for _ in 0..20 {
            let (st, k, kp, mu) = honest(&mut rng);
            let proof = RDl2PcProof::prove(&st, &k, &kp, &mu, &mut rng);
            assert!(proof.verify(&st), "honest R_DL-2PC proof must verify");
        }
    }

    #[test]
    fn tampered_m_rejected() {
        let mut rng = rand::thread_rng();
        let (mut st, k, kp, mu) = honest(&mut rng);
        let proof = RDl2PcProof::prove(&st, &k, &kp, &mu, &mut rng);
        // Tamper with M (claim a different mu in exponent).
        st.m += <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        assert!(!proof.verify(&st), "tampered M must be rejected");
    }

    #[test]
    fn tampered_n_rejected() {
        let mut rng = rand::thread_rng();
        let (mut st, k, kp, mu) = honest(&mut rng);
        let proof = RDl2PcProof::prove(&st, &k, &kp, &mu, &mut rng);
        st.n += <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        assert!(!proof.verify(&st), "tampered N must be rejected");
    }

    #[test]
    fn wrong_witness_rejected() {
        let mut rng = rand::thread_rng();
        let (st, k, kp, _mu) = honest(&mut rng);
        let wrong_mu = k256::Secp256k1::random_scalar(&mut rng);
        let proof = RDl2PcProof::prove(&st, &k, &kp, &wrong_mu, &mut rng);
        assert!(!proof.verify(&st), "proof with wrong mu must not verify");
    }
}
