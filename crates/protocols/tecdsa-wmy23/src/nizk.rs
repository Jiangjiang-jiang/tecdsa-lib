#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, ops::Reduce, CurveArithmetic};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;

type Point = k256::ProjectivePoint;
type Scalar = k256::Scalar;

#[derive(Clone, Debug)]
pub struct RDl2PcProof {
    pub t1: Point,
    pub t2: Point,
    pub t3: Point,
    pub u1: Scalar,
    pub u2: Scalar,
    pub u3: Scalar,
}

#[derive(Clone, Copy, Debug)]
pub struct RDl2PcStatement {
    pub pc: Point,
    pub x: Point,
    pub b: Point,
    pub n: Point,
    pub r: Point,
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

    #[must_use]
    pub fn verify(&self, st: &RDl2PcStatement) -> bool {
        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();

        let c = challenge(st, &self.t1, &self.t2, &self.t3);

        if g * self.u1 + h * self.u2 != self.t1 + st.pc * c {
            return false;
        }
        if st.x * self.u1 + st.b * self.u3 != self.t2 + st.n * c {
            return false;
        }
        if st.r * self.u3 != self.t3 + st.m * c {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn honest(rng: &mut impl CryptoRngCore) -> (RDl2PcStatement, Scalar, Scalar, Scalar) {
        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();
        let b = -g;

        let k = k256::Secp256k1::random_scalar(rng);
        let k_prime = k256::Secp256k1::random_scalar(rng);
        let mu = k256::Secp256k1::random_scalar(rng);

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
