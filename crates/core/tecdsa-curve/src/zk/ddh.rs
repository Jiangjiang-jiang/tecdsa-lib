// SPDX-License-Identifier: MIT OR Apache-2.0
//! Non-interactive DDH-tuple zero-knowledge proof.
//!
//! Proves that `(G, A, B, C)` is a Diffie-Hellman tuple: the prover knows
//! a witness `w` such that `B = w*G` and `C = w*A`.
//!
//! # Sigma Protocol
//!
//! - **Statement:** `(G, A, B, C)` with `B = wG`, `C = wA`
//! - **Witness:** `w`
//! - **Commit:** sample `r <- Z_q`, compute `R_G = rG`, `R_A = rA`
//! - **Challenge:** `e = H(G || A || B || C || R_G || R_A)` via SHA-256, reduced to scalar
//! - **Response:** `z = r - e*w`
//! - **Verify:** `z*G + e*B == R_G` and `z*A + e*C == R_A`

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use sha2::{Digest, Sha256};

use crate::TecdsaCurve;

/// Statement for a DDH-tuple proof: four group elements `(G, A, B, C)`.
pub struct DdhStatement<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Base generator (typically the standard generator).
    pub g: C::ProjectivePoint,
    /// Second base point.
    pub a: C::ProjectivePoint,
    /// `B = w * G`.
    pub b: C::ProjectivePoint,
    /// `C = w * A`.
    pub c: C::ProjectivePoint,
}

/// Witness for a DDH-tuple proof: the secret scalar `w`.
pub struct DdhWitness<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret scalar such that `B = wG` and `C = wA`.
    pub w: C::Scalar,
}

/// Non-interactive DDH-tuple proof.
pub struct DdhProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Commitment `R_G = r * G`.
    pub g_r: C::ProjectivePoint,
    /// Commitment `R_A = r * A`.
    pub a_r: C::ProjectivePoint,
    /// Response scalar `z = r - e * w`.
    pub z: C::Scalar,
}

impl<C: TecdsaCurve> Clone for DdhProof<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            g_r: self.g_r,
            a_r: self.a_r,
            z: self.z,
        }
    }
}

impl<C: TecdsaCurve> DdhProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Compute the Fiat-Shamir challenge:
    /// `e = H(G || A || B || C || R_G || R_A)` reduced to a scalar.
    fn challenge(
        stmt: &DdhStatement<C>,
        g_r: &C::ProjectivePoint,
        a_r: &C::ProjectivePoint,
    ) -> C::Scalar {
        let hash: [u8; 32] = Sha256::new()
            .chain_update(b"DdhProof")
            .chain_update(stmt.g.to_bytes().as_ref())
            .chain_update(stmt.a.to_bytes().as_ref())
            .chain_update(stmt.b.to_bytes().as_ref())
            .chain_update(stmt.c.to_bytes().as_ref())
            .chain_update(g_r.to_bytes().as_ref())
            .chain_update(a_r.to_bytes().as_ref())
            .finalize()
            .into();

        C::scalar_from_bytes(&hash)
    }

    /// Create a DDH-tuple proof.
    ///
    /// The prover demonstrates knowledge of `wit.w` such that
    /// `stmt.b = wit.w * stmt.g` and `stmt.c = wit.w * stmt.a`.
    #[must_use]
    pub fn prove(
        stmt: &DdhStatement<C>,
        wit: &DdhWitness<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let r = C::random_scalar(rng);
        let g_r = stmt.g * r;
        let a_r = stmt.a * r;
        let e = Self::challenge(stmt, &g_r, &a_r);
        // z = r - e * w
        let z = r - e * wit.w;
        Self { g_r, a_r, z }
    }

    /// Verify a DDH-tuple proof against the given statement.
    ///
    /// Checks that `z*G + e*B == R_G` and `z*A + e*C == R_A`.
    #[must_use]
    pub fn verify(&self, stmt: &DdhStatement<C>) -> bool {
        let e = Self::challenge(stmt, &self.g_r, &self.a_r);
        let lhs_g = stmt.g * self.z + stmt.b * e;
        let lhs_a = stmt.a * self.z + stmt.c * e;
        lhs_g == self.g_r && lhs_a == self.a_r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    mod secp256k1_tests {
        use k256::Secp256k1;

        use super::*;

        #[test]
        fn ddh_honest_verifies() {
            let mut rng = rand::thread_rng();
            let g = Secp256k1::generator();
            let w = Secp256k1::random_scalar(&mut rng);
            let a_scalar = Secp256k1::random_scalar(&mut rng);
            let a = g * a_scalar;
            let b = g * w;
            let c = a * w;

            let stmt = DdhStatement::<Secp256k1> { g, a, b, c };
            let wit = DdhWitness::<Secp256k1> { w };
            let proof = DdhProof::prove(&stmt, &wit, &mut rng);
            assert!(proof.verify(&stmt), "honest DDH proof must verify");
        }

        #[test]
        fn ddh_wrong_witness_rejects() {
            let mut rng = rand::thread_rng();
            let g = Secp256k1::generator();
            let w = Secp256k1::random_scalar(&mut rng);
            let w_bad = Secp256k1::random_scalar(&mut rng);
            let a_scalar = Secp256k1::random_scalar(&mut rng);
            let a = g * a_scalar;
            let b = g * w;
            let c = a * w;

            let stmt = DdhStatement::<Secp256k1> { g, a, b, c };
            // Use the wrong witness.
            let wit_bad = DdhWitness::<Secp256k1> { w: w_bad };
            let proof = DdhProof::prove(&stmt, &wit_bad, &mut rng);
            assert!(
                !proof.verify(&stmt),
                "DDH proof with wrong witness must not verify"
            );
        }
    }
}
