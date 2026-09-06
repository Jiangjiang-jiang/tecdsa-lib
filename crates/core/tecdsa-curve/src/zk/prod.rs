// SPDX-License-Identifier: MIT OR Apache-2.0
//! Scalar-product zero-knowledge proof `R_prod`.
//!
//! Proves that `(E, F)` is computed by multiplying the ElGamal-encrypted value
//! in `(C, D)` by `(A, B)` and rerandomizing.
//!
//! # Relation
//!
//! - **Statement:** `(P, A, B, C, D, E, F)` -- seven EC points
//! - **Witness:** `(t, r, y)` such that:
//!   - `(C, D) = EGexpEnc_P(y; t)`, i.e., `C = t*G`, `D = t*P + y*G`
//!   - `E = y*A + r*G`
//!   - `F = y*B + r*P`
//!
//! # Sigma Protocol (LN18 Appendix A.3)
//!
//! - **Commit:** sample `sigma, rho <- Z_q`, compute
//!   `X = sigma*A + rho*G`, `Y = sigma*B + rho*P`, `W = sigma*G`
//! - **Challenge:** `e = H(P || A || B || C || D || E || F || X || Y || W)`
//! - **Response:** `z1 = sigma + e*y`, `z2 = rho + e*r`
//! - **Nested DDH:** proves `(G, P, e*C, e*D + W - z1*G)` is a DH tuple
//!   with witness `w = e*t`
//! - **Verify:**
//!   1. `z1*A + z2*G == X + e*E`
//!   2. `z1*B + z2*P == Y + e*F`
//!   3. Nested DDH proof verifies

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use sha2::{Digest, Sha256};

use super::ddh::{DdhProof, DdhStatement, DdhWitness};
use crate::TecdsaCurve;

/// Statement for the scalar-product proof `R_prod`.
pub struct ProdStatement<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// `ElGamal` public key `P`.
    pub p: C::ProjectivePoint,
    /// Point `A`.
    pub a: C::ProjectivePoint,
    /// Point `B`.
    pub b: C::ProjectivePoint,
    /// `EGexpEnc` ciphertext part 1: `C = t*G`.
    pub c: C::ProjectivePoint,
    /// `EGexpEnc` ciphertext part 2: `D = t*P + y*G`.
    pub d: C::ProjectivePoint,
    /// Product ciphertext part 1: `E = y*A + r*G`.
    pub e_pt: C::ProjectivePoint,
    /// Product ciphertext part 2: `F = y*B + r*P`.
    pub f: C::ProjectivePoint,
}

/// Witness for the scalar-product proof: `(t, r, y)`.
pub struct ProdWitness<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// `EGexpEnc` randomness for `(C, D)`.
    pub t: C::Scalar,
    /// Rerandomization randomness for `(E, F)`.
    pub r: C::Scalar,
    /// The scalar multiplier.
    pub y: C::Scalar,
}

/// Non-interactive scalar-product proof `R_prod`.
pub struct ProdProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Commitment `X = sigma*A + rho*G`.
    pub x: C::ProjectivePoint,
    /// Commitment `Y = sigma*B + rho*P`.
    pub y_commit: C::ProjectivePoint,
    /// Commitment `W = sigma*G`.
    pub w: C::ProjectivePoint,
    /// Response `z1 = sigma + e*y`.
    pub z1: C::Scalar,
    /// Response `z2 = rho + e*r`.
    pub z2: C::Scalar,
    /// Nested DDH proof for `(C, D)` consistency.
    pub ddh_proof: DdhProof<C>,
}

impl<C: TecdsaCurve> Clone for ProdProof<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            x: self.x,
            y_commit: self.y_commit,
            w: self.w,
            z1: self.z1,
            z2: self.z2,
            ddh_proof: self.ddh_proof.clone(),
        }
    }
}

impl<C: TecdsaCurve> ProdProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Compute the Fiat-Shamir challenge:
    /// `e = H(P || A || B || C || D || E || F || X || Y || W)` reduced to a scalar.
    fn challenge(
        stmt: &ProdStatement<C>,
        x: &C::ProjectivePoint,
        y_commit: &C::ProjectivePoint,
        w: &C::ProjectivePoint,
    ) -> C::Scalar {
        let hash: [u8; 32] = Sha256::new()
            .chain_update(b"ProdProof")
            .chain_update(stmt.p.to_bytes().as_ref())
            .chain_update(stmt.a.to_bytes().as_ref())
            .chain_update(stmt.b.to_bytes().as_ref())
            .chain_update(stmt.c.to_bytes().as_ref())
            .chain_update(stmt.d.to_bytes().as_ref())
            .chain_update(stmt.e_pt.to_bytes().as_ref())
            .chain_update(stmt.f.to_bytes().as_ref())
            .chain_update(x.to_bytes().as_ref())
            .chain_update(y_commit.to_bytes().as_ref())
            .chain_update(w.to_bytes().as_ref())
            .finalize()
            .into();

        C::scalar_from_bytes(&hash)
    }

    /// Build the nested DDH statement from the main proof components.
    ///
    /// The DDH tuple is `(G, P, e*C, e*D + W - z1*G)` with witness `w = e*t`.
    ///
    /// Verification:
    /// - `B_ddh = e*C = e*t*G = (e*t)*G = w*G`
    /// - `C_ddh = e*D + W - z1*G = e*(t*P + y*G) + sigma*G - (sigma + e*y)*G = e*t*P = w*P`
    fn ddh_statement(
        stmt: &ProdStatement<C>,
        e: &C::Scalar,
        w_commit: &C::ProjectivePoint,
        z1: &C::Scalar,
    ) -> DdhStatement<C> {
        let g = C::generator();
        let b_ddh = stmt.c * *e;
        let c_ddh = stmt.d * *e + *w_commit - g * *z1;
        DdhStatement {
            g,
            a: stmt.p,
            b: b_ddh,
            c: c_ddh,
        }
    }

    /// Create a scalar-product proof.
    ///
    /// Demonstrates knowledge of `(t, r, y)` such that the statement holds.
    #[must_use]
    pub fn prove(
        stmt: &ProdStatement<C>,
        witness: &ProdWitness<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let g = C::generator();

        // Sample commitment nonces
        let sigma = C::random_scalar(rng);
        let rho = C::random_scalar(rng);

        // Commit: X = sigma*A + rho*G, Y = sigma*B + rho*P, W = sigma*G
        let x = stmt.a * sigma + g * rho;
        let y_commit = stmt.b * sigma + stmt.p * rho;
        let w = g * sigma;

        // Challenge
        let e = Self::challenge(stmt, &x, &y_commit, &w);

        // Response: z1 = sigma + e*y, z2 = rho + e*r
        let z1 = sigma + e * witness.y;
        let z2 = rho + e * witness.r;

        // Build nested DDH statement and prove
        let ddh_stmt = Self::ddh_statement(stmt, &e, &w, &z1);
        let w_ddh = witness.t * e;
        let ddh_wit = DdhWitness::<C> { w: w_ddh };
        let ddh_proof = DdhProof::prove(&ddh_stmt, &ddh_wit, rng);

        Self {
            x,
            y_commit,
            w,
            z1,
            z2,
            ddh_proof,
        }
    }

    /// Verify a scalar-product proof against the given statement.
    ///
    /// Checks:
    /// 1. `z1*A + z2*G == X + e*E`
    /// 2. `z1*B + z2*P == Y + e*F`
    /// 3. Nested DDH proof verifies
    #[must_use]
    pub fn verify(&self, stmt: &ProdStatement<C>) -> bool {
        let g = C::generator();
        let e = Self::challenge(stmt, &self.x, &self.y_commit, &self.w);

        // Check 1: z1*A + z2*G == X + e*E
        let lhs1 = stmt.a * self.z1 + g * self.z2;
        let rhs1 = self.x + stmt.e_pt * e;
        if lhs1 != rhs1 {
            return false;
        }

        // Check 2: z1*B + z2*P == Y + e*F
        let lhs2 = stmt.b * self.z1 + stmt.p * self.z2;
        let rhs2 = self.y_commit + stmt.f * e;
        if lhs2 != rhs2 {
            return false;
        }

        // Check 3: Nested DDH proof verifies
        let ddh_stmt = Self::ddh_statement(stmt, &e, &self.w, &self.z1);
        self.ddh_proof.verify(&ddh_stmt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    mod secp256k1_tests {
        use k256::Secp256k1;

        use super::*;

        type C = Secp256k1;

        /// Helper: build a valid statement + witness for testing.
        fn setup() -> (ProdStatement<C>, ProdWitness<C>) {
            let mut rng = rand::thread_rng();
            let g = C::generator();

            // ElGamal key pair
            let dk = C::random_scalar(&mut rng);
            let pk = g * dk;

            // Random points A, B
            let alpha = C::random_scalar(&mut rng);
            let a = g * alpha;
            let b = pk * alpha; // B = alpha * P (so A, B are "consistent")

            // Witness scalars
            let y = C::random_scalar(&mut rng);
            let t = C::random_scalar(&mut rng);
            let r = C::random_scalar(&mut rng);

            // EGexpEnc(y; t): C = t*G, D = t*P + y*G
            let c = g * t;
            let d = pk * t + g * y;

            // Product: E = y*A + r*G, F = y*B + r*P
            let e_pt = a * y + g * r;
            let f = b * y + pk * r;

            let stmt = ProdStatement::<C> {
                p: pk,
                a,
                b,
                c,
                d,
                e_pt,
                f,
            };
            let witness = ProdWitness::<C> { t, r, y };
            (stmt, witness)
        }

        #[test]
        fn prod_honest_verifies() {
            let (stmt, witness) = setup();
            let mut rng = rand::thread_rng();
            let proof = ProdProof::prove(&stmt, &witness, &mut rng);
            assert!(proof.verify(&stmt), "honest ProdProof must verify");
        }

        #[test]
        fn prod_wrong_y_rejects() {
            let (stmt, witness) = setup();
            let mut rng = rand::thread_rng();

            // Use wrong y value
            let bad_witness = ProdWitness::<C> {
                t: witness.t,
                r: witness.r,
                y: C::random_scalar(&mut rng),
            };
            let proof = ProdProof::prove(&stmt, &bad_witness, &mut rng);
            assert!(
                !proof.verify(&stmt),
                "ProdProof with wrong y must not verify"
            );
        }

        #[test]
        fn prod_wrong_r_rejects() {
            let (stmt, witness) = setup();
            let mut rng = rand::thread_rng();

            // Use wrong r value
            let bad_witness = ProdWitness::<C> {
                t: witness.t,
                r: C::random_scalar(&mut rng),
                y: witness.y,
            };
            let proof = ProdProof::prove(&stmt, &bad_witness, &mut rng);
            assert!(
                !proof.verify(&stmt),
                "ProdProof with wrong r must not verify"
            );
        }

        #[test]
        fn prod_wrong_t_rejects() {
            let (stmt, witness) = setup();
            let mut rng = rand::thread_rng();

            // Use wrong t value — DDH sub-proof should fail
            let bad_witness = ProdWitness::<C> {
                t: C::random_scalar(&mut rng),
                r: witness.r,
                y: witness.y,
            };
            let proof = ProdProof::prove(&stmt, &bad_witness, &mut rng);
            assert!(
                !proof.verify(&stmt),
                "ProdProof with wrong t must not verify"
            );
        }
    }
}
