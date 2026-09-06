// SPDX-License-Identifier: MIT OR Apache-2.0
//! Zero-knowledge proof of knowledge for ElGamal-in-the-exponent encryption.
//!
//! Proves knowledge of plaintext `x` and randomness `r` such that
//! `(A, B) = EGexpEnc_P(x; r) = (r*G, r*P + x*G)`.
//!
//! # Sigma protocol ($R_{EG}$)
//!
//! - **Statement:** `(P, A, B)` where `A = r*G`, `B = r*P + x*G`
//! - **Witness:** `(x, r)`
//! - **Commit:** sample `sigma, rho <- Z_q`, compute `X = sigma*G`, `Y = sigma*P + rho*G`
//! - **Challenge:** `e = H(P || A || B || X || Y)` via SHA-256, reduced to scalar
//! - **Response:** `z1 = sigma + e*r`, `z2 = rho + e*x`
//! - **Verify:** `z1*G == X + e*A` and `z1*P + z2*G == Y + e*B`

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use sha2::{Digest, Sha256};

use crate::TecdsaCurve;

/// Statement for the `EGexpEnc` knowledge proof: `(P, A, B)`.
pub struct EgexpStatement<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Public key `P = d*G`.
    pub p: C::ProjectivePoint,
    /// Ciphertext first component `A = r*G`.
    pub a: C::ProjectivePoint,
    /// Ciphertext second component `B = r*P + x*G`.
    pub b: C::ProjectivePoint,
}

/// Witness for the `EGexpEnc` knowledge proof: `(x, r)`.
pub struct EgexpWitness<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Plaintext scalar `x`.
    pub x: C::Scalar,
    /// Encryption randomness `r`.
    pub r: C::Scalar,
}

/// Non-interactive proof for the `EGexpEnc` relation.
pub struct EgexpProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Commitment `X = sigma*G`.
    pub commit_x: C::ProjectivePoint,
    /// Commitment `Y = sigma*P + rho*G`.
    pub commit_y: C::ProjectivePoint,
    /// Response `z1 = sigma + e*r` (randomness response).
    pub z1: C::Scalar,
    /// Response `z2 = rho + e*x` (plaintext response).
    pub z2: C::Scalar,
}

impl<C: TecdsaCurve> Clone for EgexpProof<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            commit_x: self.commit_x,
            commit_y: self.commit_y,
            z1: self.z1,
            z2: self.z2,
        }
    }
}

impl<C: TecdsaCurve> EgexpProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Compute the Fiat-Shamir challenge: `e = H(P || A || B || X || Y)` reduced to a scalar.
    fn challenge(
        stmt: &EgexpStatement<C>,
        commit_x: &C::ProjectivePoint,
        commit_y: &C::ProjectivePoint,
    ) -> C::Scalar {
        let hash: [u8; 32] = Sha256::new()
            .chain_update(b"EgexpProof")
            .chain_update(stmt.p.to_bytes().as_ref())
            .chain_update(stmt.a.to_bytes().as_ref())
            .chain_update(stmt.b.to_bytes().as_ref())
            .chain_update(commit_x.to_bytes().as_ref())
            .chain_update(commit_y.to_bytes().as_ref())
            .finalize()
            .into();

        C::scalar_from_bytes(&hash)
    }

    /// Create a proof of knowledge of `(x, r)` such that `(A, B) = EGexpEnc_P(x; r)`.
    ///
    /// - `stmt`: the public statement `(P, A, B)`
    /// - `witness`: the secret witness `(x, r)`
    /// - `rng`: cryptographic RNG for sampling the commitment nonces
    #[must_use]
    pub fn prove(
        stmt: &EgexpStatement<C>,
        witness: &EgexpWitness<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let g = C::generator();

        // Sample commitment nonces
        let sigma = C::random_scalar(rng);
        let rho = C::random_scalar(rng);

        // Commit: X = sigma*G, Y = sigma*P + rho*G
        let commit_x = g * sigma;
        let commit_y = stmt.p * sigma + g * rho;

        // Challenge
        let e = Self::challenge(stmt, &commit_x, &commit_y);

        // Response: z1 = sigma + e*r, z2 = rho + e*x
        let z1 = sigma + e * witness.r;
        let z2 = rho + e * witness.x;

        Self {
            commit_x,
            commit_y,
            z1,
            z2,
        }
    }

    /// Verify a proof against the statement `(P, A, B)`.
    ///
    /// Checks:
    /// 1. `z1*G == X + e*A`
    /// 2. `z1*P + z2*G == Y + e*B`
    #[must_use]
    pub fn verify(&self, stmt: &EgexpStatement<C>) -> bool {
        let g = C::generator();
        let e = Self::challenge(stmt, &self.commit_x, &self.commit_y);

        // Check 1: z1*G == X + e*A
        let lhs1 = g * self.z1;
        let rhs1 = self.commit_x + stmt.a * e;
        if lhs1 != rhs1 {
            return false;
        }

        // Check 2: z1*P + z2*G == Y + e*B
        let lhs2 = stmt.p * self.z1 + g * self.z2;
        let rhs2 = self.commit_y + stmt.b * e;
        lhs2 == rhs2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal_exp;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    #[test]
    #[cfg(feature = "secp256k1")]
    fn egexp_honest_verifies() {
        let mut rng = rand::thread_rng();

        // Key setup
        let dk = C::random_scalar(&mut rng);
        let pk = C::generator() * dk;

        // Encrypt a random message
        let x = C::random_scalar(&mut rng);
        let (ct, r) = elgamal_exp::encrypt_random::<C>(&pk, &x, &mut rng);

        let stmt = EgexpStatement::<C> {
            p: pk,
            a: ct.a,
            b: ct.b,
        };
        let witness = EgexpWitness::<C> { x, r };

        let proof = EgexpProof::prove(&stmt, &witness, &mut rng);
        assert!(proof.verify(&stmt), "honest proof must verify");
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn egexp_wrong_x_rejects() {
        let mut rng = rand::thread_rng();

        let dk = C::random_scalar(&mut rng);
        let pk = C::generator() * dk;

        let x = C::random_scalar(&mut rng);
        let (ct, r) = elgamal_exp::encrypt_random::<C>(&pk, &x, &mut rng);

        let stmt = EgexpStatement::<C> {
            p: pk,
            a: ct.a,
            b: ct.b,
        };

        // Use wrong plaintext
        let wrong_x = C::random_scalar(&mut rng);
        let bad_witness = EgexpWitness::<C> { x: wrong_x, r };

        let proof = EgexpProof::prove(&stmt, &bad_witness, &mut rng);
        assert!(!proof.verify(&stmt), "proof with wrong x must not verify");
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn egexp_wrong_r_rejects() {
        let mut rng = rand::thread_rng();

        let dk = C::random_scalar(&mut rng);
        let pk = C::generator() * dk;

        let x = C::random_scalar(&mut rng);
        let (ct, r) = elgamal_exp::encrypt_random::<C>(&pk, &x, &mut rng);
        let _ = r; // discard correct r

        let stmt = EgexpStatement::<C> {
            p: pk,
            a: ct.a,
            b: ct.b,
        };

        // Use wrong randomness
        let wrong_r = C::random_scalar(&mut rng);
        let bad_witness = EgexpWitness::<C> { x, r: wrong_r };

        let proof = EgexpProof::prove(&stmt, &bad_witness, &mut rng);
        assert!(!proof.verify(&stmt), "proof with wrong r must not verify");
    }
}
