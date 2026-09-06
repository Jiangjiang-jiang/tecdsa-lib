// SPDX-License-Identifier: MIT OR Apache-2.0
use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use sha2::{Digest, Sha256};

use crate::TecdsaCurve;

/// Statement for the rerandomization ZK proof $R_{RE}$.
///
/// Asserts the existence of scalars $(r, s)$ such that
/// $A' = rG + sA$ and $B' = r\mathcal{P} + sB$.
pub struct ReStatement<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Generator $G$.
    pub g: C::ProjectivePoint,
    /// Auxiliary base point $\mathcal{P}$.
    pub p: C::ProjectivePoint,
    /// Original point $A$.
    pub a: C::ProjectivePoint,
    /// Original point $B$.
    pub b: C::ProjectivePoint,
    /// Rerandomized point $A' = rG + sA$.
    pub a_prime: C::ProjectivePoint,
    /// Rerandomized point $B' = r\mathcal{P} + sB$.
    pub b_prime: C::ProjectivePoint,
}

/// Witness for the rerandomization ZK proof.
pub struct ReWitness<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Rerandomization scalar $r$.
    pub r: C::Scalar,
    /// Rerandomization scalar $s$.
    pub s: C::Scalar,
}

/// Non-interactive Schnorr-style proof for the rerandomization relation $R_{RE}$.
///
/// Proves knowledge of $(r, s)$ such that $A' = rG + sA$ and $B' = r\mathcal{P} + sB$
/// using a sigma protocol made non-interactive via Fiat-Shamir (SHA-256).
pub struct ReProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Commitment $X = \sigma G + \tau A$.
    pub x: C::ProjectivePoint,
    /// Commitment $Y = \sigma \mathcal{P} + \tau B$.
    pub y: C::ProjectivePoint,
    /// Response `z1 = sigma + e * r`.
    pub z1: C::Scalar,
    /// Response `z2 = tau + e * s`.
    pub z2: C::Scalar,
}

impl<C: TecdsaCurve> Clone for ReProof<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            x: self.x,
            y: self.y,
            z1: self.z1,
            z2: self.z2,
        }
    }
}

impl<C: TecdsaCurve> ReProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Compute the Fiat-Shamir challenge:
    /// `e = H(G || P || A || B || A' || B' || X || Y)` reduced to a scalar.
    fn challenge(
        stmt: &ReStatement<C>,
        x: &C::ProjectivePoint,
        y: &C::ProjectivePoint,
    ) -> C::Scalar {
        use elliptic_curve::group::GroupEncoding;

        let hash: [u8; 32] = Sha256::new()
            .chain_update(b"ReProof")
            .chain_update(stmt.g.to_bytes().as_ref())
            .chain_update(stmt.p.to_bytes().as_ref())
            .chain_update(stmt.a.to_bytes().as_ref())
            .chain_update(stmt.b.to_bytes().as_ref())
            .chain_update(stmt.a_prime.to_bytes().as_ref())
            .chain_update(stmt.b_prime.to_bytes().as_ref())
            .chain_update(x.to_bytes().as_ref())
            .chain_update(y.to_bytes().as_ref())
            .finalize()
            .into();

        C::scalar_from_bytes(&hash)
    }

    /// Create a rerandomization proof.
    ///
    /// - `stmt`: the public statement $(G, \mathcal{P}, A, B, A', B')$
    /// - `witness`: the secret scalars $(r, s)$
    /// - `sigma`: random ephemeral scalar $\sigma$
    /// - `tau`: random ephemeral scalar $\tau$
    #[must_use]
    pub fn prove(
        stmt: &ReStatement<C>,
        witness: &ReWitness<C>,
        sigma: &C::Scalar,
        tau: &C::Scalar,
    ) -> Self {
        // Commit: X = sigma*G + tau*A, Y = sigma*P + tau*B
        let x = stmt.g * sigma + stmt.a * tau;
        let y = stmt.p * sigma + stmt.b * tau;

        // Challenge
        let e = Self::challenge(stmt, &x, &y);

        // Response: z1 = sigma + e*r, z2 = tau + e*s
        let z1 = *sigma + e * witness.r;
        let z2 = *tau + e * witness.s;

        Self { x, y, z1, z2 }
    }

    /// Verify a rerandomization proof against the given statement.
    ///
    /// Checks:
    /// - `z1*G + z2*A == X + e*A'`
    /// - `z1*P + z2*B == Y + e*B'`
    #[must_use]
    pub fn verify(&self, stmt: &ReStatement<C>) -> bool {
        let e = Self::challenge(stmt, &self.x, &self.y);

        let lhs1 = stmt.g * self.z1 + stmt.a * self.z2;
        let rhs1 = self.x + stmt.a_prime * e;

        let lhs2 = stmt.p * self.z1 + stmt.b * self.z2;
        let rhs2 = self.y + stmt.b_prime * e;

        lhs1 == rhs1 && lhs2 == rhs2
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    type C = k256::Secp256k1;

    /// Helper: build a valid statement + witness for testing.
    fn setup() -> (ReStatement<C>, ReWitness<C>) {
        let r = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let s = <C as TecdsaCurve>::random_scalar(&mut OsRng);

        let g = C::generator();
        // Use a NUMS second base point (hash-derived, DL unknown w.r.t. G).
        let p = C::nums_pedersen_h();

        // Random points A, B on the curve.
        let a_sk = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let b_sk = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let a = g * a_sk;
        let b = p * b_sk;

        // Rerandomized points.
        let a_prime = g * r + a * s;
        let b_prime = p * r + b * s;

        let stmt = ReStatement {
            g,
            p,
            a,
            b,
            a_prime,
            b_prime,
        };
        let witness = ReWitness { r, s };
        (stmt, witness)
    }

    #[test]
    fn re_honest_verifies() {
        let (stmt, witness) = setup();
        let sigma = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let tau = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let proof = ReProof::<C>::prove(&stmt, &witness, &sigma, &tau);
        assert!(proof.verify(&stmt), "honest proof must verify");
    }

    #[test]
    fn re_wrong_witness_rejects() {
        let (stmt, _witness) = setup();
        // Use a completely wrong witness.
        let bad_witness = ReWitness {
            r: <C as TecdsaCurve>::random_scalar(&mut OsRng),
            s: <C as TecdsaCurve>::random_scalar(&mut OsRng),
        };
        let sigma = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let tau = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let proof = ReProof::<C>::prove(&stmt, &bad_witness, &sigma, &tau);
        assert!(!proof.verify(&stmt), "proof with wrong witness must reject");
    }
}
