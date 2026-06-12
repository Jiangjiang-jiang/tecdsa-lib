use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use sha2::{Digest, Sha256};

use crate::TecdsaCurve;

pub struct ReStatement<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub g: C::ProjectivePoint,
    pub p: C::ProjectivePoint,
    pub a: C::ProjectivePoint,
    pub b: C::ProjectivePoint,
    pub a_prime: C::ProjectivePoint,
    pub b_prime: C::ProjectivePoint,
}

pub struct ReWitness<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub r: C::Scalar,
    pub s: C::Scalar,
}

pub struct ReProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub x: C::ProjectivePoint,
    pub y: C::ProjectivePoint,
    pub z1: C::Scalar,
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

        crate::conv::bytes_to_scalar::<C>(&hash)
    }

    #[must_use]
    pub fn prove(
        stmt: &ReStatement<C>,
        witness: &ReWitness<C>,
        sigma: &C::Scalar,
        tau: &C::Scalar,
    ) -> Self {
        let x = stmt.g * sigma + stmt.a * tau;
        let y = stmt.p * sigma + stmt.b * tau;

        let e = Self::challenge(stmt, &x, &y);

        let z1 = *sigma + e * witness.r;
        let z2 = *tau + e * witness.s;

        Self { x, y, z1, z2 }
    }

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

    fn setup() -> (ReStatement<C>, ReWitness<C>) {
        let r = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let s = <C as TecdsaCurve>::random_scalar(&mut OsRng);

        let g = C::generator();
        let p = C::nums_pedersen_h();

        let a_sk = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let b_sk = <C as TecdsaCurve>::random_scalar(&mut OsRng);
        let a = g * a_sk;
        let b = p * b_sk;

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
