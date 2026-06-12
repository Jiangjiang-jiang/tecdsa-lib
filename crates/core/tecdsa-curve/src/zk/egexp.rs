use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use sha2::{Digest, Sha256};

use crate::TecdsaCurve;

pub struct EgexpStatement<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub p: C::ProjectivePoint,
    pub a: C::ProjectivePoint,
    pub b: C::ProjectivePoint,
}

pub struct EgexpWitness<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub x: C::Scalar,
    pub r: C::Scalar,
}

pub struct EgexpProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub commit_x: C::ProjectivePoint,
    pub commit_y: C::ProjectivePoint,
    pub z1: C::Scalar,
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

        crate::conv::bytes_to_scalar::<C>(&hash)
    }

    #[must_use]
    pub fn prove(
        stmt: &EgexpStatement<C>,
        witness: &EgexpWitness<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let g = C::generator();

        let sigma = C::random_scalar(rng);
        let rho = C::random_scalar(rng);

        let commit_x = g * sigma;
        let commit_y = stmt.p * sigma + g * rho;

        let e = Self::challenge(stmt, &commit_x, &commit_y);

        let z1 = sigma + e * witness.r;
        let z2 = rho + e * witness.x;

        Self {
            commit_x,
            commit_y,
            z1,
            z2,
        }
    }

    #[must_use]
    pub fn verify(&self, stmt: &EgexpStatement<C>) -> bool {
        let g = C::generator();
        let e = Self::challenge(stmt, &self.commit_x, &self.commit_y);

        let lhs1 = g * self.z1;
        let rhs1 = self.commit_x + stmt.a * e;
        if lhs1 != rhs1 {
            return false;
        }

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

        let dk = C::random_scalar(&mut rng);
        let pk = C::generator() * dk;

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
        let _ = r;

        let stmt = EgexpStatement::<C> {
            p: pk,
            a: ct.a,
            b: ct.b,
        };

        let wrong_r = C::random_scalar(&mut rng);
        let bad_witness = EgexpWitness::<C> { x, r: wrong_r };

        let proof = EgexpProof::prove(&stmt, &bad_witness, &mut rng);
        assert!(!proof.verify(&stmt), "proof with wrong r must not verify");
    }
}
