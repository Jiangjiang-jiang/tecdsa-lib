use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use sha2::{Digest, Sha256};

use crate::TecdsaCurve;

pub struct DdhStatement<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub g: C::ProjectivePoint,
    pub a: C::ProjectivePoint,
    pub b: C::ProjectivePoint,
    pub c: C::ProjectivePoint,
}

pub struct DdhWitness<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub w: C::Scalar,
}

pub struct DdhProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub g_r: C::ProjectivePoint,
    pub a_r: C::ProjectivePoint,
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

        crate::conv::bytes_to_scalar::<C>(&hash)
    }

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
        let z = r - e * wit.w;
        Self { g_r, a_r, z }
    }

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
            let wit_bad = DdhWitness::<Secp256k1> { w: w_bad };
            let proof = DdhProof::prove(&stmt, &wit_bad, &mut rng);
            assert!(
                !proof.verify(&stmt),
                "DDH proof with wrong witness must not verify"
            );
        }
    }
}
