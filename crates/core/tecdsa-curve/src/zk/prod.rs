use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use sha2::{Digest, Sha256};

use super::ddh::{DdhProof, DdhStatement, DdhWitness};
use crate::TecdsaCurve;

pub struct ProdStatement<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub p: C::ProjectivePoint,
    pub a: C::ProjectivePoint,
    pub b: C::ProjectivePoint,
    pub c: C::ProjectivePoint,
    pub d: C::ProjectivePoint,
    pub e_pt: C::ProjectivePoint,
    pub f: C::ProjectivePoint,
}

pub struct ProdWitness<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub t: C::Scalar,
    pub r: C::Scalar,
    pub y: C::Scalar,
}

pub struct ProdProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub x: C::ProjectivePoint,
    pub y_commit: C::ProjectivePoint,
    pub w: C::ProjectivePoint,
    pub z1: C::Scalar,
    pub z2: C::Scalar,
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

        crate::conv::bytes_to_scalar::<C>(&hash)
    }

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

    #[must_use]
    pub fn prove(
        stmt: &ProdStatement<C>,
        witness: &ProdWitness<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let g = C::generator();

        let sigma = C::random_scalar(rng);
        let rho = C::random_scalar(rng);

        let x = stmt.a * sigma + g * rho;
        let y_commit = stmt.b * sigma + stmt.p * rho;
        let w = g * sigma;

        let e = Self::challenge(stmt, &x, &y_commit, &w);

        let z1 = sigma + e * witness.y;
        let z2 = rho + e * witness.r;

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

    #[must_use]
    pub fn verify(&self, stmt: &ProdStatement<C>) -> bool {
        let g = C::generator();
        let e = Self::challenge(stmt, &self.x, &self.y_commit, &self.w);

        let lhs1 = stmt.a * self.z1 + g * self.z2;
        let rhs1 = self.x + stmt.e_pt * e;
        if lhs1 != rhs1 {
            return false;
        }

        let lhs2 = stmt.b * self.z1 + stmt.p * self.z2;
        let rhs2 = self.y_commit + stmt.f * e;
        if lhs2 != rhs2 {
            return false;
        }

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

        fn setup() -> (ProdStatement<C>, ProdWitness<C>) {
            let mut rng = rand::thread_rng();
            let g = C::generator();

            let dk = C::random_scalar(&mut rng);
            let pk = g * dk;

            let alpha = C::random_scalar(&mut rng);
            let a = g * alpha;
            let b = pk * alpha;

            let y = C::random_scalar(&mut rng);
            let t = C::random_scalar(&mut rng);
            let r = C::random_scalar(&mut rng);

            let c = g * t;
            let d = pk * t + g * y;

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
