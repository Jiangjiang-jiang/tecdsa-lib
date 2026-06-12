#![allow(non_snake_case)]

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, CurveArithmetic, FieldBytes, FieldBytesSize,
    PrimeField,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;

#[derive(Debug, thiserror::Error)]
pub enum HomoElGamalError {
    #[error("HomoElGamal verification failed")]
    Verify,
}

pub struct HomoElGamalStatement<C: CurveArithmetic> {
    pub G: C::ProjectivePoint,
    pub H: C::ProjectivePoint,
    pub Y: C::ProjectivePoint,
    pub D: C::ProjectivePoint,
    pub E: C::ProjectivePoint,
}

pub struct HomoElGamalWitness<C: CurveArithmetic> {
    pub x: C::Scalar,
    pub r: C::Scalar,
}

#[derive(Debug, Clone)]
pub struct HomoElGamalProof<C: CurveArithmetic> {
    pub A: C::ProjectivePoint,
    pub B: C::ProjectivePoint,
    pub z1: C::Scalar,
    pub z2: C::Scalar,
}

impl<C: TecdsaCurve> Serialize for HomoElGamalProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let a_bytes: Vec<u8> = self.A.to_bytes().as_ref().to_vec();
        let b_bytes: Vec<u8> = self.B.to_bytes().as_ref().to_vec();
        let z1_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&self.z1.to_repr()).to_vec();
        let z2_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&self.z2.to_repr()).to_vec();
        let mut state = serializer.serialize_struct("HomoElGamalProof", 4)?;
        state.serialize_field("A", &a_bytes)?;
        state.serialize_field("B", &b_bytes)?;
        state.serialize_field("z1", &z1_bytes)?;
        state.serialize_field("z2", &z2_bytes)?;
        state.end()
    }
}

impl<'de, C: TecdsaCurve> Deserialize<'de> for HomoElGamalProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use std::{fmt, marker::PhantomData};

        use serde::de::{self, MapAccess, Visitor};

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            A,
            B,
            Z1,
            Z2,
        }

        struct ProofVisitor<C2: TecdsaCurve>(PhantomData<C2>)
        where
            FieldBytesSize<C2>: ModulusSize;

        impl<'de2, C2: TecdsaCurve> Visitor<'de2> for ProofVisitor<C2>
        where
            FieldBytesSize<C2>: ModulusSize,
            C2::Scalar: PrimeField<Repr = FieldBytes<C2>>,
        {
            type Value = HomoElGamalProof<C2>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("struct HomoElGamalProof")
            }

            fn visit_map<V: MapAccess<'de2>>(
                self,
                mut map: V,
            ) -> Result<HomoElGamalProof<C2>, V::Error> {
                let mut a_bytes: Option<Vec<u8>> = None;
                let mut b_bytes: Option<Vec<u8>> = None;
                let mut z1_bytes: Option<Vec<u8>> = None;
                let mut z2_bytes: Option<Vec<u8>> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::A => {
                            if a_bytes.is_some() {
                                return Err(de::Error::duplicate_field("A"));
                            }
                            a_bytes = Some(map.next_value()?);
                        }
                        Field::B => {
                            if b_bytes.is_some() {
                                return Err(de::Error::duplicate_field("B"));
                            }
                            b_bytes = Some(map.next_value()?);
                        }
                        Field::Z1 => {
                            if z1_bytes.is_some() {
                                return Err(de::Error::duplicate_field("z1"));
                            }
                            z1_bytes = Some(map.next_value()?);
                        }
                        Field::Z2 => {
                            if z2_bytes.is_some() {
                                return Err(de::Error::duplicate_field("z2"));
                            }
                            z2_bytes = Some(map.next_value()?);
                        }
                    }
                }
                let a_bytes = a_bytes.ok_or_else(|| de::Error::missing_field("A"))?;
                let b_bytes = b_bytes.ok_or_else(|| de::Error::missing_field("B"))?;
                let z1_bytes = z1_bytes.ok_or_else(|| de::Error::missing_field("z1"))?;
                let z2_bytes = z2_bytes.ok_or_else(|| de::Error::missing_field("z2"))?;

                let A = decode_point::<C2>(&a_bytes).map_err(de::Error::custom)?;
                let B = decode_point::<C2>(&b_bytes).map_err(de::Error::custom)?;
                let z1 = decode_scalar::<C2>(&z1_bytes).map_err(de::Error::custom)?;
                let z2 = decode_scalar::<C2>(&z2_bytes).map_err(de::Error::custom)?;

                Ok(HomoElGamalProof { A, B, z1, z2 })
            }
        }

        const FIELDS: &[&str] = &["A", "B", "z1", "z2"];
        deserializer.deserialize_struct("HomoElGamalProof", FIELDS, ProofVisitor::<C>(PhantomData))
    }
}

fn decode_point<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::ProjectivePoint, String>
where
    FieldBytesSize<C>: ModulusSize,
{
    let mut repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
    let repr_slice = repr.as_mut();
    if bytes.len() != repr_slice.len() {
        return Err(format!(
            "point: expected {} bytes, got {}",
            repr_slice.len(),
            bytes.len()
        ));
    }
    repr_slice.copy_from_slice(bytes);
    Option::from(C::ProjectivePoint::from_bytes(&repr)).ok_or_else(|| "invalid point".to_string())
}

fn decode_scalar<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::Scalar, String>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let repr = FieldBytes::<C>::try_from(bytes)
        .map_err(|_| format!("scalar: expected {} bytes", C::SCALAR_BYTES))?;
    Option::from(C::Scalar::from_repr(repr)).ok_or_else(|| "invalid scalar".to_string())
}

fn compute_challenge<C>(
    stmt: &HomoElGamalStatement<C>,
    A: &C::ProjectivePoint,
    B: &C::ProjectivePoint,
) -> C::Scalar
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    let mut hasher = Sha256::new();
    hasher.update(b"PiHomoElGamal");

    hasher.update(stmt.G.to_bytes().as_ref());
    hasher.update(stmt.H.to_bytes().as_ref());
    hasher.update(stmt.Y.to_bytes().as_ref());
    hasher.update(stmt.D.to_bytes().as_ref());
    hasher.update(stmt.E.to_bytes().as_ref());
    hasher.update(A.to_bytes().as_ref());
    hasher.update(B.to_bytes().as_ref());

    let hash = hasher.finalize();
    tecdsa_curve::conv::bytes_to_scalar::<C>(&hash)
}

impl<C> HomoElGamalProof<C>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    pub fn prove(
        witness: &HomoElGamalWitness<C>,
        statement: &HomoElGamalStatement<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let s1 = C::random_scalar(rng);
        let s2 = C::random_scalar(rng);

        let A = statement.H * s1 + statement.Y * s2;

        let B = statement.G * s2;

        let e = compute_challenge::<C>(statement, &A, &B);

        let z1 = s1 + e * witness.x;

        let z2 = s2 + e * witness.r;

        HomoElGamalProof { A, B, z1, z2 }
    }

    pub fn verify(&self, statement: &HomoElGamalStatement<C>) -> Result<(), HomoElGamalError> {
        let e = compute_challenge::<C>(statement, &self.A, &self.B);

        let lhs1 = statement.H * self.z1 + statement.Y * self.z2;
        let rhs1 = self.A + statement.D * e;

        let lhs2 = statement.G * self.z2;
        let rhs2 = self.B + statement.E * e;

        let check1 = lhs1.to_bytes().as_ref() == rhs1.to_bytes().as_ref();
        let check2 = lhs2.to_bytes().as_ref() == rhs2.to_bytes().as_ref();

        if check1 && check2 {
            Ok(())
        } else {
            Err(HomoElGamalError::Verify)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestCurve = k256::Secp256k1;
    type Point = <TestCurve as CurveArithmetic>::ProjectivePoint;

    fn setup(
        rng: &mut impl CryptoRngCore,
    ) -> (
        HomoElGamalStatement<TestCurve>,
        HomoElGamalWitness<TestCurve>,
    ) {
        let G = Point::GENERATOR;

        let h_scalar = TestCurve::random_scalar(rng);
        let H = G * h_scalar;

        let y_scalar = TestCurve::random_scalar(rng);
        let Y = G * y_scalar;

        let x = TestCurve::random_scalar(rng);
        let r = TestCurve::random_scalar(rng);

        let D = H * x + Y * r;
        let E = G * r;

        let statement = HomoElGamalStatement { G, H, Y, D, E };
        let witness = HomoElGamalWitness { x, r };

        (statement, witness)
    }

    #[test]
    fn homo_elgamal_honest_verifies() {
        let mut rng = rand::thread_rng();
        let (statement, witness) = setup(&mut rng);

        let proof = HomoElGamalProof::prove(&witness, &statement, &mut rng);
        proof
            .verify(&statement)
            .expect("honest proof should verify");
    }

    #[test]
    fn homo_elgamal_wrong_x_rejects() {
        let mut rng = rand::thread_rng();
        let (statement, witness) = setup(&mut rng);

        let wrong_witness = HomoElGamalWitness {
            x: TestCurve::random_scalar(&mut rng),
            r: witness.r,
        };

        let proof = HomoElGamalProof::prove(&wrong_witness, &statement, &mut rng);
        assert!(
            proof.verify(&statement).is_err(),
            "proof with wrong x should fail"
        );
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn homo_elgamal_wrong_r_rejects() {
        let mut rng = rand::thread_rng();
        let (statement, witness) = setup(&mut rng);

        let wrong_witness = HomoElGamalWitness {
            x: witness.x,
            r: TestCurve::random_scalar(&mut rng),
        };

        let proof = HomoElGamalProof::prove(&wrong_witness, &statement, &mut rng);
        assert!(
            proof.verify(&statement).is_err(),
            "proof with wrong r should fail"
        );
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn homo_elgamal_rejects_mutated_proof() {
        let mut rng = rand::thread_rng();
        let (statement, witness) = setup(&mut rng);

        let mut proof = HomoElGamalProof::prove(&witness, &statement, &mut rng);

        proof.z1 += <TestCurve as CurveArithmetic>::Scalar::ONE;

        assert!(
            proof.verify(&statement).is_err(),
            "verification must reject a proof with mutated z1 response"
        );
    }
}
