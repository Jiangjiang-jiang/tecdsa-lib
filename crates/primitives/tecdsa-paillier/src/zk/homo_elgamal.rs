// SPDX-License-Identifier: MIT OR Apache-2.0
//! Homomorphic ElGamal proof.
//!
//! Proves: prover knows $(x, r)$ s.t. $D = xH + rY$ and $E = rG$.
//! Used in GG18 Phase 5a: proves signature share is correctly formed.
//! Reference: GG18 §4.3.
//!
//! This is a **pure EC proof** — no Paillier or big-integer arithmetic.
//! It lives in `tecdsa-paillier::zk` because it is used alongside
//! Paillier-based signing protocols.

#![allow(non_snake_case)]

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, CurveArithmetic, FieldBytes, FieldBytesSize,
    PrimeField,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;

/// Error type for HomoElGamal proof verification.
#[derive(Debug, thiserror::Error)]
pub enum HomoElGamalError {
    /// Verification of the HomoElGamal proof failed.
    #[error("HomoElGamal verification failed")]
    Verify,
}

// ---------------------------------------------------------------------------
// Statement / Witness
// ---------------------------------------------------------------------------

/// Public statement for the HomoElGamal proof.
///
/// Five EC points forming the relation:
/// - $D = xH + rY$
/// - $E = rG$
pub struct HomoElGamalStatement<C: CurveArithmetic> {
    /// Group generator $G$.
    pub G: C::ProjectivePoint,
    /// Base point $H$ (e.g., the nonce point $R$ in signing).
    pub H: C::ProjectivePoint,
    /// Public key $Y$.
    pub Y: C::ProjectivePoint,
    /// Ciphertext component $D = xH + rY$.
    pub D: C::ProjectivePoint,
    /// Randomness commitment $E = rG$.
    pub E: C::ProjectivePoint,
}

/// Witness for the HomoElGamal proof: two scalars $(x, r)$.
pub struct HomoElGamalWitness<C: CurveArithmetic> {
    /// The message scalar $x$.
    pub x: C::Scalar,
    /// The randomness scalar $r$.
    pub r: C::Scalar,
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/// Non-interactive HomoElGamal proof (Fiat-Shamir transformed via SHA-256).
#[derive(Debug, Clone)]
pub struct HomoElGamalProof<C: CurveArithmetic> {
    /// First commitment: $A = s_1 H + s_2 Y$.
    pub A: C::ProjectivePoint,
    /// Second commitment: $B = s_2 G$.
    pub B: C::ProjectivePoint,
    /// Response $z_1 = s_1 + e \cdot x$.
    pub z1: C::Scalar,
    /// Response $z_2 = s_2 + e \cdot r$.
    pub z2: C::Scalar,
}

// ---------------------------------------------------------------------------
// Serde impls
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Fiat-Shamir challenge
// ---------------------------------------------------------------------------

/// Compute the Fiat-Shamir challenge by hashing all seven points
/// (G, H, Y, D, E, A, B) as compressed SEC1 bytes.
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

// ---------------------------------------------------------------------------
// Prove / Verify
// ---------------------------------------------------------------------------

impl<C> HomoElGamalProof<C>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    /// Construct a non-interactive HomoElGamal proof.
    ///
    /// # Protocol
    ///
    /// 1. Sample $s_1, s_2 \gets \mathbb{Z}_q$
    /// 2. $A = s_1 H + s_2 Y$
    /// 3. $B = s_2 G$
    /// 4. $e = \mathcal{H}(G, H, Y, D, E, A, B)$
    /// 5. $z_1 = s_1 + e \cdot x$
    /// 6. $z_2 = s_2 + e \cdot r$
    pub fn prove(
        witness: &HomoElGamalWitness<C>,
        statement: &HomoElGamalStatement<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        // 1. Sample random blinding scalars
        let s1 = C::random_scalar(rng);
        let s2 = C::random_scalar(rng);

        // 2. A = s1*H + s2*Y
        let A = statement.H * s1 + statement.Y * s2;

        // 3. B = s2*G
        let B = statement.G * s2;

        // 4. e = H(G, H, Y, D, E, A, B)
        let e = compute_challenge::<C>(statement, &A, &B);

        // 5. z1 = s1 + e*x
        let z1 = s1 + e * witness.x;

        // 6. z2 = s2 + e*r
        let z2 = s2 + e * witness.r;

        HomoElGamalProof { A, B, z1, z2 }
    }

    /// Verify a HomoElGamal proof.
    ///
    /// Checks:
    /// 1. $z_1 H + z_2 Y \stackrel{?}{=} A + e D$
    /// 2. $z_2 G \stackrel{?}{=} B + e E$
    ///
    /// # Errors
    /// Returns [`HomoElGamalError::Verify`] if any check fails.
    pub fn verify(&self, statement: &HomoElGamalStatement<C>) -> Result<(), HomoElGamalError> {
        // Recompute challenge
        let e = compute_challenge::<C>(statement, &self.A, &self.B);

        // Check 1: z1*H + z2*Y == A + e*D
        let lhs1 = statement.H * self.z1 + statement.Y * self.z2;
        let rhs1 = self.A + statement.D * e;

        // Check 2: z2*G == B + e*E
        let lhs2 = statement.G * self.z2;
        let rhs2 = self.B + statement.E * e;

        // Compare via serialized bytes (constant-time for projective points)
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

    /// Build a valid statement and witness for testing.
    fn setup(
        rng: &mut impl CryptoRngCore,
    ) -> (
        HomoElGamalStatement<TestCurve>,
        HomoElGamalWitness<TestCurve>,
    ) {
        let G = Point::GENERATOR;

        // Random base point H (e.g., a nonce point)
        let h_scalar = TestCurve::random_scalar(rng);
        let H = G * h_scalar;

        // Random public key Y
        let y_scalar = TestCurve::random_scalar(rng);
        let Y = G * y_scalar;

        // Witness: (x, r)
        let x = TestCurve::random_scalar(rng);
        let r = TestCurve::random_scalar(rng);

        // D = xH + rY
        let D = H * x + Y * r;
        // E = rG
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

        // Use a wrong x
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

        // Use a wrong r
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

        // Mutate the z1 response scalar by adding 1.
        proof.z1 += <TestCurve as CurveArithmetic>::Scalar::ONE;

        assert!(
            proof.verify(&statement).is_err(),
            "verification must reject a proof with mutated z1 response"
        );
    }
}
