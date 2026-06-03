// SPDX-License-Identifier: MIT OR Apache-2.0
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec::Vec};

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::TecdsaCurve;

/// Schnorr-style discrete-log proof `DLOG{ w : P = w*G }`.
///
/// Proves knowledge of a scalar `w` such that `P = w * G` using the standard
/// Schnorr sigma protocol made non-interactive via Fiat-Shamir (SHA-256).
pub struct DlogProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Schnorr commitment point `R = r*G`.
    pub commitment: C::ProjectivePoint,
    /// Schnorr response scalar `s = r + c*w`.
    pub response: C::Scalar,
}

impl<C: TecdsaCurve> Clone for DlogProof<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            response: self.response,
        }
    }
}

// Manual Serialize: encode commitment as GroupEncoding bytes, response as PrimeField repr bytes.
impl<C: TecdsaCurve> Serialize for DlogProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let commitment_bytes: Vec<u8> = self.commitment.to_bytes().as_ref().to_vec();
        let repr = self.response.to_repr();
        let response_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&repr).to_vec();
        let mut state = serializer.serialize_struct("DlogProof", 2)?;
        state.serialize_field("commitment", &commitment_bytes)?;
        state.serialize_field("response", &response_bytes)?;
        state.end()
    }
}

impl<'de, C: TecdsaCurve> Deserialize<'de> for DlogProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use core::{fmt, marker::PhantomData};

        use serde::de::{self, MapAccess, SeqAccess, Visitor};

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Commitment,
            Response,
        }

        struct DlogProofVisitor<C2: TecdsaCurve>(PhantomData<C2>)
        where
            FieldBytesSize<C2>: ModulusSize;

        impl<'de2, C2: TecdsaCurve> Visitor<'de2> for DlogProofVisitor<C2>
        where
            FieldBytesSize<C2>: ModulusSize,
            C2::Scalar: PrimeField<Repr = FieldBytes<C2>>,
        {
            type Value = DlogProof<C2>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("struct DlogProof")
            }

            fn visit_seq<V: SeqAccess<'de2>>(self, mut seq: V) -> Result<DlogProof<C2>, V::Error> {
                let commitment_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let response_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let commitment =
                    decode_point::<C2>(&commitment_bytes).map_err(de::Error::custom)?;
                let response = decode_scalar::<C2>(&response_bytes).map_err(de::Error::custom)?;
                Ok(DlogProof {
                    commitment,
                    response,
                })
            }

            fn visit_map<V: MapAccess<'de2>>(self, mut map: V) -> Result<DlogProof<C2>, V::Error> {
                let mut commitment_bytes: Option<Vec<u8>> = None;
                let mut response_bytes: Option<Vec<u8>> = None;
                while let Some(key) = map.next_key::<Field>()? {
                    match key {
                        Field::Commitment => {
                            if commitment_bytes.is_some() {
                                return Err(de::Error::duplicate_field("commitment"));
                            }
                            commitment_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        Field::Response => {
                            if response_bytes.is_some() {
                                return Err(de::Error::duplicate_field("response"));
                            }
                            response_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                    }
                }
                let commitment_bytes =
                    commitment_bytes.ok_or_else(|| de::Error::missing_field("commitment"))?;
                let response_bytes =
                    response_bytes.ok_or_else(|| de::Error::missing_field("response"))?;
                let commitment =
                    decode_point::<C2>(&commitment_bytes).map_err(de::Error::custom)?;
                let response = decode_scalar::<C2>(&response_bytes).map_err(de::Error::custom)?;
                Ok(DlogProof {
                    commitment,
                    response,
                })
            }
        }

        const FIELDS: &[&str] = &["commitment", "response"];
        deserializer.deserialize_struct("DlogProof", FIELDS, DlogProofVisitor::<C>(PhantomData))
    }
}

/// Decode a `ProjectivePoint` from bytes using `GroupEncoding`.
fn decode_point<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::ProjectivePoint, String>
where
    FieldBytesSize<C>: ModulusSize,
{
    let repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
    let repr_len = repr.as_ref().len();
    if bytes.len() != repr_len {
        return Err(format!(
            "invalid commitment length: expected {repr_len}, got {}",
            bytes.len()
        ));
    }
    let mut repr = repr;
    repr.as_mut().copy_from_slice(bytes);
    let ct = C::ProjectivePoint::from_bytes(&repr);
    Option::from(ct).ok_or_else(|| "invalid commitment point".to_string())
}

/// Decode a `Scalar` from its big-endian repr bytes.
fn decode_scalar<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::Scalar, String>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut fb = FieldBytes::<C>::default();
    if bytes.len() != fb.len() {
        return Err(format!(
            "invalid response length: expected {}, got {}",
            fb.len(),
            bytes.len()
        ));
    }
    fb.copy_from_slice(bytes);
    Option::from(<C::Scalar as PrimeField>::from_repr(fb))
        .ok_or_else(|| "invalid scalar".to_string())
}

impl<C: TecdsaCurve> DlogProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Compute the Fiat-Shamir challenge: `c = H(R || P || aux)` reduced to a scalar.
    fn challenge(
        commitment: &C::ProjectivePoint,
        public_point: &C::ProjectivePoint,
        aux: &[u8],
    ) -> C::Scalar {
        let r_bytes = commitment.to_bytes();
        let p_bytes = public_point.to_bytes();
        let hash: [u8; 32] = Sha256::new()
            .chain_update(b"DlogProof")
            .chain_update(r_bytes.as_ref())
            .chain_update(p_bytes.as_ref())
            .chain_update(aux)
            .finalize()
            .into();

        crate::conv::bytes_to_scalar::<C>(&hash)
    }

    /// Create a Schnorr proof of knowledge of `witness` such that
    /// `public_point = witness * G`.
    ///
    /// - `witness`: the secret scalar `w`
    /// - `ephemeral_secret`: a random scalar `r` (the Schnorr nonce)
    /// - `public_point`: the statement `P = w * G`
    /// - `aux`: auxiliary data mixed into the Fiat-Shamir challenge (e.g. combined rid)
    #[must_use]
    pub fn prove(
        witness: &C::Scalar,
        ephemeral_secret: &C::Scalar,
        public_point: &C::ProjectivePoint,
        aux: &[u8],
    ) -> Self {
        let commitment = C::generator() * ephemeral_secret;
        let c = Self::challenge(&commitment, public_point, aux);
        // s = r + c * w
        let response = *ephemeral_secret + c * *witness;
        Self {
            commitment,
            response,
        }
    }

    /// Verify a Schnorr proof against `public_point`.
    ///
    /// Checks that `response * G == commitment + c * public_point` where
    /// `c = H(commitment || public_point || aux)`.
    #[must_use]
    pub fn verify(&self, public_point: &C::ProjectivePoint, aux: &[u8]) -> bool {
        let c = Self::challenge(&self.commitment, public_point, aux);
        let lhs = C::generator() * self.response;
        let rhs = self.commitment + *public_point * c;
        lhs == rhs
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
        fn dlog_honest_verifies() {
            let mut rng = rand::thread_rng();
            let w = Secp256k1::random_scalar(&mut rng);
            let public_point = Secp256k1::generator() * w;
            let ephemeral = Secp256k1::random_scalar(&mut rng);

            let proof = DlogProof::<Secp256k1>::prove(&w, &ephemeral, &public_point, b"test-aux");
            assert!(
                proof.verify(&public_point, b"test-aux"),
                "honest proof must verify"
            );
        }

        #[test]
        fn dlog_proof_rejects_mutated_response() {
            let mut rng = rand::thread_rng();
            let w = Secp256k1::random_scalar(&mut rng);
            let public_point = Secp256k1::generator() * w;
            let ephemeral = Secp256k1::random_scalar(&mut rng);

            let mut proof =
                DlogProof::<Secp256k1>::prove(&w, &ephemeral, &public_point, b"test-aux");

            // Mutate the response scalar by adding 1.
            proof.response += <Secp256k1 as elliptic_curve::CurveArithmetic>::Scalar::ONE;

            assert!(
                !proof.verify(&public_point, b"test-aux"),
                "verification must reject a proof with mutated response"
            );
        }
    }
}
