// SPDX-License-Identifier: MIT OR Apache-2.0
use elliptic_curve::{
    ops::{LinearCombination, Reduce},
    sec1::ModulusSize,
    FieldBytes, FieldBytesSize, PrimeField,
};
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{DataToSign, Signature};

/// Hash a message with SHA-256 and reduce to a scalar for ECDSA signing (secp256k1).
#[must_use]
pub fn hash_to_data_to_sign(message: &[u8]) -> DataToSign<k256::Secp256k1> {
    let hash_bytes: [u8; 32] = Sha256::digest(message).into();
    let fb = k256::FieldBytes::from(hash_bytes);
    let scalar = <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&fb);
    DataToSign::from_digest(scalar)
}

/// Manually verify an ECDSA signature using the textbook equation.
///
/// Panics on failure — intended for test assertions only.
pub fn assert_ecdsa_valid<C>(
    sig: &Signature<C>,
    message: &DataToSign<C>,
    public_key: &C::ProjectivePoint,
) where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    tecdsa_protocol::verify_ecdsa::<C>(sig, public_key, message)
        .expect("ECDSA signature verification must succeed");
}
