// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

pub mod key_share;
pub mod keygen;
pub mod presign;
pub mod sign;

pub mod aux_info;
pub mod bridge;
pub mod full_sign;
pub mod metadata;
pub mod security_level;
pub mod trusted_dealer;

#[cfg(feature = "identifiable-abort")]
pub mod ia;

// ---------------------------------------------------------------------------
// Protocol trait implementation
// ---------------------------------------------------------------------------

use tecdsa_protocol::Protocol;

/// Concrete protocol descriptor for the CGGMP20 (revised, 2024) threshold
/// ECDSA scheme instantiated over secp256k1.
///
/// The `Protocol` trait requires a single concrete `Curve`, so `Cggmp20` is
/// pinned to `k256::Secp256k1` here even though the underlying presign and
/// sign state machines are generic over any `C: TecdsaCurve`.
pub struct Cggmp20;

impl Protocol for Cggmp20 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Cggmp20CoreKeyShare<k256::Secp256k1>;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = key_share::AuxInfo;
    type Presignature = (
        sign::types::Presignature<k256::Secp256k1>,
        sign::types::PresignaturePublicData<k256::Secp256k1>,
    );
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Cggmp20KeygenMachine<k256::Secp256k1>;
    type AuxGen = aux_info::AuxInfoMachine<security_level::SecurityLevel128>;
    type Presign = presign::Cggmp20PresignMachine<k256::Secp256k1>;
    type Sign = full_sign::FullSignMachine<k256::Secp256k1>;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: tecdsa_protocol::ProtocolMetadata = crate::metadata::METADATA;
}

// ---------------------------------------------------------------------------
// KeyImport implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "key-import")]
impl tecdsa_protocol::KeyImport for Cggmp20 {
    /// Import a raw 32-byte secp256k1 secret key into CGGMP20 core key shares.
    ///
    /// Returns `Cggmp20CoreKeyShare` values (without `AuxInfo`). Callers must
    /// run the auxiliary-info protocol separately to obtain Paillier keys and
    /// ring-Pedersen parameters before signing.
    fn import_key(
        secret_key: &[u8],
        threshold: u16,
        total: u16,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Vec<Self::KeyShare>, tecdsa_core::TecdsaError> {
        use elliptic_curve::{FieldBytes, PrimeField};

        // Validate byte length
        if secret_key.len() != 32 {
            return Err(tecdsa_core::TecdsaError::InvalidKey(format!(
                "expected 32-byte secp256k1 secret key, got {} bytes",
                secret_key.len()
            )));
        }

        // Deserialize big-endian bytes into a scalar
        let mut fb = FieldBytes::<k256::Secp256k1>::default();
        fb.copy_from_slice(secret_key);
        let scalar =
            Option::from(<k256::Scalar as PrimeField>::from_repr(fb)).ok_or_else(|| {
                tecdsa_core::TecdsaError::InvalidKey(
                    "secret key bytes are not a valid secp256k1 scalar".into(),
                )
            })?;

        // Validate threshold parameters
        if threshold == 0 || threshold > total {
            return Err(tecdsa_core::TecdsaError::InvalidKey(format!(
                "invalid threshold parameters: threshold={threshold}, total={total}"
            )));
        }

        // Delegate to the trusted dealer
        Ok(trusted_dealer::deal::<k256::Secp256k1>(
            &scalar, threshold, total, rng,
        ))
    }
}
