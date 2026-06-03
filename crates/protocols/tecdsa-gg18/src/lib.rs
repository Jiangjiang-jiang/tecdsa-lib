// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;

// ---------------------------------------------------------------------------
// Protocol trait implementation
// ---------------------------------------------------------------------------

use std::marker::PhantomData;

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

/// Curve-generic GG18 threshold ECDSA protocol descriptor.
///
/// GG18 has no separate AuxGen phase -- auxiliary data (Paillier keys,
/// Ring-Pedersen parameters) is generated inline during key generation.
/// The signing protocol is split into two phases:
///
/// - **Presign (offline):** Phases 1-4, produces a [`presign::Gg18Presignature`].
///   3 message rounds. Message-independent.
/// - **OnlineSign:** Phase 5, takes a presignature + message hash and produces
///   the final ECDSA signature. 5 message rounds.
pub struct Gg18Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Gg18Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar:
        PrimeField<Repr = FieldBytes<C>> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Curve = C;

    type KeyShare = key_share::Gg18KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Gg18Presignature<C>;
    type Signature = tecdsa_protocol::Signature<C>;

    type KeyGen = keygen::Gg18KeygenMachine<C>;
    type AuxGen = NoOpMachine;
    type Presign = presign::Gg18PresignMachine<C>;
    type Sign = sign::Gg18OnlineSignMachine<C>;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

/// Backward-compatible alias: GG18 over secp256k1.
pub type Gg18 = Gg18Protocol<k256::Secp256k1>;
