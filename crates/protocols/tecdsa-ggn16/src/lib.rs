// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;
pub mod utils;

use std::marker::PhantomData;

use elliptic_curve::ops::LinearCombination;
use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

/// Curve-generic GGN16 threshold-optimal ECDSA protocol descriptor.
///
/// Uses a shared Paillier key with threshold decryption (unlike GG18/CGGMP20
/// which use per-party Paillier keys). The signing protocol is split into:
///
/// - **Presign (offline):** Rounds 1-5 (5 message rounds). Message-independent.
///   Produces a [`presign::Ggn16Presignature`].
/// - **OnlineSign:** Round 6 (1 message round). Threshold decrypts the
///   encrypted signature $\sigma = E(s)$.
///
/// Reference: Gennaro, Goldfeder, Narayanan. ACNS 2016.
pub struct Ggn16Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Ggn16Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Curve = C;

    type KeyShare = key_share::Ggn16KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Ggn16Presignature<C>;
    type Signature = tecdsa_protocol::Signature<C>;

    type KeyGen = keygen::Ggn16KeygenMachine<C>;
    type AuxGen = NoOpMachine;
    type Presign = presign::Ggn16PresignMachine<C>;
    type Sign = sign::Ggn16OnlineSignMachine<C>;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

/// Backward-compatible alias: GGN16 over secp256k1.
pub type Ggn16 = Ggn16Protocol<k256::Secp256k1>;
