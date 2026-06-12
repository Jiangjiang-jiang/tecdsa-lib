#![forbid(unsafe_code)]

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;

use std::marker::PhantomData;

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

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

pub type Gg18 = Gg18Protocol<k256::Secp256k1>;
