#![forbid(unsafe_code)]

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;
pub mod utils;

use std::marker::PhantomData;

use elliptic_curve::{
    ops::{LinearCombination, Reduce},
    sec1::ModulusSize,
    FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

pub struct Dkls23Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Dkls23Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>
        + Reduce<FieldBytes<C>>
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Curve = C;

    type KeyShare = key_share::Dkls23KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Dkls23Presignature<C>;
    type Signature = tecdsa_protocol::Signature<C>;

    type KeyGen = keygen::Dkls23KeygenMachine<C>;
    type AuxGen = NoOpMachine;
    type Presign = presign::Dkls23PresignMachine<C, rand_core::OsRng>;
    type Sign = sign::Dkls23OnlineSignMachine<C>;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

pub type Dkls23 = Dkls23Protocol<k256::Secp256k1>;
