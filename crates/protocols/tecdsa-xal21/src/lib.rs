#![forbid(unsafe_code)]
#![allow(non_snake_case)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod offline_sign;
pub mod online_sign;
#[deprecated(note = "use tecdsa_paillier::zk::correct_key_ni directly")]
pub mod zk_correct_key {
    pub use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
}

use std::marker::PhantomData;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{Protocol, ProtocolMetadata};

pub struct Xal21Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Xal21Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Curve = C;

    type KeyShare = keygen::Xal21KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = ();
    type Signature = ();

    type KeyGen = keygen::Xal21KeygenMachine<C>;
    type AuxGen = tecdsa_protocol::NoOpMachine;
    type Presign = tecdsa_protocol::NoOpMachine;
    type Sign = tecdsa_protocol::NoOpMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

pub type Xal21 = Xal21Protocol<k256::Secp256k1>;
