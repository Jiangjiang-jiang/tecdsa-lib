#![forbid(unsafe_code)]

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;

use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata, Signature};

pub struct Llz25;

impl Protocol for Llz25 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Llz25KeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::machine::Llz25Presignature;
    type Signature = Signature<k256::Secp256k1>;

    type KeyGen = keygen::Llz25KeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::machine::Llz25PresignMachine;
    type Sign = sign::machine::Llz25SignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = metadata::METADATA;
}
