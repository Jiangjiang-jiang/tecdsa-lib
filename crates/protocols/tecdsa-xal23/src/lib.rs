#![forbid(unsafe_code)]
#![allow(non_snake_case)]

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;

use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

pub struct Xal23;

impl Protocol for Xal23 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Xal23KeyShare<k256::Secp256k1>;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Xal23Presignature<k256::Secp256k1>;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Xal23KeygenMachine<k256::Secp256k1>;
    type AuxGen = NoOpMachine;
    type Presign = presign::Xal23PresignMachine<k256::Secp256k1>;
    type Sign = sign::Xal23SignMachine<k256::Secp256k1>;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = XAL23_METADATA;
}

pub const XAL23_METADATA: ProtocolMetadata = metadata::METADATA;
