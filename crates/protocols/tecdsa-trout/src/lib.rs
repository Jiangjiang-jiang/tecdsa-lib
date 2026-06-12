#![forbid(unsafe_code)]

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;

use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

pub struct Trout;

impl Protocol for Trout {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::TroutKeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::TroutPresignOutput;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::TroutKeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::machine::TroutPresignMachine;
    type Sign = sign::machine::TroutSignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = metadata::METADATA;
}
