#![forbid(unsafe_code)]

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod mtawc;
pub mod nizk;
pub mod presign;
pub mod sign;

use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

pub struct Wmy23;

impl Protocol for Wmy23 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Wmy23KeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Wmy23Presignature;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Wmy23KeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::Wmy23PresignMachine;
    type Sign = sign::Wmy23OnlineSignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}
