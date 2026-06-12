#![forbid(unsafe_code)]

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod mpmta;
pub mod presign;
pub mod pvss;
pub mod sign;

pub use key_share::Tx25KeyShare;
use tecdsa_protocol::{NoOpMachine, Protocol};

pub struct Tx25;

impl Protocol for Tx25 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Tx25KeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Tx25Presignature;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Tx25KeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::Tx25PresignMachine;
    type Sign = sign::Tx25OnlineSignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: tecdsa_protocol::ProtocolMetadata = crate::metadata::METADATA;
}
