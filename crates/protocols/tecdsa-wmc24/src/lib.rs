#![forbid(unsafe_code)]

pub(crate) mod curve_wire;
pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;

pub use key_share::Wmc24KeyShare;
use tecdsa_protocol::{NoOpMachine, Protocol};

pub struct Wmc24;

impl Protocol for Wmc24 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Wmc24KeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Wmc24Presignature;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Wmc24KeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::Wmc24PresignMachine;
    type Sign = sign::Wmc24OnlineSignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: tecdsa_protocol::ProtocolMetadata = crate::metadata::METADATA;
}
