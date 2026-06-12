#![forbid(unsafe_code)]

pub(crate) mod cl_wire;
pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;

pub use key_share::Jtx25KeyShare;
use tecdsa_protocol::{NoOpMachine, Protocol};

pub struct Jtx25;

impl Protocol for Jtx25 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Jtx25KeyShare;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Jtx25Presignature;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Jtx25KeygenMachine;
    type AuxGen = NoOpMachine;
    type Presign = presign::Jtx25PresignMachine;
    type Sign = sign::Jtx25OnlineSignMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: tecdsa_protocol::ProtocolMetadata = crate::metadata::METADATA;
}
