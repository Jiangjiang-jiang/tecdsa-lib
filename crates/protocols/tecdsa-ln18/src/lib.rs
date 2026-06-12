#![forbid(unsafe_code)]

pub mod f_mult;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod mta;
pub mod sign;

use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use tecdsa_protocol::Protocol;

pub struct Ln18;

impl Protocol for Ln18
where
    FieldBytesSize<k256::Secp256k1>: ModulusSize,
{
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Ln18KeyShare<k256::Secp256k1>;
    type PublicKey = <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = key_share::Ln18OfflineSignState<k256::Secp256k1>;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Ln18KeygenMachine<k256::Secp256k1>;
    type AuxGen = tecdsa_protocol::NoOpMachine;
    type Presign = sign::Ln18OfflineSignMachine<k256::Secp256k1>;
    type Sign = sign::Ln18OnlineSignMachine<k256::Secp256k1>;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: tecdsa_protocol::ProtocolMetadata = crate::metadata::METADATA;
}
