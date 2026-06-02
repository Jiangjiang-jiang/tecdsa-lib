// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

//! Lindell 2017 two-party ECDSA protocol.
//!
//! Implements "Fast Secure Two-Party ECDSA Signing" (Lindell, CRYPTO 2017 / JoC 2021).
//!
//! This is a 2-party protocol with asymmetric roles:
//! - **Party 1** (server): holds Paillier decryption key, multiplicative share `x_1`
//! - **Party 2** (client): holds Paillier encryption key, encrypted `x_1`, multiplicative share `x_2`
//!
//! Key sharing is **multiplicative**: `x = x_1 * x_2` (not additive).
//!
//! The signing protocol uses Paillier homomorphic encryption to combine partial
//! signatures without revealing either party's secret share.

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod sign;
#[deprecated(note = "use tecdsa_paillier::zk::correct_key_ni directly")]
pub mod zk_correct_key {
    pub use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
}
#[deprecated(note = "use tecdsa_paillier::zk::pdl directly")]
pub mod zk_pdl {
    pub use tecdsa_paillier::zk::pdl::*;
}
#[deprecated(note = "use tecdsa_paillier::zk::range_ni directly")]
pub mod zk_range {
    pub use tecdsa_paillier::zk::range_ni::*;
}

// ---------------------------------------------------------------------------
// Protocol trait implementation
// ---------------------------------------------------------------------------

use std::marker::PhantomData;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{Protocol, ProtocolMetadata};

/// Curve-generic Lindell 2017 two-party ECDSA protocol descriptor.
pub struct Lin17Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Lin17Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Curve = C;

    type KeyShare = keygen::Lin17KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = ();
    type Signature = ();

    type KeyGen = keygen::Lin17KeygenMachine<C>;
    type AuxGen = tecdsa_protocol::NoOpMachine;
    type Presign = tecdsa_protocol::NoOpMachine;
    type Sign = tecdsa_protocol::NoOpMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

/// Backward-compatible alias: Lin17 over secp256k1.
pub type Lin17 = Lin17Protocol<k256::Secp256k1>;
