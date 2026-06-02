// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

//! KGG24 two-party ECDSA protocol with proactive security.
//!
//! Implements "Fast Two-party Threshold ECDSA with Proactive Security"
//! (Koziel, Gordon, Gentry, 2024).
//!
//! This is a 2-party protocol with asymmetric roles:
//! - **Party 1** (server): holds Paillier decryption key, additive share `x_1`
//! - **Party 2** (client): holds Paillier encryption key, encrypted `x_1 + t*q` (noised), additive share `x_2`
//!
//! Key sharing is **additive**: `x = x_1 + x_2` (not multiplicative as in Lin17).
//!
//! Key improvements over Lin17:
//! - Additive sharing with noise hiding: `C = Enc(x_1 + t*q)`
//! - Lighter keygen with "loose consistency proof" Pi_eq
//! - No global abort: bad signature triggers refresh instead of full keygen restart
//! - Proactive refresh protocol to re-randomize shares without changing the public key
//! - 3 messages for both keygen and signing (vs 6/4 in Lin17)

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod refresh;
pub mod sign;
#[deprecated(note = "use tecdsa_paillier::zk::correct_key_ni directly")]
pub mod zk_correct_key {
    pub use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
}
#[deprecated(note = "use tecdsa_paillier::zk::pi_eq directly")]
pub mod zk_eq {
    pub use tecdsa_paillier::zk::pi_eq::*;
}

// ---------------------------------------------------------------------------
// Protocol trait implementation
// ---------------------------------------------------------------------------

use std::marker::PhantomData;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{Protocol, ProtocolMetadata};

/// Curve-generic KGG24 two-party ECDSA protocol descriptor.
pub struct Kgg24Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Kgg24Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Curve = C;

    type KeyShare = keygen::Kgg24KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = ();
    type Signature = ();

    type KeyGen = keygen::Kgg24KeygenMachine<C>;
    type AuxGen = tecdsa_protocol::NoOpMachine;
    type Presign = tecdsa_protocol::NoOpMachine;
    type Sign = tecdsa_protocol::NoOpMachine;
    // KGG24 supports proactive refresh via `refresh::refresh_party1/2`,
    // but wrapping those into a StateMachine is deferred.
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

/// Backward-compatible alias: KGG24 over secp256k1.
pub type Kgg24 = Kgg24Protocol<k256::Secp256k1>;
