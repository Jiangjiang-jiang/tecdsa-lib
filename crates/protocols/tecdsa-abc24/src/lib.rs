// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

//! ABC+24 two-party threshold ECDSA protocol.
//!
//! Implements "Two-Round 2PC ECDSA at the Cost of 1 OLE"
//! (Adjedj, Blokh, Couteau, Galansky, Joux, Makriyannis, 2026).
//!
//! This is a 2-party protocol with asymmetric roles:
//! - **Server (P_1)**: holds Paillier decryption key `phi(N)`, additive share `x_2`
//! - **Client (P_2)**: holds additive share `x_1`, Paillier ciphertext `E = enc(x_2)`
//!
//! Key sharing is **additive**: `x = x_1 + x_2`.
//!
//! The protocol achieves:
//! - **2 rounds** of signing (optimal)
//! - **1 OLE** per signature (optimal for Paillier-based approaches)
//! - **Concurrent security** via nonce derandomization with random oracle
//! - **Star topology** support (server shares key with multiple clients)
//!
//! The OLE is realized using Paillier homomorphic encryption with
//! Damgard-Fujisaki integer commitments for the ZK proofs.

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod setup;
pub mod sign;
#[deprecated(note = "use tecdsa_paillier::zk::correct_key_ni directly")]
pub mod zk_correct_key {
    pub use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
}
#[deprecated(note = "use tecdsa_paillier::zk::pdl directly")]
pub mod zk_pdl {
    pub use tecdsa_paillier::zk::pdl::*;
}

use std::marker::PhantomData;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{Protocol, ProtocolMetadata};

/// Curve-generic ABC+24 two-party ECDSA protocol descriptor.
pub struct Abc24Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Abc24Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Curve = C;

    type KeyShare = keygen::Abc24KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = ();
    type Signature = ();

    type KeyGen = keygen::Abc24KeygenMachine<C>;
    type AuxGen = tecdsa_protocol::NoOpMachine;
    type Presign = tecdsa_protocol::NoOpMachine;
    type Sign = tecdsa_protocol::NoOpMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

/// Backward-compatible alias: ABC+24 over secp256k1.
pub type Abc24 = Abc24Protocol<k256::Secp256k1>;
