// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![allow(non_snake_case)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

//! XAL+21 online-friendly two-party ECDSA protocol.
//!
//! Implements "Efficient Online-friendly Two-Party ECDSA Signature"
//! (Xue, Au, Liu, Yuen, Cui, ACM CCS 2021).
//!
//! This is a 2-party protocol with asymmetric roles:
//! - **Party 1** (server): holds Paillier decryption key, additive share `x_1`
//! - **Party 2** (client): holds Paillier encryption key, additive share `x_2`
//!
//! Key sharing is **additive**: `x = x_1 + x_2`.
//!
//! The protocol separates signing into an **offline** phase (3 steps, message-independent)
//! and an **online** phase (1 message, optimal -- only scalar arithmetic).
//!
//! ## Key Innovations
//!
//! 1. **Re-sharing**: `x = x'_1 * (k_2 + r_1) + x'_2` using 1 MtA call
//! 2. **Linear nonce**: `k = k_1 * (r_1 + k_2)`, where P_1 picks `k_1, r_1`; P_2 picks `k_2`
//! 3. **Online phase optimal**: P_2 sends `s_2 = (k_2 + r_1)^{-1} * (m + r * x'_2)`,
//!    P_1 computes `s = k_1^{-1} * (s_2 + r * x'_1)` -- no Paillier ops online

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod offline_sign;
pub mod online_sign;
#[deprecated(note = "use tecdsa_paillier::zk::correct_key_ni directly")]
pub mod zk_correct_key {
    pub use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
}

// ---------------------------------------------------------------------------
// Protocol trait implementation
// ---------------------------------------------------------------------------

use std::marker::PhantomData;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{Protocol, ProtocolMetadata};

/// Curve-generic XAL+21 two-party ECDSA protocol descriptor.
pub struct Xal21Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Xal21Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Curve = C;

    type KeyShare = keygen::Xal21KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = ();
    type Signature = ();

    type KeyGen = keygen::Xal21KeygenMachine<C>;
    type AuxGen = tecdsa_protocol::NoOpMachine;
    type Presign = tecdsa_protocol::NoOpMachine;
    type Sign = tecdsa_protocol::NoOpMachine;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

/// Backward-compatible alias: XAL+21 over secp256k1.
pub type Xal21 = Xal21Protocol<k256::Secp256k1>;
