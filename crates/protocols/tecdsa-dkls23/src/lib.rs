// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! DKLs23 threshold ECDSA protocol.
//!
//! Implements the [`Protocol`] trait for the Doerner-Kondi-Lee-shelat 2023
//! threshold ECDSA protocol, which achieves 4-round signing using OT/VOLE-based
//! secure multiplication instead of Paillier encryption.
//!
//! ## Key Properties
//!
//! - **4-round signing:** 3-round presign (offline) + 1-round online sign.
//!   (The paper describes 3 rounds; the extra presign round is for RVOLE init.)
//! - **No ZK proofs:** uses statistical EC point consistency checks.
//! - **OT/VOLE multiplication:** replaces Paillier MtA with real RVOLE from `tecdsa-ot`.
//! - **Relaxed DKG:** 3-round key generation with Shamir secret sharing.
//!
//! ## Protocol Structure
//!
//! - **KeyGen (3 rounds):** Feldman VSS + consistency checks.
//! - **Presign (3 rounds):** RVOLE-based multiplication to compute nonce inversion
//!   and key product shares, plus EC consistency checks on R = kG.
//!   Round 1: RVOLE init + nonce commit.
//!   Round 2: RVOLE receiver phase 1 + nonce decommit.
//!   Round 3: RVOLE sender run + consistency elements.
//! - **OnlineSign (1 round):** each party broadcasts (u_i, w_i), then
//!   s = sum(w_j) * sum(u_j)^{-1} mod q.
//!
//! Reference: Doerner, Kondi, Lee, shelat. "Threshold ECDSA in Three Rounds."
//! IEEE S&P 2023.

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;
pub mod utils;

use std::marker::PhantomData;

use elliptic_curve::{
    ops::{LinearCombination, Reduce},
    sec1::ModulusSize,
    FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

/// Curve-generic DKLs23 threshold ECDSA protocol descriptor.
pub struct Dkls23Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Dkls23Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>
        + Reduce<FieldBytes<C>>
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Curve = C;

    type KeyShare = key_share::Dkls23KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Dkls23Presignature<C>;
    type Signature = tecdsa_protocol::Signature<C>;

    type KeyGen = keygen::Dkls23KeygenMachine<C>;
    type AuxGen = NoOpMachine;
    type Presign = presign::Dkls23PresignMachine<C, rand_core::OsRng>;
    type Sign = sign::Dkls23OnlineSignMachine<C>;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

/// Backward-compatible alias: DKLs23 over secp256k1.
pub type Dkls23 = Dkls23Protocol<k256::Secp256k1>;
