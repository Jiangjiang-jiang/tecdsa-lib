// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! KU25 -- honest-majority threshold ECDSA with batch generation of
//! key-independent presignatures (Katz and Urban).
//!
//! The protocol targets *key-management networks*: a fixed set of `n` servers
//! that hold shares of a large number of ECDSA keys on behalf of many users.
//! In that setting two properties matter that dishonest-majority protocols do
//! not offer:
//!
//! * **Key-independent presignatures.**  A presignature is not tied to a key,
//!   so a network hosting `N` keys does not need `N` presignatures sitting
//!   around; any presignature can be used with any key.
//! * **Batch presigning.**  `m` presignatures are produced in a *constant*
//!   number of rounds, so the amortized cost collapses as `m` grows.
//!
//! Both are possible because the setting assumes an honest majority
//! (`n >= 2t + 1`), which allows a Shamir-based MPC design with no MtA, no
//! Paillier/class-group machinery and no range proofs.
//!
//! # Phases
//!
//! | phase | module | rounds | key-dependent? |
//! |---|---|---|---|
//! | PRSS setup (`F_rss.Init`) | [`setup`] | 1 (point-to-point) | no |
//! | Key generation | [`keygen`] | 1 (broadcast) | yes |
//! | Batch presigning | [`presign`] | 4 (broadcast) | **no** |
//! | Online signing | [`sign`] | 1 (broadcast) | yes |
//!
//! The PRSS setup is run **once**, ever.  Key generation may be run once per
//! hosted key.  Presigning may be run at any time, in bulk, with no reference
//! to any key.
//!
//! # Modular structure (mirrors the paper)
//!
//! * [`prss`] realises `F_rss` via pseudorandom (zero) secret sharing --
//!   Section 5.  The dealer-free key distribution is in [`setup`].
//! * [`presign`] realises `F_wmult` (Appendix A), `F_triple` (Section 4) and
//!   the presigning half of `Pi_ECDSA` (Section 3) as one four-round protocol.
//! * [`sign`] is the signing half of `Pi_ECDSA`.
//! * [`interp`] provides the paper's `interpolate_d(j, S, .)` with its
//!   all-important consistency check.
//!
//! # Security model
//!
//! UC-secure with abort against a static, rushing, malicious adversary
//! corrupting up to `t < n/2` parties, over private point-to-point channels;
//! **no broadcast channel is assumed**.  Distributed key generation is out of
//! scope in the paper; the [`keygen`] module supplies the natural one-round
//! PRSS-based DKG for the same model.
//!
//! # Threshold convention
//!
//! Following the rest of this workspace, `threshold` always means the
//! *reconstruction* threshold, i.e. `t + 1` in the paper's notation.  An
//! honest majority requires `n >= 2 * (threshold - 1) + 1`.
//!
//! # Scaling caveat
//!
//! PRSS needs `binomial(n, t)` replicated keys, so it is exponential in `n`.
//! The paper targets `n < 20`; this implementation caps the committee at
//! [`prss::MAX_PARTIES`] and rejects larger ones rather than exhausting memory.
//!
//! # Example
//!
//! ```
//! use elliptic_curve::Field;
//! use k256::{Scalar, Secp256k1};
//! use tecdsa_ku25::{
//!     keygen::Ku25KeygenMachine, presign::Ku25PresignMachine, setup::Ku25SetupMachine,
//!     sign::Ku25SignMachine,
//! };
//! use tecdsa_protocol::{ecdsa::DataToSign, PartyId, StateMachine};
//! use tecdsa_testkit::Orchestrator;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let (n, threshold) = (5u16, 3u16); // n = 2t + 1 with t = 2
//! let parties: Vec<PartyId> = (1..=n).map(PartyId).collect();
//!
//! // 1. One-time, key-independent PRSS setup.
//! let prss: Vec<_> = Orchestrator::new(
//!     parties
//!         .iter()
//!         .map(|&p| {
//!             (
//!                 p,
//!                 Ku25SetupMachine::<Secp256k1>::new(p, parties.clone(), threshold).unwrap(),
//!             )
//!         })
//!         .collect(),
//!     4,
//! )
//! .run()?
//! .into_iter()
//! .collect::<Result<Vec<_>, _>>()?;
//!
//! // 2. Key generation for one hosted key.
//! let shares: Vec<_> = Orchestrator::new(
//!     parties
//!         .iter()
//!         .zip(&prss)
//!         .map(|(&p, k)| {
//!             (
//!                 p,
//!                 Ku25KeygenMachine::new(p, parties.clone(), k, &[7u8; 32]).unwrap(),
//!             )
//!         })
//!         .collect(),
//!     4,
//! )
//! .run()?
//! .into_iter()
//! .collect::<Result<Vec<_>, _>>()?;
//!
//! // 3. Batch presigning -- no key involved.
//! let session = [1u8; 32];
//! let batches: Vec<_> = Orchestrator::new(
//!     parties
//!         .iter()
//!         .zip(&prss)
//!         .map(|(&p, k)| {
//!             (
//!                 p,
//!                 Ku25PresignMachine::new_with_session(p, parties.clone(), k, 4, &session)
//!                     .unwrap(),
//!             )
//!         })
//!         .collect(),
//!     10,
//! )
//! .run()?
//! .into_iter()
//! .collect::<Result<Vec<_>, _>>()?;
//!
//! // 4. Online signing with the first presignature of the batch.
//! let digest = DataToSign::<Secp256k1>::from_digest(Scalar::from(1234u64));
//! let sigs: Vec<_> = Orchestrator::new(
//!     parties
//!         .iter()
//!         .zip(shares.iter().zip(batches))
//!         .map(|(&p, (share, batch))| {
//!             let presig = batch.into_vec().remove(0);
//!             (
//!                 p,
//!                 Ku25SignMachine::new(p, parties.clone(), share, presig, digest).unwrap(),
//!             )
//!         })
//!         .collect(),
//!     4,
//! )
//! .run()?
//! .into_iter()
//! .collect::<Result<Vec<_>, _>>()?;
//!
//! assert_eq!(sigs.len(), usize::from(n));
//! # Ok(())
//! # }
//! ```

pub mod committee;
pub mod error;
pub mod interp;
pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod prss;
pub mod setup;
pub mod sign;
pub mod wire;

use std::marker::PhantomData;

pub use committee::Committee;
use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
pub use error::{Ku25Error, Ku25Result};
pub use key_share::Ku25KeyShare;
pub use keygen::Ku25KeygenMachine;
pub use presign::{Ku25PresignBatch, Ku25PresignMachine, Ku25Presignature};
pub use prss::PrssKeys;
pub use setup::Ku25SetupMachine;
pub use sign::Ku25SignMachine;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{NoRefreshMachine, Protocol, ProtocolMetadata};

/// KU25 protocol descriptor, generic over the curve.
pub struct Ku25Protocol<C: TecdsaCurve>(PhantomData<C>)
where
    FieldBytesSize<C>: ModulusSize;

impl<C: TecdsaCurve> Protocol for Ku25Protocol<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Curve = C;

    type KeyShare = Ku25KeyShare<C>;
    type PublicKey = C::ProjectivePoint;
    /// The key-independent PRSS material produced by [`setup`].
    type AuxInfo = PrssKeys<C>;
    /// A whole batch: KU25's unit of presignature production is `m` at a time.
    type Presignature = Ku25PresignBatch<C>;
    type Signature = tecdsa_protocol::Signature<C>;

    type KeyGen = Ku25KeygenMachine<C>;
    type AuxGen = Ku25SetupMachine<C>;
    type Presign = Ku25PresignMachine<C>;
    type Sign = Ku25SignMachine<C>;
    /// KU25 has no refresh protocol; re-running [`setup`] rotates the PRSS keys.
    type Refresh = NoRefreshMachine<Ku25KeyShare<C>>;

    const METADATA: ProtocolMetadata = crate::metadata::METADATA;
}

/// KU25 over secp256k1.
pub type Ku25 = Ku25Protocol<k256::Secp256k1>;
