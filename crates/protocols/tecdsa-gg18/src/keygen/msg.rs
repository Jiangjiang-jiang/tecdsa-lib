// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the GG18 threshold key generation protocol.
//!
//! The protocol runs in 4 rounds:
//! - Round 1: broadcast hash commitment
//! - Round 2: broadcast decommitment (`y_i`, `ek_i`, `N'_i`, `h1_i`, `h2_i`, nonce),
//!   unicast Feldman VSS share to each party
//! - Round 3: broadcast Schnorr `DLog` proof
//! - Round 4: (verification only, no new messages)

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use rug::Integer;
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::BigIntExt;

/// Number of repetitions in the Paillier-Blum modulus proof (Pi_mod).
///
/// Pi_mod's soundness error is `2^-PI_MOD_SECURITY`: a prover who does not know
/// the factorisation passes a single repetition with probability 1/2. GG18 §4.1
/// Phase 3 inherits CGGMP20 Figure 12's requirement of 80.
///
/// Do not lower this to speed up tests. It is the soundness parameter of a proof
/// that the Paillier modulus is well formed; at 16 an adversary can grind a
/// malformed modulus past verification with probability 2^-16.
pub const PI_MOD_SECURITY: usize = 80;

// ---------------------------------------------------------------------------
// Serializable wrapper for Integer (which lacks serde)
// ---------------------------------------------------------------------------

/// A big integer serialized as MSF (most-significant-first) bytes.
///
/// Wraps `rug::Integer` with serde support via
/// its `to_bytes_msf` / `from_bytes_msf` conversions.
#[derive(Clone, Debug)]
pub struct SerInteger(pub Integer);

impl Serialize for SerInteger {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.0.to_bytes_msf();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerInteger {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(SerInteger(Integer::from_bytes_msf(&bytes)))
    }
}

// ---------------------------------------------------------------------------
// Round 1: hash commitment
// ---------------------------------------------------------------------------

/// Round 1 broadcast: hash commitment to public key point, Paillier key,
/// and Ring-Pedersen parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgRound1 {
    /// Hash commitment `V_i = H(y_i || ek_i || N'_i || h1_i || h2_i)`.
    pub commitment: HashCommitment,
}

// ---------------------------------------------------------------------------
// Round 2: decommitment + VSS share
// ---------------------------------------------------------------------------

/// Round 2 broadcast: decommitment revealing public data.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound2Broad<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Public key contribution `y_i = u_i * G`.
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub y_i: C::ProjectivePoint,
    /// Paillier encryption key `ek_i`.
    pub ek: tecdsa_paillier::EncryptionKey,
    /// Ring-Pedersen RSA modulus `N'_i`.
    pub n_tilde: SerInteger,
    /// Ring-Pedersen first base `h1_i`.
    pub h1: SerInteger,
    /// Ring-Pedersen second base `h2_i`.
    pub h2: SerInteger,
    /// Feldman polynomial commitments `C_j = a_j * G`.
    #[serde(with = "tecdsa_curve::serde_projective::vec")]
    pub feldman_commitments: Vec<C::ProjectivePoint>,
    /// Nonce used when creating the hash commitment in Round 1.
    pub decommit_nonce: [u8; 32],
}

/// Round 2 unicast: Feldman VSS share for the recipient party.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgRound2Uni<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The VSS share value `f_i(j)` for the recipient party.
    pub vss_share: <C as CurveArithmetic>::Scalar,
}

// ---------------------------------------------------------------------------
// Round 3: DLog proof
// ---------------------------------------------------------------------------

/// Round 3 broadcast: Schnorr `DLog` proof for the party's public share,
/// plus a Paillier-Blum modulus proof (Pi_mod) for the party's Paillier modulus N.
///
/// The Pi_mod proof is required by the paper §4.1 Phase 3 to ensure that
/// each party's Paillier modulus is square-free.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Schnorr proof that the sender knows its secret share `x_i`
    /// such that `X_i = x_i * G`.
    pub schnorr_proof: DlogProof<C>,
    /// Proof that the sender's Paillier modulus N is a Paillier-Blum modulus
    /// (product of two safe primes, both ≡ 3 mod 4).
    pub paillier_mod_proof: tecdsa_paillier::zk::pi_mod::NiProof<PI_MOD_SECURITY>,
}

// ---------------------------------------------------------------------------
// Unified envelope
// ---------------------------------------------------------------------------

/// Unified envelope for all GG18 keygen messages.
///
/// Uses a single type for both `Inbound` and `Outbound` so that the
/// `Orchestrator` constraint `Outbound: Into<Inbound>` is trivially satisfied.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum Gg18KeygenMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(MsgRound1),
    Round2Broad(MsgRound2Broad<C>),
    Round2Uni(MsgRound2Uni<C>),
    Round3(MsgRound3<C>),
}
