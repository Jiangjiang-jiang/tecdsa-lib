// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the GG18 threshold signing protocol.
//!
//! The protocol runs in 8 message rounds:
//!
//! - Round 1: broadcast Com(g_γ_i) + P2P c_A with AliceProof (merged Phase 1+2a)
//! - Round 2: P2P c_B with BobProofExt (Phase 2b)
//! - Round 3: broadcast δ_i + decommit g_γ_i + Schnorr proof for γ_i (merged Phase 3+4)
//! - Round 4: broadcast Phase 5a commitment
//! - Round 5: broadcast Phase 5b decommitment + proofs
//! - Round 6: broadcast Phase 5c commitment
//! - Round 7: broadcast Phase 5d decommitment (U_i, T_i) — NO s_i
//! - Round 8: broadcast Phase 5e partial signature s_i (after zero-check)

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::zk::{
    homo_elgamal::HomoElGamalProof,
    mta_range::{AliceProof, BobProofExt},
};

use crate::keygen::msg::SerInteger;

// ---------------------------------------------------------------------------
// Round 1: Phase 1 + Phase 2a merged
// ---------------------------------------------------------------------------

/// Round 1 broadcast component: commitment to the ephemeral public nonce `g_gamma_i`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgSignRound1Broadcast {
    /// Hash commitment to `g_gamma_i`.
    pub commitment: HashCommitment,
}

/// Round 1 P2P component: Alice sends her encrypted value `c_a = Enc(k_i)` with
/// a range proof.
///
/// This is the first MtA message for both the `(k_i, gamma_j)` and `(k_i, w_j)` MtA.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgSignRound1P2p {
    /// Paillier ciphertext `c_a = Enc(k_i; r_i)`.
    pub c_a: SerInteger,
    /// Range proof that the encrypted value is bounded.
    pub alice_proof: AliceProof,
}

// ---------------------------------------------------------------------------
// Round 2: Phase 2b — MtA Bob response
// ---------------------------------------------------------------------------

/// Round 2 P2P: Bob responds with `c_b` for the MtA, plus range proofs.
///
/// Contains both the `(k_i, gamma_j)` and `(k_i, w_j)` responses.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgSignRound2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// MtA ciphertext for `(k_i, gamma_j)`: `c_b_gamma = gamma_j * c_a + Enc(-beta; r_b)`.
    pub c_b_gamma: SerInteger,
    /// MtA ciphertext for `(k_i, w_j)`: `c_b_w = w_j * c_a + Enc(-nu; r_b)`.
    pub c_b_w: SerInteger,
    /// Extended range proof for the gamma MtA.
    pub bob_proof_gamma: BobProofExt<C>,
    /// Extended range proof for the w MtA.
    pub bob_proof_w: BobProofExt<C>,
    /// Bob's claimed w_j * G (used by Alice to verify bob_proof_w).
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub w_j_point: C::ProjectivePoint,
}

// ---------------------------------------------------------------------------
// Round 3: Phase 3 + Phase 4 merged — delta + decommit + Schnorr proof
// ---------------------------------------------------------------------------

/// Round 3 broadcast: delta share, decommitment of g_gamma_i, and Schnorr proof
/// of knowledge of gamma_i.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgSignRound3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// $\delta_i = k_i \gamma_i + \sum \alpha_{ij} + \sum \beta_{ij}$
    pub delta_i: <C as CurveArithmetic>::Scalar,
    /// The ephemeral public nonce `g_gamma_i = gamma_i * G`.
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub g_gamma_i: C::ProjectivePoint,
    /// The decommitment nonce from Round 1.
    pub decommit_nonce: [u8; 32],
    /// Schnorr proof that the sender knows gamma_i s.t. g_gamma_i = gamma_i * G.
    /// Required by paper §4.2, Phase 4.
    pub gamma_proof: DlogProof<C>,
}

// ---------------------------------------------------------------------------
// Round 4: Phase 5a — commitment to (V_i, A_i, B_i)
// ---------------------------------------------------------------------------

/// Round 4 broadcast: commitment to Phase 5 verification values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgPhase5aCommit {
    /// Hash commitment to `(V_i, A_i, B_i)`.
    pub commitment: HashCommitment,
}

// ---------------------------------------------------------------------------
// Round 5: Phase 5b — decommit (V_i, A_i, B_i) with proofs
// ---------------------------------------------------------------------------

/// Round 5 broadcast: decommitment of Phase 5 verification values and proofs.
#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgPhase5bDecommit<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// $V_i = R \cdot \sigma_i + G \cdot l_i$
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub V_i: C::ProjectivePoint,
    /// $A_i = G \cdot \rho_i$
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub A_i: C::ProjectivePoint,
    /// $B_i = G \cdot (l_i \cdot \rho_i)$
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub B_i: C::ProjectivePoint,
    /// Decommitment nonce for the Round 4 commitment.
    pub decommit_nonce: [u8; 32],
    /// HomoElGamal proof that V_i is correctly formed.
    pub homo_proof: HomoElGamalProof<C>,
    /// DLog proof for rho_i (proving knowledge of A_i = rho_i * G).
    pub dlog_proof: DlogProof<C>,
}

// ---------------------------------------------------------------------------
// Round 6: Phase 5c — commitment to (U_i, T_i)
// ---------------------------------------------------------------------------

/// Round 6 broadcast: commitment to `(U_i, T_i)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgPhase5cCommit {
    /// Hash commitment to `(U_i, T_i)`.
    pub commitment: HashCommitment,
}

// ---------------------------------------------------------------------------
// Round 7: Phase 5d — decommit (U_i, T_i) only — NO s_i!
// ---------------------------------------------------------------------------

/// Round 7 broadcast: decommitment of `(U_i, T_i)` WITHOUT the partial signature.
///
/// **Security fix**: The partial signature `s_i` is NOT included here.
/// It is only broadcast in Round 8 after the zero-check passes.
/// This prevents leaking s_i values when the zero-check fails.
#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgPhase5dDecommit<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// $U_i = V \cdot \rho_i$ where $V = \sum V_j$.
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub U_i: C::ProjectivePoint,
    /// $T_i = A_i \cdot l_i$ where $A = \sum A_j$.
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub T_i: C::ProjectivePoint,
    /// Decommitment nonce for the Round 6 commitment.
    pub decommit_nonce: [u8; 32],
}

// ---------------------------------------------------------------------------
// Round 8: Phase 5e — partial signature (after zero-check)
// ---------------------------------------------------------------------------

/// Round 8 broadcast: the partial signature `s_i`.
///
/// Only sent after the Phase 5 zero-check in Round 7 passes, ensuring
/// honest parties' s_i values are never exposed to a malicious party
/// that fails the zero-check.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgPhase5eSig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Partial signature $s_i = m \cdot k_i + r \cdot \sigma_i$.
    pub s_i: <C as CurveArithmetic>::Scalar,
}

// ---------------------------------------------------------------------------
// Unified envelope
// ---------------------------------------------------------------------------

/// Unified message envelope for all GG18 signing rounds.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum Gg18SignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1Broadcast(MsgSignRound1Broadcast),
    Round1P2p(MsgSignRound1P2p),
    Round2(MsgSignRound2<C>),
    Round3(MsgSignRound3<C>),
    Round4(MsgPhase5aCommit),
    Round5(MsgPhase5bDecommit<C>),
    Round6(MsgPhase5cCommit),
    Round7(MsgPhase5dDecommit<C>),
    Round8(MsgPhase5eSig<C>),
}
