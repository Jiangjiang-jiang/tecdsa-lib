// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the CGGMP20 presigning protocol.
//!
//! **Curve constraint:** The ZK proof types (`pi_elog::NiProof`, `pi_aff::NiProof`,
//! `pi_enc_elg::NiProof`) are parameterized over `generic_ec::curves::Secp256k1`
//! because the upstream `paillier-zk` crate uses `generic_ec` rather than
//! `elliptic-curve`.  This means `Cggmp20PresignMachine<C>` currently only compiles
//! when `C = k256::Secp256k1`.  Supporting additional curves requires either
//! extending `BridgeCurve` with a `GE` associated type propagated into message
//! types, or forking `paillier-zk` to use `elliptic-curve` directly.

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use generic_ec::curves::Secp256k1 as GE;
use serde::{Deserialize, Serialize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    zk::paillier_zk::{
        dlog_with_el_gamal_commitment as pi_elog, paillier_affine_operation_in_range as pi_aff,
        paillier_encryption_in_range_with_el_gamal as pi_enc_elg,
    },
    Ciphertext,
};

/// Round 1 broadcast: Paillier ciphertexts and El-Gamal commitment points.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound1<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Enc(pk_i, k_i)
    pub big_k: Ciphertext,
    /// Enc(pk_i, gamma_i)
    pub big_g: Ciphertext,
    /// y_i * G
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub big_y: C::ProjectivePoint,
    /// a_i * G
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub a1: C::ProjectivePoint,
    /// a_i * Y_i + k_i * G  (El-Gamal for k_i)
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub a2: C::ProjectivePoint,
    /// b_i * G
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub b1: C::ProjectivePoint,
    /// b_i * Y_i + gamma_i * G  (El-Gamal for gamma_i)
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub b2: C::ProjectivePoint,
}

/// Round 2 P2P: MtA results, masked ciphertexts, and ZK proofs (one per peer).
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct MsgRound2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Gamma_i = gamma_i * G
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub big_gamma: C::ProjectivePoint,
    /// MtA result: gamma_i (*) K_j (+) Enc(-beta)
    pub big_d: Ciphertext,
    /// Enc(pk_i, -beta)
    pub big_f: Ciphertext,
    /// MtA result: x_i (*) K_j (+) Enc(-hat_beta)
    pub hat_big_d: Ciphertext,
    /// Enc(pk_i, -hat_beta)
    pub hat_big_f: Ciphertext,
    /// π_enc_elg proof that K_i encrypts k_i in range
    pub psi0: pi_enc_elg::NiProof<GE>,
    /// π_enc_elg proof that G_i encrypts gamma_i in range
    pub psi1: pi_enc_elg::NiProof<GE>,
    /// π_elog proof tying Gamma_i to El-Gamal commitment
    pub tilde_psi: pi_elog::NiProof<GE>,
    /// π_aff_g proof for MtA D (gamma * K)
    pub psi: pi_aff::NiProof<GE>,
    /// π_aff_g proof for MtA hat_D (x * K)
    pub hat_psi: pi_aff::NiProof<GE>,
}

/// Round 3 broadcast: delta, Delta, S shares with π_elog proof.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgRound3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// delta_i = gamma_i * k_i + sum(alpha_ij + beta_ij)
    pub delta: <C as CurveArithmetic>::Scalar,
    /// Delta_i = k_i * Gamma
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub big_delta: C::ProjectivePoint,
    /// S_i = chi_i * Gamma
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub big_s: C::ProjectivePoint,
    /// π_elog proof that Delta_i = k_i * Gamma
    pub psi_prime: pi_elog::NiProof<GE>,
}

/// Unified envelope for all presign messages.
///
/// Uses a single type for both `Inbound` and `Outbound` so that the
/// `Orchestrator` constraint `Outbound: Into<Inbound>` is trivially satisfied.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum PresignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(MsgRound1<C>),
    Round2(MsgRound2<C>),
    Round3(MsgRound3<C>),
}
