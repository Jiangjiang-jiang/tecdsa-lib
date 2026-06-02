// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the CGGMP20 full-signing protocol (presign + sign round).

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_curve::TecdsaCurve;

use crate::presign::msg::PresignMsg;

/// Round 4 broadcast: a party's partial signature scalar.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub struct MsgRound4<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Partial signature scalar `sigma_i = k_tilde_i * m + r * chi_tilde_i`.
    pub sigma: <C as CurveArithmetic>::Scalar,
}

/// Unified envelope for all full-signing messages (presign rounds 1–3 + signing round 4).
///
/// Uses a single type for both `Inbound` and `Outbound` so that the
/// `Orchestrator` constraint `Outbound: Into<Inbound>` is trivially satisfied.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C::Scalar: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>"
))]
pub enum FullSignMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Presign(PresignMsg<C>),
    Round4(MsgRound4<C>),
}
