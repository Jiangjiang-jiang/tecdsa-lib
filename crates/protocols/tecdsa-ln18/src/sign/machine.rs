// SPDX-License-Identifier: MIT OR Apache-2.0
//! LN18 StateMachine wrappers for presign, online sign, legacy sign, and full-sign.

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};

use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{ecdsa::Signature, PartyId};

use crate::key_share::Ln18Presignature;

use super::msg::{Ln18FullSignMsg, Ln18OnlineSignMsg, Ln18PresignMsg, Ln18SignMsg};

// ---------------------------------------------------------------------------
// Ln18PresignMachine -- minimal StateMachine wrapper for presigning
// ---------------------------------------------------------------------------

/// A minimal `StateMachine` wrapper for the LN18 presign protocol.
pub struct Ln18PresignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    result: Option<Ln18Presignature<C>>,
}

impl<C: TecdsaCurve> Ln18PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a presign machine that wraps a pre-computed presignature.
    #[must_use]
    pub fn from_result(presig: Ln18Presignature<C>) -> Self {
        Self {
            result: Some(presig),
        }
    }
}

impl<C: TecdsaCurve> tecdsa_protocol::StateMachine for Ln18PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Ln18Presignature<C>;
    type Inbound = Ln18PresignMsg;
    type Outbound = Ln18PresignMsg;

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(tecdsa_core::TecdsaError::Other(
            "Ln18PresignMachine: use ln18_presign_parallel for presigning".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<tecdsa_protocol::Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.result.is_some()
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.result
            .ok_or_else(|| tecdsa_core::TecdsaError::Other("presign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.result.is_some() {
            9 // done (8 rounds + 1)
        } else {
            0
        }
    }

    fn ia_report(&self) -> Option<&tecdsa_protocol::IaReport> {
        None
    }
}

// ---------------------------------------------------------------------------
// Ln18OnlineSignMachine -- minimal StateMachine wrapper for online signing
// ---------------------------------------------------------------------------

/// A minimal `StateMachine` wrapper for the LN18 online sign protocol.
pub struct Ln18OnlineSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    result: Option<Signature<C>>,
}

impl<C: TecdsaCurve> Ln18OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create an online sign machine that wraps a pre-computed signature.
    #[must_use]
    pub fn from_result(sig: Signature<C>) -> Self {
        Self { result: Some(sig) }
    }
}

impl<C: TecdsaCurve> tecdsa_protocol::StateMachine for Ln18OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Signature<C>;
    type Inbound = Ln18OnlineSignMsg;
    type Outbound = Ln18OnlineSignMsg;

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(tecdsa_core::TecdsaError::Other(
            "Ln18OnlineSignMachine: use ln18_online_sign_parallel for signing".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<tecdsa_protocol::Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.result.is_some()
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.result
            .ok_or_else(|| tecdsa_core::TecdsaError::Other("online sign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.result.is_some() {
            7 // done (6 rounds + 1)
        } else {
            0
        }
    }

    fn ia_report(&self) -> Option<&tecdsa_protocol::IaReport> {
        None
    }
}

// ---------------------------------------------------------------------------
// Legacy Ln18SignMachine (delegates to online sign machine)
// ---------------------------------------------------------------------------

/// A minimal `StateMachine` wrapper for the combined LN18 sign protocol.
///
/// This wraps the full sign (presign + online sign) for backward compatibility.
pub struct Ln18SignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    result: Option<Signature<C>>,
}

impl<C: TecdsaCurve> Ln18SignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a sign machine that wraps a pre-computed signature.
    #[must_use]
    pub fn from_result(sig: Signature<C>) -> Self {
        Self { result: Some(sig) }
    }
}

impl<C: TecdsaCurve> tecdsa_protocol::StateMachine for Ln18SignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Signature<C>;
    type Inbound = Ln18SignMsg;
    type Outbound = Ln18SignMsg;

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(tecdsa_core::TecdsaError::Other(
            "Ln18SignMachine: use ln18_sign_parallel for signing".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<tecdsa_protocol::Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.result.is_some()
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.result
            .ok_or_else(|| tecdsa_core::TecdsaError::Other("sign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.result.is_some() {
            15 // done (14 rounds + 1)
        } else {
            0
        }
    }

    fn ia_report(&self) -> Option<&tecdsa_protocol::IaReport> {
        None
    }
}

// ---------------------------------------------------------------------------
// Ln18FullSignMachine -- StateMachine wrapper for 8-round full signing
// ---------------------------------------------------------------------------

/// A minimal `StateMachine` wrapper for the LN18 8-round full-sign protocol.
///
/// This wraps the interleaved mult1/mult2 signing mode that achieves 8 rounds
/// when the message is known from the start.
pub struct Ln18FullSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    result: Option<Signature<C>>,
}

impl<C: TecdsaCurve> Ln18FullSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a full-sign machine that wraps a pre-computed signature.
    #[must_use]
    pub fn from_result(sig: Signature<C>) -> Self {
        Self { result: Some(sig) }
    }
}

impl<C: TecdsaCurve> tecdsa_protocol::StateMachine for Ln18FullSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Signature<C>;
    type Inbound = Ln18FullSignMsg;
    type Outbound = Ln18FullSignMsg;

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(tecdsa_core::TecdsaError::Other(
            "Ln18FullSignMachine: use ln18_full_sign_parallel for signing".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<tecdsa_protocol::Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.result.is_some()
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.result
            .ok_or_else(|| tecdsa_core::TecdsaError::Other("full sign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.result.is_some() {
            9 // done (8 rounds + 1)
        } else {
            0
        }
    }

    fn ia_report(&self) -> Option<&tecdsa_protocol::IaReport> {
        None
    }
}
