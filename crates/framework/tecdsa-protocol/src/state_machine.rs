// SPDX-License-Identifier: MIT OR Apache-2.0
use serde::{Deserialize, Serialize};

use crate::{abort::IaReport, party::PartyId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Recipient {
    Party(PartyId),
    Broadcast,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outgoing<M> {
    pub to: Recipient,
    pub msg: M,
}

/// A trivial state machine that immediately completes with `()`.
///
/// Used by protocols that do not have a distinct phase for a given associated
/// type (e.g., GG18 has no separate AuxGen or Presign phase).
pub struct NoOpMachine {
    done: bool,
}

impl NoOpMachine {
    #[must_use]
    pub fn new() -> Self {
        Self { done: true }
    }
}

impl Default for NoOpMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachine for NoOpMachine {
    type Output = ();
    type Inbound = ();
    type Outbound = ();

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(tecdsa_core::TecdsaError::Other(
            "NoOpMachine does not accept messages".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        Ok(())
    }

    fn current_round(&self) -> u16 {
        0
    }

    fn ia_report(&self) -> Option<&crate::abort::IaReport> {
        None
    }
}

/// A trivial state machine that immediately errors, used for protocols that
/// do not support key refresh.
///
/// Unlike [`NoOpMachine`] (which has `Output = ()`), this machine is generic
/// over the output type so it can satisfy `StateMachine<Output = KS>` for
/// any `KS` (e.g. `Protocol::KeyShare`).  Calling [`finish`](StateMachine::finish)
/// always returns an error.
pub struct NoRefreshMachine<KS> {
    _phantom: core::marker::PhantomData<KS>,
}

impl<KS> NoRefreshMachine<KS> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<KS> Default for NoRefreshMachine<KS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<KS: Send + 'static> StateMachine for NoRefreshMachine<KS> {
    type Output = KS;
    type Inbound = ();
    type Outbound = ();

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(tecdsa_core::TecdsaError::Other(
            "NoRefreshMachine: this protocol does not support key refresh".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        false
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        Err(tecdsa_core::TecdsaError::Other(
            "NoRefreshMachine: this protocol does not support key refresh".into(),
        ))
    }

    fn current_round(&self) -> u16 {
        0
    }

    fn ia_report(&self) -> Option<&crate::abort::IaReport> {
        None
    }
}

pub trait StateMachine: Send + 'static {
    type Output;
    type Inbound: serde::de::DeserializeOwned + serde::Serialize + Send;
    type Outbound: serde::Serialize + Send;

    /// Process an inbound message from `from`.
    ///
    /// # Errors
    /// Returns an error if the message is invalid, out-of-order, or from an unknown sender.
    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()>;

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>>;
    fn is_done(&self) -> bool;

    /// Consume the state machine and return the protocol output.
    ///
    /// # Errors
    /// Returns an error if the protocol did not complete successfully.
    fn finish(self) -> tecdsa_core::Result<Self::Output>;

    fn current_round(&self) -> u16;
    fn ia_report(&self) -> Option<&IaReport>;
}
