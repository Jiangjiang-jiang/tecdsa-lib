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

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()>;

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>>;
    fn is_done(&self) -> bool;

    fn finish(self) -> tecdsa_core::Result<Self::Output>;

    fn current_round(&self) -> u16;
    fn ia_report(&self) -> Option<&IaReport>;
}
