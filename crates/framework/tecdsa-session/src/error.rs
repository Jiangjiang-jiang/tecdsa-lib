use std::time::Duration;

use tecdsa_core::TecdsaError;
use tecdsa_protocol::{IaReport, PartyId};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("protocol error: {0}")]
    Protocol(#[from] TecdsaError),

    #[error("wire encode/decode error: {0}")]
    Wire(String),

    #[error("transport failure: {0}")]
    TransportFailure(String),

    #[error("round {round} timed out after {timeout:?}")]
    RoundTimeout { round: u16, timeout: Duration },

    #[error("exceeded maximum {0} rounds")]
    MaxRoundsExceeded(u16),

    #[error("invalid header: {reason}")]
    InvalidHeader { reason: String },

    #[error("parties {parties:?} unresponsive in round {round}")]
    PartyUnresponsive { parties: Vec<PartyId>, round: u16 },

    #[error("protocol abort: {0:?}")]
    ProtocolAbort(IaReport),

    #[error("duplicate message from party {from} in round {round}")]
    DuplicateMessage { from: PartyId, round: u16 },
}
