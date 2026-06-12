use serde::{Deserialize, Serialize};

use crate::party::PartyId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IaReport {
    pub blamed: Vec<PartyId>,
    pub reason: AbortReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AbortReason {
    InvalidProof { round: u16, party: PartyId },
    InvalidCommitment { round: u16, party: PartyId },
    MissingMessage { round: u16, party: PartyId },
    EquivocationDetected { party: PartyId },
    ProtocolSpecific(String),
}
