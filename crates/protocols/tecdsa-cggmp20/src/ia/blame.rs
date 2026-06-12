use serde::{Deserialize, Serialize};
use tecdsa_protocol::PartyId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlameEvidence {
    InvalidEncProof {
        round: u16,
        party: PartyId,
        proof_type: String,
    },
    InvalidAffProof {
        round: u16,
        party: PartyId,
    },
    InconsistentDelta {
        party: PartyId,
    },
    InvalidModProof {
        party: PartyId,
    },
    InvalidFacProof {
        party: PartyId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameReport {
    pub faulty_parties: Vec<PartyId>,
    pub evidence: Vec<BlameEvidence>,
}
