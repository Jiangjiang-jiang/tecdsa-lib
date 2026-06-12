use tecdsa_protocol::PartyId;

#[derive(Debug, Clone)]
pub enum Deviation {
    DropMessage {
        from: PartyId,
        to: PartyId,
        round: u16,
    },
    WrongCommitment { party: PartyId, round: u16 },
    BadZkProof { party: PartyId, round: u16 },
    ReorderRounds { party: PartyId },
    EquivocateBroadcast { party: PartyId, round: u16 },
}

#[derive(Debug, Default)]
pub struct DeviationPlan {
    pub deviations: Vec<Deviation>,
}

impl DeviationPlan {
    #[must_use]
    pub fn new() -> Self {
        Self {
            deviations: Vec::new(),
        }
    }

    #[must_use]
    pub fn with(mut self, d: Deviation) -> Self {
        self.deviations.push(d);
        self
    }

    #[must_use]
    pub fn should_drop(&self, from: PartyId, to: PartyId, round: u16) -> bool {
        self.deviations.iter().any(|d| {
            matches!(d,
                Deviation::DropMessage { from: f, to: t, round: r }
                if *f == from && *t == to && *r == round
            )
        })
    }
}
