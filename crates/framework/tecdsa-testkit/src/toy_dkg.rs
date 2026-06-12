use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tecdsa_protocol::{abort::IaReport, Outgoing, PartyId, Recipient, StateMachine};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ToyDkgMsg {
    Commitment([u8; 32]),
    Reveal(Vec<u8>),
}

pub struct ToyDkgMachine {
    #[allow(dead_code)]
    me: PartyId,
    n: u16,
    round: u16,
    secret: Vec<u8>,
    commitment: [u8; 32],
    commitments: HashMap<u16, [u8; 32]>,
    reveals: HashMap<u16, Vec<u8>>,
    outbox: Vec<Outgoing<ToyDkgMsg>>,
    done: bool,
    result: Option<Vec<u8>>,
}

impl ToyDkgMachine {
    #[must_use]
    pub fn new(me: PartyId, n: u16) -> Self {
        let secret = format!("secret-from-{}", me.0).into_bytes();
        let commitment: [u8; 32] = Sha256::digest(&secret).into();
        let outbox = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: ToyDkgMsg::Commitment(commitment),
        }];
        Self {
            me,
            n,
            round: 1,
            secret,
            commitment,
            commitments: HashMap::new(),
            reveals: HashMap::new(),
            outbox,
            done: false,
            result: None,
        }
    }
}

impl StateMachine for ToyDkgMachine {
    type Output = Vec<u8>;
    type Inbound = ToyDkgMsg;
    type Outbound = ToyDkgMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match msg {
            ToyDkgMsg::Commitment(c) => {
                self.commitments.insert(from.0, c);
                if self.commitments.len() == (self.n - 1) as usize && self.round == 1 {
                    self.round = 2;
                    self.outbox.push(Outgoing {
                        to: Recipient::Broadcast,
                        msg: ToyDkgMsg::Reveal(self.secret.clone()),
                    });
                }
            }
            ToyDkgMsg::Reveal(r) => {
                let expected: [u8; 32] = Sha256::digest(&r).into();
                if let Some(com) = self.commitments.get(&from.0) {
                    if *com == expected {
                        self.reveals.insert(from.0, r);
                    }
                }
                if self.reveals.len() == (self.n - 1) as usize && self.round == 2 {
                    let mut all_secrets: Vec<Vec<u8>> = self.reveals.values().cloned().collect();
                    all_secrets.push(self.secret.clone());
                    all_secrets.sort();
                    let combined: Vec<u8> = Sha256::digest(all_secrets.concat()).to_vec();
                    self.result = Some(combined);
                    self.done = true;
                }
            }
        }
        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        std::mem::take(&mut self.outbox)
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.result
            .ok_or_else(|| tecdsa_core::TecdsaError::Abort("toy DKG not done".into()))
    }

    fn current_round(&self) -> u16 {
        self.round
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

impl ToyDkgMachine {
    #[must_use]
    pub fn own_commitment(&self) -> [u8; 32] {
        self.commitment
    }
}
