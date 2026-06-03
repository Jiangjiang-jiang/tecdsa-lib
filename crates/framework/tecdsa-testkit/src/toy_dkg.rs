// SPDX-License-Identifier: MIT OR Apache-2.0
//! Toy 3-party commit-reveal DKG used to validate the `StateMachine` + `Orchestrator` framework.
//!
//! This is **not** a real DKG.  It is a deliberately minimal protocol whose only
//! purpose is to exercise every code path in [`crate::Orchestrator`]:
//!
//! - Round 1 — each party broadcasts a SHA-256 *commitment* to its secret.
//! - Round 2 — after collecting all commitments, each party broadcasts the *reveal*.
//! - Finish — after verifying all reveals, each party derives a shared "public key"
//!   by hashing the sorted secrets.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tecdsa_protocol::{abort::IaReport, Outgoing, PartyId, Recipient, StateMachine};

/// Protocol message for the toy DKG.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ToyDkgMsg {
    /// A SHA-256 commitment to the sender's secret.
    Commitment([u8; 32]),
    /// The revealed secret (must hash to the previously-sent commitment).
    Reveal(Vec<u8>),
}

// The `Orchestrator` requires `M::Outbound: Into<M::Inbound>`.  Since
// `Outbound = Inbound = ToyDkgMsg` this is satisfied by the blanket
// `impl<T> From<T> for T` from `core` — no explicit impl needed.

/// State machine for the toy commit-reveal DKG.
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
    /// Create a new machine for party `me` in an `n`-party session.
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
                // Once we have all n-1 commitments we advance to round 2.
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
                // Once we have all n-1 verified reveals we can compute the result.
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

// Suppress unused-field warning for `commitment` — it's stored for potential
// future self-verification but not read back inside this module.
impl ToyDkgMachine {
    /// Returns the party's own commitment (SHA-256 of its secret).
    #[must_use]
    pub fn own_commitment(&self) -> [u8; 32] {
        self.commitment
    }
}
