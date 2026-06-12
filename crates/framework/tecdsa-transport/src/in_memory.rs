use std::collections::{BTreeMap, HashMap};

use tecdsa_protocol::PartyId;

use crate::Transport;

#[derive(Debug, Clone, Default)]
pub struct NetworkPartyMetrics {
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub messages_sent: usize,
    pub messages_received: usize,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkMetrics {
    pub per_party: BTreeMap<u16, NetworkPartyMetrics>,
    pub total_bytes: usize,
    pub total_messages: usize,
}

pub struct InMemoryNetwork {
    n: u16,
    mailboxes: HashMap<u16, Vec<(PartyId, Vec<u8>)>>,
    metrics: NetworkMetrics,
}

impl InMemoryNetwork {
    #[must_use]
    pub fn new(n: u16) -> Self {
        let mut mailboxes = HashMap::new();
        for i in 0..n {
            mailboxes.insert(i, Vec::new());
        }
        Self {
            n,
            mailboxes,
            metrics: NetworkMetrics::default(),
        }
    }

    #[must_use]
    pub fn from_party_ids(party_ids: &[PartyId]) -> Self {
        let mut mailboxes = HashMap::new();
        for pid in party_ids {
            mailboxes.insert(pid.0, Vec::new());
        }
        Self {
            n: party_ids.len() as u16,
            mailboxes,
            metrics: NetworkMetrics::default(),
        }
    }

    #[must_use]
    pub fn party_count(&self) -> u16 {
        self.n
    }

    #[must_use]
    pub fn metrics(&self) -> &NetworkMetrics {
        &self.metrics
    }
}

impl Transport for InMemoryNetwork {
    fn send(&mut self, from: PartyId, to: PartyId, data: Vec<u8>) {
        let len = data.len();
        if let Some(mb) = self.mailboxes.get_mut(&to.0) {
            mb.push((from, data));
        }
        self.metrics.total_bytes += len;
        self.metrics.total_messages += 1;
        self.metrics.per_party.entry(from.0).or_default().bytes_sent += len;
        self.metrics
            .per_party
            .entry(from.0)
            .or_default()
            .messages_sent += 1;
        self.metrics
            .per_party
            .entry(to.0)
            .or_default()
            .bytes_received += len;
        self.metrics
            .per_party
            .entry(to.0)
            .or_default()
            .messages_received += 1;
    }

    fn broadcast(&mut self, from: PartyId, data: Vec<u8>) {
        let len = data.len();
        let keys: Vec<u16> = self.mailboxes.keys().copied().collect();
        let n_recipients = keys.iter().filter(|&&k| k != from.0).count();
        for key in keys {
            if key != from.0 {
                if let Some(mb) = self.mailboxes.get_mut(&key) {
                    mb.push((from, data.clone()));
                }
                self.metrics
                    .per_party
                    .entry(key)
                    .or_default()
                    .bytes_received += len;
                self.metrics
                    .per_party
                    .entry(key)
                    .or_default()
                    .messages_received += 1;
            }
        }
        self.metrics.total_bytes += len * n_recipients;
        self.metrics.total_messages += n_recipients;
        self.metrics.per_party.entry(from.0).or_default().bytes_sent += len * n_recipients;
        self.metrics
            .per_party
            .entry(from.0)
            .or_default()
            .messages_sent += n_recipients;
    }

    fn receive(&mut self, party: PartyId) -> Vec<(PartyId, Vec<u8>)> {
        self.mailboxes
            .get_mut(&party.0)
            .map(std::mem::take)
            .unwrap_or_default()
    }
}
