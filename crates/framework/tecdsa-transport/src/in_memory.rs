// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-memory network for deterministic, single-threaded protocol testing.

use std::collections::{BTreeMap, HashMap};

use tecdsa_protocol::PartyId;

use crate::Transport;

/// Per-party communication metrics.
#[derive(Debug, Clone, Default)]
pub struct NetworkPartyMetrics {
    /// Total bytes sent by this party.
    pub bytes_sent: usize,
    /// Total bytes received by this party.
    pub bytes_received: usize,
    /// Total messages sent by this party.
    pub messages_sent: usize,
    /// Total messages received by this party.
    pub messages_received: usize,
}

/// Aggregate communication metrics for the entire network.
#[derive(Debug, Clone, Default)]
pub struct NetworkMetrics {
    /// Metrics broken down by party index.
    pub per_party: BTreeMap<u16, NetworkPartyMetrics>,
    /// Total bytes transferred across all sends/broadcasts.
    pub total_bytes: usize,
    /// Total messages transferred across all sends/broadcasts.
    pub total_messages: usize,
}

/// A fully in-process network with per-party mailboxes.
///
/// All message delivery is synchronous and lossless.  Use this for unit tests
/// and Known-Answer-Test (KAT) runners where determinism matters.
pub struct InMemoryNetwork {
    n: u16,
    mailboxes: HashMap<u16, Vec<(PartyId, Vec<u8>)>>,
    metrics: NetworkMetrics,
}

impl InMemoryNetwork {
    /// Create a new network for `n` parties (indices `0..n`).
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

    /// Create a new network from explicit party IDs.
    ///
    /// Unlike [`new`](Self::new), which assumes 0-based party indices,
    /// this constructor creates mailboxes keyed by the actual `PartyId`
    /// values (e.g., 1-based or arbitrary).
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

    /// Return the number of parties in the network.
    #[must_use]
    pub fn party_count(&self) -> u16 {
        self.n
    }

    /// Return accumulated communication metrics.
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
        // Track metrics.
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
        // Collect mailbox keys first to avoid borrow conflicts.
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
