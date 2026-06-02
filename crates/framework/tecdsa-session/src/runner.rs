// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transport-agnostic protocol runner that drives a [`StateMachine`] through
//! its round lifecycle, encoding outgoing messages and decoding/validating
//! incoming ones via the [`tecdsa_wire`] envelope format.

use std::collections::{HashMap, HashSet};

use tecdsa_protocol::state_machine::{Outgoing, Recipient};
use tecdsa_protocol::{PartyId, StateMachine};
use tecdsa_wire::Header;

use crate::config::SessionRunConfig;
use crate::error::SessionError;
use crate::metrics::SessionMetrics;

/// Core protocol loop driver.
///
/// `SessionRunner` handles wire encoding/decoding and header validation but
/// does **not** own a transport -- callers are responsible for moving bytes
/// between parties.
pub(crate) struct SessionRunner<M>
where
    M: StateMachine,
    M::Outbound: serde::Serialize,
    M::Inbound: serde::de::DeserializeOwned,
{
    pub(crate) machine: M,
    session_id: [u8; 32],
    my_id: PartyId,
    #[allow(dead_code)]
    parties: Vec<PartyId>,
    pub(crate) config: SessionRunConfig,
    #[allow(dead_code)]
    current_round_num: u16,
    future_buffer: HashMap<u16, Vec<(PartyId, M::Inbound)>>,
    /// Tracks `(from, round, to)` triples to detect duplicate wire messages.
    /// The `to` field distinguishes broadcast (0xFFFF) from P2P messages.
    seen: HashSet<(u16, u16, u16)>,
    pub(crate) metrics: SessionMetrics,
}

impl<M> SessionRunner<M>
where
    M: StateMachine,
    M::Outbound: serde::Serialize,
    M::Inbound: serde::de::DeserializeOwned,
{
    /// Create a new `SessionRunner`.
    pub(crate) fn new(
        machine: M,
        session_id: [u8; 32],
        my_id: PartyId,
        parties: Vec<PartyId>,
        config: SessionRunConfig,
    ) -> Self {
        let current_round_num = machine.current_round();
        Self {
            machine,
            session_id,
            my_id,
            parties,
            config,
            current_round_num,
            future_buffer: HashMap::new(),
            seen: HashSet::new(),
            metrics: SessionMetrics::default(),
        }
    }

    /// Drain outgoing messages from the state machine, encode them into wire
    /// format, and return `(Recipient, bytes)` pairs for the caller to deliver.
    pub(crate) fn step_encode(&mut self) -> Result<Vec<(Recipient, Vec<u8>)>, SessionError> {
        let outgoing: Vec<Outgoing<M::Outbound>> = self.machine.drain_outgoing();
        let mut result = Vec::with_capacity(outgoing.len());

        for out in outgoing {
            let to_field = match &out.to {
                Recipient::Party(p) => p.0,
                Recipient::Broadcast => 0xFFFF,
            };
            let header = Header {
                session_id: self.session_id,
                protocol_id: self.config.protocol_id,
                round: self.machine.current_round(),
                from: self.my_id.0,
                to: to_field,
            };
            let bytes = tecdsa_wire::encode(&header, &out.msg)
                .map_err(|e| SessionError::Wire(e.to_string()))?;
            self.metrics.bytes_sent += bytes.len();
            self.metrics.messages_sent += 1;
            result.push((out.to, bytes));
        }

        Ok(result)
    }

    /// Decode and validate incoming wire messages, feeding them to the state
    /// machine.  Messages for future rounds are buffered; stale messages are
    /// discarded.
    pub(crate) fn step_decode(&mut self, raw: &[(PartyId, Vec<u8>)]) -> Result<(), SessionError> {
        for (from, bytes) in raw {
            self.metrics.bytes_received += bytes.len();
            self.metrics.messages_received += 1;

            let (header, msg): (Header, M::Inbound) =
                tecdsa_wire::decode(bytes).map_err(|e| SessionError::Wire(e.to_string()))?;

            // --- header validation ---
            if header.session_id != self.session_id {
                return Err(SessionError::InvalidHeader {
                    reason: format!(
                        "session_id mismatch: expected {:?}, got {:?}",
                        self.session_id, header.session_id
                    ),
                });
            }
            if header.from != from.0 {
                return Err(SessionError::InvalidHeader {
                    reason: format!(
                        "from mismatch: envelope says {}, header says {}",
                        from.0, header.from
                    ),
                });
            }
            if header.protocol_id != self.config.protocol_id {
                return Err(SessionError::InvalidHeader {
                    reason: format!(
                        "protocol_id mismatch: expected {}, got {}",
                        self.config.protocol_id, header.protocol_id
                    ),
                });
            }

            // duplicate detection -- include `to` to allow a party to send
            // both broadcast (to=0xFFFF) and P2P (to=specific) in the same round.
            if !self.seen.insert((header.from, header.round, header.to)) {
                return Err(SessionError::DuplicateMessage {
                    from: *from,
                    round: header.round,
                });
            }

            let current = self.machine.current_round();
            let is_two_party_p2p = self.parties.len() == 2 && header.to != 0xFFFF;
            if header.round == current || (is_two_party_p2p && header.round > current) {
                self.machine
                    .handle(*from, msg)
                    .map_err(SessionError::Protocol)?;
            } else if header.round > current {
                self.future_buffer
                    .entry(header.round)
                    .or_default()
                    .push((*from, msg));
            }
            // header.round < current => stale, silently discard
        }

        // Drain buffered messages that now match the (possibly advanced) current round.
        let current = self.machine.current_round();
        if let Some(buffered) = self.future_buffer.remove(&current) {
            for (from, msg) in buffered {
                self.machine
                    .handle(from, msg)
                    .map_err(SessionError::Protocol)?;
            }
        }

        self.current_round_num = self.machine.current_round();
        Ok(())
    }

    /// Whether the underlying state machine has completed.
    pub(crate) fn is_done(&self) -> bool {
        self.machine.is_done()
    }

    /// Consume the runner and return the protocol output.
    pub(crate) fn finish(self) -> Result<M::Output, SessionError> {
        self.machine.finish().map_err(SessionError::Protocol)
    }

    /// Current round number as reported by the state machine.
    pub(crate) fn current_round(&self) -> u16 {
        self.machine.current_round()
    }
}
