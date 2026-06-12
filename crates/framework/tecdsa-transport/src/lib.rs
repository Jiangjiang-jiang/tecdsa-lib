#![doc = "Transport trait and in-memory adapter for the tecdsa threshold ECDSA library."]

pub mod in_memory;
pub mod netsim;

pub use in_memory::{InMemoryNetwork, NetworkMetrics, NetworkPartyMetrics};
use tecdsa_protocol::PartyId;

pub trait Transport {
    fn send(&mut self, from: PartyId, to: PartyId, data: Vec<u8>);

    fn broadcast(&mut self, from: PartyId, data: Vec<u8>);

    fn receive(&mut self, party: PartyId) -> Vec<(PartyId, Vec<u8>)>;
}
