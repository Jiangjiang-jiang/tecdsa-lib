use std::time::Duration;

use tecdsa_protocol::PartyId;

#[async_trait::async_trait]
pub trait AsyncTransport: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn send(&mut self, from: PartyId, to: PartyId, data: Vec<u8>) -> Result<(), Self::Error>;

    async fn broadcast(&mut self, from: PartyId, data: Vec<u8>) -> Result<(), Self::Error>;

    async fn receive(
        &mut self,
        party: PartyId,
        timeout: Duration,
    ) -> Result<Vec<(PartyId, Vec<u8>)>, Self::Error>;
}
