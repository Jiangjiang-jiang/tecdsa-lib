// SPDX-License-Identifier: MIT OR Apache-2.0
//! Async session that owns both a `SessionRunner` and an [`AsyncTransport`],
//! driving the protocol to completion with `tokio`-based timeouts and retries.

use tecdsa_protocol::{state_machine::Recipient, PartyId, StateMachine};

use crate::{
    async_transport::AsyncTransport, config::SessionRunConfig, error::SessionError,
    metrics::SessionMetrics, runner::SessionRunner,
};

/// An async session that runs a protocol to completion.
///
/// `AsyncSession` combines a `SessionRunner` (wire encode/decode + validation)
/// with an [`AsyncTransport`] (async message delivery) to provide an
/// `async fn run()` API suitable for production deployment behind tokio.
///
/// Round-level timeouts are enforced via [`tokio::time::timeout`].
/// Transport failures are retried according to [`RetryPolicy`](crate::RetryPolicy)
/// with exponential backoff.
pub struct AsyncSession<M, T>
where
    M: StateMachine,
    M::Outbound: serde::Serialize,
    M::Inbound: serde::de::DeserializeOwned,
    T: AsyncTransport,
{
    runner: SessionRunner<M>,
    transport: T,
    my_id: PartyId,
}

impl<M, T> AsyncSession<M, T>
where
    M: StateMachine,
    M::Outbound: serde::Serialize,
    M::Inbound: serde::de::DeserializeOwned,
    T: AsyncTransport,
{
    /// Create a new `AsyncSession`.
    pub fn new(
        machine: M,
        transport: T,
        my_id: PartyId,
        parties: Vec<PartyId>,
        session_id: [u8; 32],
        config: SessionRunConfig,
    ) -> Self {
        let runner = SessionRunner::new(machine, session_id, my_id, parties, config);
        Self {
            runner,
            transport,
            my_id,
        }
    }

    /// Drive the protocol to completion asynchronously, returning the final
    /// output.
    ///
    /// Each iteration: drain outgoing messages (encode + send with retry),
    /// then receive and decode incoming messages (with round-level timeout).
    /// Loops until the state machine signals completion or the maximum round
    /// count is exceeded.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] on wire errors, header validation failures,
    /// duplicate messages, round timeouts, transport failures (after retries
    /// exhausted), or exceeding the maximum round count.
    pub async fn run(mut self) -> Result<M::Output, SessionError> {
        loop {
            // Encode + send with retry
            let encoded = self.runner.step_encode()?;
            for (recipient, bytes) in encoded {
                self.send_with_retry(&recipient, bytes).await?;
            }

            if self.runner.is_done() {
                return self.runner.finish();
            }
            let current_round = self.runner.current_round();
            if current_round >= self.runner.config.max_rounds {
                return Err(SessionError::MaxRoundsExceeded(
                    self.runner.config.max_rounds,
                ));
            }

            // Receive with round-level timeout + decode
            let round_timeout = self.runner.config.round_timeout;
            let raw = self.receive_with_timeout(round_timeout).await?;
            self.runner.step_decode(&raw)?;
        }
    }

    /// Send a single message with exponential-backoff retry.
    async fn send_with_retry(
        &mut self,
        recipient: &Recipient,
        bytes: Vec<u8>,
    ) -> Result<(), SessionError> {
        let max_retries = self.runner.config.retry_policy.max_retries;
        let base_delay = self.runner.config.retry_policy.base_delay;

        let mut last_err: Option<String> = None;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                let delay = base_delay * 2u32.saturating_pow(u32::from(attempt - 1));
                tokio::time::sleep(delay).await;
            }

            let result = match recipient {
                Recipient::Party(to) => self.transport.send(self.my_id, *to, bytes.clone()).await,
                Recipient::Broadcast => self.transport.broadcast(self.my_id, bytes.clone()).await,
            };

            match result {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = Some(e.to_string());
                }
            }
        }

        Err(SessionError::TransportFailure(format!(
            "send failed after {} retries: {}",
            max_retries,
            last_err.unwrap_or_default(),
        )))
    }

    /// Receive incoming messages with a round-level timeout.
    async fn receive_with_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<Vec<(PartyId, Vec<u8>)>, SessionError> {
        let round = self.runner.current_round();

        match tokio::time::timeout(timeout, self.transport.receive(self.my_id, timeout)).await {
            Ok(Ok(msgs)) => Ok(msgs),
            Ok(Err(e)) => Err(SessionError::TransportFailure(e.to_string())),
            Err(_elapsed) => Err(SessionError::RoundTimeout { round, timeout }),
        }
    }

    /// Access the current session metrics.
    pub fn metrics(&self) -> &SessionMetrics {
        &self.runner.metrics
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tecdsa_protocol::{IaReport, PartyId};

    use super::*;

    // --- Mock transport that never returns (for timeout test) ---

    struct NeverTransport;

    #[async_trait::async_trait]
    impl AsyncTransport for NeverTransport {
        type Error = Infallible;

        async fn send(
            &mut self,
            _from: PartyId,
            _to: PartyId,
            _data: Vec<u8>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn broadcast(&mut self, _from: PartyId, _data: Vec<u8>) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn receive(
            &mut self,
            _party: PartyId,
            _timeout: Duration,
        ) -> Result<Vec<(PartyId, Vec<u8>)>, Self::Error> {
            // Block forever
            std::future::pending().await
        }
    }

    // --- Mock transport that always fails sends (for retry test) ---

    #[derive(Debug)]
    struct MockSendError(String);
    impl std::fmt::Display for MockSendError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    impl std::error::Error for MockSendError {}

    struct FailingSendTransport {
        send_attempts: Arc<Mutex<u32>>,
    }

    #[async_trait::async_trait]
    impl AsyncTransport for FailingSendTransport {
        type Error = MockSendError;

        async fn send(
            &mut self,
            _from: PartyId,
            _to: PartyId,
            _data: Vec<u8>,
        ) -> Result<(), Self::Error> {
            let mut count = self.send_attempts.lock().unwrap();
            *count += 1;
            Err(MockSendError("connection refused".into()))
        }

        async fn broadcast(&mut self, _from: PartyId, _data: Vec<u8>) -> Result<(), Self::Error> {
            let mut count = self.send_attempts.lock().unwrap();
            *count += 1;
            Err(MockSendError("connection refused".into()))
        }

        async fn receive(
            &mut self,
            _party: PartyId,
            _timeout: Duration,
        ) -> Result<Vec<(PartyId, Vec<u8>)>, Self::Error> {
            Ok(vec![])
        }
    }

    // --- Minimal state machine for testing ---

    struct DoneAfterOneMachine {
        round: u16,
        done: bool,
    }

    impl DoneAfterOneMachine {
        fn new() -> Self {
            Self {
                round: 0,
                done: false,
            }
        }
    }

    impl StateMachine for DoneAfterOneMachine {
        type Inbound = ();
        type Outbound = ();
        type Output = ();

        fn handle(
            &mut self,
            _from: PartyId,
            _msg: Self::Inbound,
        ) -> Result<(), tecdsa_core::TecdsaError> {
            self.round = 1;
            self.done = true;
            Ok(())
        }

        fn drain_outgoing(
            &mut self,
        ) -> Vec<tecdsa_protocol::state_machine::Outgoing<Self::Outbound>> {
            vec![]
        }

        fn current_round(&self) -> u16 {
            self.round
        }

        fn is_done(&self) -> bool {
            self.done
        }

        fn finish(self) -> Result<Self::Output, tecdsa_core::TecdsaError> {
            Ok(())
        }

        fn ia_report(&self) -> Option<&IaReport> {
            None
        }
    }

    // --- The test machine that starts done immediately ---

    struct AlreadyDoneMachine;

    impl StateMachine for AlreadyDoneMachine {
        type Inbound = ();
        type Outbound = ();
        type Output = String;

        fn handle(
            &mut self,
            _from: PartyId,
            _msg: Self::Inbound,
        ) -> Result<(), tecdsa_core::TecdsaError> {
            Ok(())
        }

        fn drain_outgoing(
            &mut self,
        ) -> Vec<tecdsa_protocol::state_machine::Outgoing<Self::Outbound>> {
            vec![]
        }

        fn current_round(&self) -> u16 {
            0
        }

        fn is_done(&self) -> bool {
            true
        }

        fn finish(self) -> Result<Self::Output, tecdsa_core::TecdsaError> {
            Ok("completed".to_string())
        }

        fn ia_report(&self) -> Option<&IaReport> {
            None
        }
    }

    #[tokio::test]
    async fn async_session_completes_immediately_when_done() {
        let machine = AlreadyDoneMachine;
        let transport = NeverTransport;
        let session = AsyncSession::new(
            machine,
            transport,
            PartyId(1),
            vec![PartyId(1), PartyId(2)],
            [0u8; 32],
            SessionRunConfig::default(),
        );
        let result = session.run().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "completed");
    }

    #[tokio::test]
    async fn async_session_timeout() {
        let machine = DoneAfterOneMachine::new();
        let transport = NeverTransport;
        let config = SessionRunConfig {
            round_timeout: Duration::from_millis(50),
            ..SessionRunConfig::default()
        };
        let session = AsyncSession::new(
            machine,
            transport,
            PartyId(1),
            vec![PartyId(1), PartyId(2)],
            [0u8; 32],
            config,
        );

        let result = session.run().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::RoundTimeout { round, timeout } => {
                assert_eq!(round, 0);
                assert_eq!(timeout, Duration::from_millis(50));
            }
            other => panic!("expected RoundTimeout, got: {other}"),
        }
    }

    #[tokio::test]
    async fn async_session_retry_exhaustion() {
        let attempts = Arc::new(Mutex::new(0u32));
        let machine = AlreadyDoneSendingMachine;
        let transport = FailingSendTransport {
            send_attempts: Arc::clone(&attempts),
        };
        let config = SessionRunConfig {
            retry_policy: crate::config::RetryPolicy {
                max_retries: 2,
                base_delay: Duration::from_millis(1),
            },
            ..SessionRunConfig::default()
        };
        let session = AsyncSession::new(
            machine,
            transport,
            PartyId(1),
            vec![PartyId(1), PartyId(2)],
            [0u8; 32],
            config,
        );

        let result = session.run().await;
        assert!(result.is_err());
        match &result.unwrap_err() {
            SessionError::TransportFailure(msg) => {
                assert!(msg.contains("2 retries"), "msg was: {msg}");
                assert!(msg.contains("connection refused"), "msg was: {msg}");
            }
            other => panic!("expected TransportFailure, got: {other}"),
        }

        // 1 initial + 2 retries = 3 total attempts
        assert_eq!(*attempts.lock().unwrap(), 3);
    }

    /// A machine that is NOT done but emits one broadcast message.
    struct AlreadyDoneSendingMachine;

    impl StateMachine for AlreadyDoneSendingMachine {
        type Inbound = ();
        type Outbound = ();
        type Output = ();

        fn handle(
            &mut self,
            _from: PartyId,
            _msg: Self::Inbound,
        ) -> Result<(), tecdsa_core::TecdsaError> {
            Ok(())
        }

        fn drain_outgoing(
            &mut self,
        ) -> Vec<tecdsa_protocol::state_machine::Outgoing<Self::Outbound>> {
            vec![tecdsa_protocol::state_machine::Outgoing {
                to: Recipient::Broadcast,
                msg: (),
            }]
        }

        fn current_round(&self) -> u16 {
            0
        }

        fn is_done(&self) -> bool {
            false
        }

        fn finish(self) -> Result<Self::Output, tecdsa_core::TecdsaError> {
            Ok(())
        }

        fn ia_report(&self) -> Option<&IaReport> {
            None
        }
    }
}
