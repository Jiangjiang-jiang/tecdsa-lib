// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    party::PartyId,
    session::{SessionConfig, SessionId},
};

#[derive(Debug, Clone)]
pub struct TranscriptContext {
    pub protocol: &'static str,
    pub phase: &'static str,
    pub session_id: SessionId,
    /// The party that produced the proof (prover/sender), NOT the local verifier.
    /// Both prover and verifier must set this to the prover's ID for transcript
    /// consistency.
    pub prover_id: Option<PartyId>,
    pub counterparty: Option<PartyId>,
    pub round: u16,
    /// Relation label (e.g. `b"R_enc"`, `b"R_cl_dl"`). Must be set explicitly;
    /// there is no default.
    pub label: &'static [u8],
}

impl TranscriptContext {
    /// Encode as a deterministic byte prefix for SHA-256 challenge derivation.
    ///
    /// Format: each field is length-prefixed (2-byte LE length + bytes).
    /// Fields are written in struct order for deterministic output.
    pub fn to_challenge_prefix(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        fn write_field(buf: &mut Vec<u8>, data: &[u8]) {
            buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
            buf.extend_from_slice(data);
        }

        write_field(&mut buf, self.protocol.as_bytes());
        write_field(&mut buf, self.phase.as_bytes());
        write_field(&mut buf, &self.session_id.0);
        match self.prover_id {
            Some(pid) => {
                buf.push(1);
                buf.extend_from_slice(&pid.0.to_le_bytes());
            }
            None => buf.push(0),
        }
        match self.counterparty {
            Some(pid) => {
                buf.push(1);
                buf.extend_from_slice(&pid.0.to_le_bytes());
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&self.round.to_le_bytes());
        write_field(&mut buf, self.label);

        buf
    }

    /// Create a context for deterministic benchmarks (fixed session, no party).
    pub fn for_benchmark(
        protocol: &'static str,
        phase: &'static str,
        round: u16,
        label: &'static [u8],
    ) -> Self {
        Self {
            protocol,
            phase,
            session_id: SessionId([0u8; 32]),
            prover_id: None,
            counterparty: None,
            round,
            label,
        }
    }

    /// Derive from an existing SessionConfig.
    ///
    /// `prover_id` is NOT set automatically — the caller must set it via
    /// [`with_prover`](Self::with_prover) to ensure both prover and verifier
    /// use the same transcript.
    pub fn with_session(
        config: &SessionConfig,
        protocol: &'static str,
        phase: &'static str,
        round: u16,
        label: &'static [u8],
    ) -> Self {
        Self {
            protocol,
            phase,
            session_id: config.session_id.clone(),
            prover_id: None,
            counterparty: None,
            round,
            label,
        }
    }

    /// Set the prover/origin party for this transcript context.
    #[must_use]
    pub fn with_prover(mut self, prover: PartyId) -> Self {
        self.prover_id = Some(prover);
        self
    }

    /// Set counterparty for point-to-point proof contexts.
    #[must_use]
    pub fn with_counterparty(mut self, counterparty: PartyId) -> Self {
        self.counterparty = Some(counterparty);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_deterministic() {
        let ctx1 = TranscriptContext::for_benchmark("CGGMP20", "presign", 1, b"R_enc");
        let ctx2 = TranscriptContext::for_benchmark("CGGMP20", "presign", 1, b"R_enc");
        assert_eq!(ctx1.to_challenge_prefix(), ctx2.to_challenge_prefix());
    }

    #[test]
    fn different_protocol_gives_different_prefix() {
        let a = TranscriptContext::for_benchmark("CGGMP20", "presign", 1, b"R_enc");
        let b = TranscriptContext::for_benchmark("GG18", "presign", 1, b"R_enc");
        assert_ne!(a.to_challenge_prefix(), b.to_challenge_prefix());
    }

    #[test]
    fn different_phase_gives_different_prefix() {
        let a = TranscriptContext::for_benchmark("CGGMP20", "presign", 1, b"R_enc");
        let b = TranscriptContext::for_benchmark("CGGMP20", "keygen", 1, b"R_enc");
        assert_ne!(a.to_challenge_prefix(), b.to_challenge_prefix());
    }

    #[test]
    fn different_round_gives_different_prefix() {
        let a = TranscriptContext::for_benchmark("CGGMP20", "presign", 1, b"R_enc");
        let b = TranscriptContext::for_benchmark("CGGMP20", "presign", 2, b"R_enc");
        assert_ne!(a.to_challenge_prefix(), b.to_challenge_prefix());
    }

    #[test]
    fn different_label_gives_different_prefix() {
        let a = TranscriptContext::for_benchmark("X", "p", 1, b"R_enc");
        let b = TranscriptContext::for_benchmark("X", "p", 1, b"R_cl_dl");
        assert_ne!(a.to_challenge_prefix(), b.to_challenge_prefix());
    }

    #[test]
    fn different_session_gives_different_prefix() {
        let a = TranscriptContext {
            session_id: SessionId([1u8; 32]),
            ..TranscriptContext::for_benchmark("X", "p", 1, b"R_enc")
        };
        let b = TranscriptContext {
            session_id: SessionId([2u8; 32]),
            ..TranscriptContext::for_benchmark("X", "p", 1, b"R_enc")
        };
        assert_ne!(a.to_challenge_prefix(), b.to_challenge_prefix());
    }

    #[test]
    fn different_prover_gives_different_prefix() {
        let a = TranscriptContext::for_benchmark("X", "p", 1, b"R_enc").with_prover(PartyId(1));
        let b = TranscriptContext::for_benchmark("X", "p", 1, b"R_enc").with_prover(PartyId(2));
        assert_ne!(a.to_challenge_prefix(), b.to_challenge_prefix());
    }

    #[test]
    fn with_counterparty_changes_prefix() {
        let base = TranscriptContext::for_benchmark("X", "p", 1, b"R_enc");
        let with_cp = base.clone().with_counterparty(PartyId(3));
        assert_ne!(base.to_challenge_prefix(), with_cp.to_challenge_prefix());
    }

    #[test]
    fn with_session_does_not_set_prover() {
        let config = SessionConfig {
            session_id: SessionId([42u8; 32]),
            local_party: crate::party::PartyInfo {
                id: PartyId(5),
                index: 5,
                total: 10,
                threshold: 3,
            },
            parties: vec![],
        };
        let ctx = TranscriptContext::with_session(&config, "TX25", "presign", 2, b"R_enc");
        assert_eq!(ctx.protocol, "TX25");
        assert!(ctx.prover_id.is_none());
        assert_eq!(ctx.session_id.0, [42u8; 32]);
        assert_eq!(ctx.round, 2);
        assert_eq!(ctx.label, b"R_enc");
    }

    #[test]
    fn prover_verifier_same_transcript() {
        let config = SessionConfig {
            session_id: SessionId([99u8; 32]),
            local_party: crate::party::PartyInfo {
                id: PartyId(1),
                index: 1,
                total: 3,
                threshold: 2,
            },
            parties: vec![PartyId(1), PartyId(2), PartyId(3)],
        };
        let prover_ctx = TranscriptContext::with_session(&config, "TX25", "presign", 1, b"R_enc")
            .with_prover(PartyId(1));

        let verifier_config = SessionConfig {
            local_party: crate::party::PartyInfo {
                id: PartyId(2),
                ..config.local_party
            },
            ..config
        };
        let verifier_ctx =
            TranscriptContext::with_session(&verifier_config, "TX25", "presign", 1, b"R_enc")
                .with_prover(PartyId(1));

        assert_eq!(
            prover_ctx.to_challenge_prefix(),
            verifier_ctx.to_challenge_prefix()
        );
    }

    #[test]
    fn prefix_not_empty() {
        let ctx = TranscriptContext::for_benchmark("X", "p", 0, b"R_test");
        assert!(!ctx.to_challenge_prefix().is_empty());
    }
}
