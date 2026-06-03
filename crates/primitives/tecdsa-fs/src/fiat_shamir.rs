// SPDX-License-Identifier: MIT OR Apache-2.0
use rand_core::CryptoRngCore;

use crate::{MerlinTranscript, SigmaRelation};

/// A non-interactive proof produced by the Fiat-Shamir transform of a
/// [`SigmaRelation`].
pub struct FiatShamirProof<R: SigmaRelation> {
    /// The prover's first-move commitment.
    pub commitment: R::Commitment,
    /// The prover's third-move response.
    pub response: R::Response,
    /// The challenge derived from the transcript (cached for verification).
    challenge: Vec<u8>,
}

impl<R: SigmaRelation> FiatShamirProof<R> {
    /// Prove knowledge of `wit` for `stmt` under domain label `domain`.
    pub fn prove(
        stmt: &R::Statement,
        wit: &R::Witness,
        domain: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let (commitment, prover_state) = R::commit(stmt, wit, rng);
        let mut transcript = MerlinTranscript::new_dynamic(domain);
        let challenge = R::challenge_bytes(stmt, &commitment, &mut transcript);
        let response = R::respond(stmt, wit, prover_state, &challenge);
        Self {
            commitment,
            response,
            challenge,
        }
    }

    /// Verify this proof for `stmt` under domain label `domain`.
    pub fn verify(&self, stmt: &R::Statement, domain: &[u8]) -> bool {
        let mut transcript = MerlinTranscript::new_dynamic(domain);
        let challenge = R::challenge_bytes(stmt, &self.commitment, &mut transcript);
        if challenge != self.challenge {
            return false;
        }
        R::verify(stmt, &self.commitment, &challenge, &self.response)
    }
}
