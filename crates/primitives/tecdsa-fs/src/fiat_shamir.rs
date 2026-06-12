use rand_core::CryptoRngCore;

use crate::{MerlinTranscript, SigmaRelation};

pub struct FiatShamirProof<R: SigmaRelation> {
    pub commitment: R::Commitment,
    pub response: R::Response,
    challenge: Vec<u8>,
}

impl<R: SigmaRelation> FiatShamirProof<R> {
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

    pub fn verify(&self, stmt: &R::Statement, domain: &[u8]) -> bool {
        let mut transcript = MerlinTranscript::new_dynamic(domain);
        let challenge = R::challenge_bytes(stmt, &self.commitment, &mut transcript);
        if challenge != self.challenge {
            return false;
        }
        R::verify(stmt, &self.commitment, &challenge, &self.response)
    }
}
