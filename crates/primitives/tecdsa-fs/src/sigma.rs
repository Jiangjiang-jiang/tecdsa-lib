use rand_core::CryptoRngCore;

use crate::TranscriptProtocol;

pub trait SigmaRelation {
    type Statement;
    type Witness;
    type Commitment;
    type Response;

    fn commit(
        stmt: &Self::Statement,
        wit: &Self::Witness,
        rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Vec<u8>);

    fn challenge_bytes(
        stmt: &Self::Statement,
        com: &Self::Commitment,
        transcript: &mut impl TranscriptProtocol,
    ) -> Vec<u8>;

    fn respond(
        stmt: &Self::Statement,
        wit: &Self::Witness,
        prover_state: Vec<u8>,
        challenge: &[u8],
    ) -> Self::Response;

    fn verify(
        stmt: &Self::Statement,
        com: &Self::Commitment,
        challenge: &[u8],
        resp: &Self::Response,
    ) -> bool;
}
