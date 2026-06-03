// SPDX-License-Identifier: MIT OR Apache-2.0
use rand_core::CryptoRngCore;

use crate::TranscriptProtocol;

/// A Sigma (three-move) protocol relation.
///
/// Implementors define the statement/witness pair and the three moves:
/// commit → challenge → respond, plus a verification check.
pub trait SigmaRelation {
    /// The public statement (e.g. a group element or ciphertext).
    type Statement;
    /// The secret witness (e.g. a scalar or plaintext).
    type Witness;
    /// The prover's commitment sent in the first move.
    type Commitment;
    /// The prover's response sent in the third move.
    type Response;

    /// First move: generate a commitment and return an opaque prover state.
    ///
    /// The prover state is passed back verbatim to `respond` and must not
    /// be revealed to the verifier.
    fn commit(
        stmt: &Self::Statement,
        wit: &Self::Witness,
        rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Vec<u8>);

    /// Derive the challenge bytes by feeding the statement and commitment into
    /// the transcript and squeezing.
    fn challenge_bytes(
        stmt: &Self::Statement,
        com: &Self::Commitment,
        transcript: &mut impl TranscriptProtocol,
    ) -> Vec<u8>;

    /// Third move: compute the response given the prover state and challenge.
    fn respond(
        stmt: &Self::Statement,
        wit: &Self::Witness,
        prover_state: Vec<u8>,
        challenge: &[u8],
    ) -> Self::Response;

    /// Verify a (commitment, challenge, response) triple against the statement.
    fn verify(
        stmt: &Self::Statement,
        com: &Self::Commitment,
        challenge: &[u8],
        resp: &Self::Response,
    ) -> bool;
}
