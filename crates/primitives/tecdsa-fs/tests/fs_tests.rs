// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_fs::{FiatShamirProof, MerlinTranscript, SigmaRelation, TranscriptProtocol};

struct IdentityRelation;

impl SigmaRelation for IdentityRelation {
    type Statement = u64;
    type Witness = u64;
    type Commitment = u64;
    type Response = u64;

    fn commit(
        _stmt: &Self::Statement,
        _wit: &Self::Witness,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> (Self::Commitment, Vec<u8>) {
        let r: u64 = rand_core::RngCore::next_u64(rng);
        (r, r.to_le_bytes().to_vec())
    }

    fn challenge_bytes(
        stmt: &Self::Statement,
        com: &Self::Commitment,
        transcript: &mut impl TranscriptProtocol,
    ) -> Vec<u8> {
        transcript.append_message(b"stmt", &stmt.to_le_bytes());
        transcript.append_message(b"com", &com.to_le_bytes());
        transcript.challenge_bytes(b"chal", 8)
    }

    fn respond(
        _stmt: &Self::Statement,
        wit: &Self::Witness,
        prover_state: Vec<u8>,
        challenge: &[u8],
    ) -> Self::Response {
        let r = u64::from_le_bytes(prover_state.try_into().unwrap());
        let c = u64::from_le_bytes(challenge[..8].try_into().unwrap());
        r.wrapping_add(c.wrapping_mul(*wit))
    }

    fn verify(
        stmt: &Self::Statement,
        com: &Self::Commitment,
        challenge: &[u8],
        resp: &Self::Response,
    ) -> bool {
        let c = u64::from_le_bytes(challenge[..8].try_into().unwrap());
        *resp == com.wrapping_add(c.wrapping_mul(*stmt))
    }
}

#[test]
fn fiat_shamir_roundtrip_honest() {
    let mut rng = rand::thread_rng();
    let stmt = 42u64;
    let wit = 42u64;
    let proof = FiatShamirProof::<IdentityRelation>::prove(&stmt, &wit, b"test-domain", &mut rng);
    assert!(proof.verify(&stmt, b"test-domain"));
}

#[test]
fn fiat_shamir_rejects_wrong_statement() {
    let mut rng = rand::thread_rng();
    let stmt = 42u64;
    let wit = 42u64;
    let proof = FiatShamirProof::<IdentityRelation>::prove(&stmt, &wit, b"test-domain", &mut rng);
    assert!(!proof.verify(&99u64, b"test-domain"));
}

#[test]
fn transcript_domain_separation() {
    let mut t1 = MerlinTranscript::new_dynamic(b"domain-a");
    let mut t2 = MerlinTranscript::new_dynamic(b"domain-b");
    t1.append_message(b"x", &[1, 2, 3]);
    t2.append_message(b"x", &[1, 2, 3]);
    let c1 = t1.challenge_bytes(b"c", 32);
    let c2 = t2.challenge_bytes(b"c", 32);
    assert_ne!(c1, c2);
}
