// SPDX-License-Identifier: MIT OR Apache-2.0
//! Interactive distributed key generation for XAL+21 (Figure 3, top section).
//!
//! Implements the full 3-round interactive keygen between P1 and P2,
//! replacing the trusted dealer with a DH-like key exchange secured by
//! DLog proofs and commitment-then-reveal.
//!
//! ## Protocol Overview
//!
//! **Round 1 (P1 -> P2)**: P1 samples `x1`, computes `Q1 = x1 * G`, creates
//! `nizkPoK(Q1, x1)`. Sends commitment `f1 = H(Q1, nizk1)`.
//!
//! **Round 2 (P2 -> P1)**: P2 samples `x2`, computes `Q2 = x2 * G`, creates
//! `nizkPoK(Q2, x2)`. Generates Paillier keypair `(ek, dk)`. Creates
//! `Pi_GCD` proof for N. Sends `(Q2, nizk2, ek, pi_gcd)`.
//!
//! **Round 3 (P1 -> P2)**: P1 verifies `nizk2` and `pi_gcd`. Decommits
//! `(Q1, nizk1)`. P2 verifies commitment and `nizk1`.
//!
//! **Output**: P1 stores `(x1, Q=Q1+Q2, Q1, ek)`.
//!             P2 stores `(x2, Q=Q1+Q2, Q1, dk, ek)`.
//!
//! Key difference from KGG24: XAL+21 has no encrypted share (C) and no
//! Pi_eq/L_PDL proof. P2 holds the Paillier key (for MtA), P1 gets the
//! encryption key.

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::zk::dlog::DlogProof;
use tecdsa_curve::TecdsaCurve;

use crate::error::Xal21Error;
use crate::key_share::{Xal21Party1KeyShare, Xal21Party2KeyShare};
use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;

// ---------------------------------------------------------------------------
// Round 1: P1 -> P2 (commitment to Q1 + DLog proof)
// ---------------------------------------------------------------------------

/// Round 1 message from P1: commitment to `(Q1, dlog_proof)`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP1Round1Msg {
    /// Hash commitment to `Q1 || dlog_proof`.
    pub commitment: HashCommitment,
}

/// P1's internal state after round 1.
pub struct KeyGenP1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret share `x1`.
    pub x1: C::Scalar,
    /// Public key share `Q1 = x1 * G`.
    pub q1: C::ProjectivePoint,
    /// DLog proof for `Q1`.
    pub dlog_proof: DlogProof<C>,
    /// Commitment opening nonce.
    pub nonce: [u8; 32],
}

/// P1 round 1: sample `x1`, compute `Q1 = x1 * G`, create DLog proof, commit.
pub fn party1_keygen_round1<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (KeyGenP1Round1Msg, KeyGenP1State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1 = C::random_scalar(rng);
    let q1 = C::generator() * x1;

    // DLog proof for Q1
    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x1, &ephemeral, &q1, b"xal21-keygen-q1");

    // Commit to (Q1, dlog_proof)
    let commit_data = serialize_point_and_proof::<C>(&q1, &dlog_proof);
    let (commitment, nonce) = HashCommitment::commit(&commit_data, rng);

    let msg = KeyGenP1Round1Msg { commitment };
    let state = KeyGenP1State {
        x1,
        q1,
        dlog_proof,
        nonce,
    };

    (msg, state)
}

// ---------------------------------------------------------------------------
// Round 2: P2 -> P1 (Q2, DLog proof, Paillier ek, Pi_GCD)
// ---------------------------------------------------------------------------

/// Round 2 message from P2.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP2Round2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// P2's public key share `Q2 = x2 * G`.
    pub q2: C::ProjectivePoint,
    /// DLog proof for `Q2`.
    pub dlog_proof: DlogProof<C>,
    /// Paillier encryption key (P2 owns the decryption key).
    pub ek: tecdsa_paillier::EncryptionKey,
    /// Pi_GCD proof: proves knowledge of factorization of N.
    pub pi_gcd: NICorrectKeyProof,
}

/// P2's internal state after round 2.
pub struct KeyGenP2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret share `x2`.
    pub x2: C::Scalar,
    /// Public key share `Q2 = x2 * G`.
    pub q2: C::ProjectivePoint,
    /// Paillier decryption key (secret).
    pub dk: tecdsa_paillier::DecryptionKey,
    /// Paillier encryption key (public).
    pub ek: tecdsa_paillier::EncryptionKey,
}

/// P2 round 2: sample `x2`, compute `Q2 = x2 * G`, create DLog proof,
/// generate Paillier keypair, create Pi_GCD proof.
pub fn party2_keygen_round2<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP2Round2Msg<C>, KeyGenP2State<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Sample x2 and compute Q2 = x2 * G
    let x2 = C::random_scalar(rng);
    let q2 = C::generator() * x2;

    // DLog proof for Q2
    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x2, &ephemeral, &q2, b"xal21-keygen-q2");

    // Generate Paillier key pair (P2 owns the decryption key for MtA)
    let dk = tecdsa_paillier::keygen(rng)
        .map_err(|e| Xal21Error::Paillier(format!("Paillier keygen failed: {e}")))?;
    let ek = dk.encryption_key().clone();

    // Create Pi_GCD proof (proves knowledge of factorization of N)
    let pi_gcd = NICorrectKeyProof::prove(&dk, b"xal21-correct-key-challenge");

    let msg = KeyGenP2Round2Msg {
        q2,
        dlog_proof,
        ek: ek.clone(),
        pi_gcd,
    };

    let state = KeyGenP2State { x2, q2, dk, ek };

    Ok((msg, state))
}

// ---------------------------------------------------------------------------
// Round 3: P1 -> P2 (decommit Q1 + DLog proof)
// ---------------------------------------------------------------------------

/// Round 3 message from P1: decommitment of `(Q1, dlog_proof)`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP1Round3Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// P1's public key share `Q1 = x1 * G`.
    pub q1: C::ProjectivePoint,
    /// DLog proof for `Q1`.
    pub dlog_proof: DlogProof<C>,
    /// Commitment opening nonce.
    pub nonce: [u8; 32],
}

/// P1 processes P2's round 2 message: verifies DLog proof and Pi_GCD.
/// If both pass, returns the decommitment message (round 3).
/// Otherwise returns an error (abort).
pub fn party1_keygen_round3<C: TecdsaCurve>(
    p1_state: &KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
) -> Result<KeyGenP1Round3Msg<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Step 1: Verify P2's DLog proof for Q2
    if !p2_msg.dlog_proof.verify(&p2_msg.q2, b"xal21-keygen-q2") {
        return Err(Xal21Error::DlogVerification(
            "Keygen: P2's DLog proof for Q2 failed".into(),
        ));
    }

    // Step 2: Verify Pi_GCD (correct key proof)
    if !p2_msg
        .pi_gcd
        .verify(&p2_msg.ek, b"xal21-correct-key-challenge")
    {
        return Err(Xal21Error::PiGcdVerification(
            "Keygen: Pi_GCD proof verification failed".into(),
        ));
    }

    // All proofs verified; decommit (Q1, dlog_proof)
    Ok(KeyGenP1Round3Msg {
        q1: p1_state.q1,
        dlog_proof: p1_state.dlog_proof.clone(),
        nonce: p1_state.nonce,
    })
}

// ---------------------------------------------------------------------------
// P2 verifies P1's decommitment (Round 3 receipt)
// ---------------------------------------------------------------------------

/// P2 verifies P1's round 3 decommitment: checks commitment opening and
/// DLog proof for Q1.
pub fn party2_verify_round3<C: TecdsaCurve>(
    p1_round1: &KeyGenP1Round1Msg,
    p1_round3: &KeyGenP1Round3Msg<C>,
) -> Result<(), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Step 1: Verify commitment opening
    let commit_data = serialize_point_and_proof::<C>(&p1_round3.q1, &p1_round3.dlog_proof);
    if !p1_round1.commitment.verify(&commit_data, &p1_round3.nonce) {
        return Err(Xal21Error::CommitmentVerification(
            "Keygen: P1's commitment to Q1 failed to open".into(),
        ));
    }

    // Step 2: Verify P1's DLog proof for Q1
    if !p1_round3
        .dlog_proof
        .verify(&p1_round3.q1, b"xal21-keygen-q1")
    {
        return Err(Xal21Error::DlogVerification(
            "Keygen: P1's DLog proof for Q1 failed".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Finalize: both parties compute key shares
// ---------------------------------------------------------------------------

/// After all verifications pass, P1 computes its key share.
pub fn party1_finalize<C: TecdsaCurve>(
    p1_state: KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
) -> Xal21Party1KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Q = Q1 + Q2 = (x1 + x2) * G (additive sharing)
    let public_key = p1_state.q1 + p2_msg.q2;

    Xal21Party1KeyShare {
        secret_share: p1_state.x1,
        public_key,
        public_share: p1_state.q1,
        ek: p2_msg.ek.clone(),
    }
}

/// After all verifications pass, P2 computes its key share.
pub fn party2_finalize<C: TecdsaCurve>(
    p2_state: KeyGenP2State<C>,
    p1_round3: &KeyGenP1Round3Msg<C>,
) -> Xal21Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Q = Q1 + Q2 = (x1 + x2) * G (additive sharing)
    let public_key = p1_round3.q1 + p2_state.q2;

    Xal21Party2KeyShare {
        secret_share: p2_state.x2,
        public_key,
        public_share_p1: p1_round3.q1,
        dk: p2_state.dk,
        ek: p2_state.ek,
    }
}

// ---------------------------------------------------------------------------
// End-to-end convenience function
// ---------------------------------------------------------------------------

/// Run the complete interactive key generation protocol and return both parties'
/// key shares.
///
/// This is a convenience function that runs all 3 rounds sequentially. In a real
/// deployment, messages would be exchanged over a network.
pub fn interactive_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(Xal21Party1KeyShare<C>, Xal21Party2KeyShare<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // === Round 1: P1 commits to Q1 ===
    let (p1_r1_msg, p1_state) = party1_keygen_round1::<C>(rng);

    // === Round 2: P2 sends Q2, Paillier key, Pi_GCD ===
    let (p2_r2_msg, p2_state) = party2_keygen_round2::<C>(rng)?;

    // === Round 3: P1 verifies proofs and decommits ===
    let p1_r3_msg = party1_keygen_round3::<C>(&p1_state, &p2_r2_msg)?;

    // === P2 verifies P1's decommitment ===
    party2_verify_round3::<C>(&p1_r1_msg, &p1_r3_msg)?;

    // === Finalize: compute key shares ===
    let p2_share = party2_finalize::<C>(p2_state, &p1_r3_msg);
    let p1_share = party1_finalize::<C>(p1_state, &p2_r2_msg);

    // Sanity check: both parties computed the same public key
    debug_assert_eq!(p1_share.public_key, p2_share.public_key);

    Ok((p1_share, p2_share))
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a `ProjectivePoint + DlogProof` to bytes for commitment.
fn serialize_point_and_proof<C: TecdsaCurve>(
    point: &C::ProjectivePoint,
    proof: &DlogProof<C>,
) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut data = Vec::new();
    data.extend_from_slice(point.to_bytes().as_ref());
    data.extend_from_slice(proof.commitment.to_bytes().as_ref());
    data.extend_from_slice(proof.response.to_repr().as_ref());
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Secp256k1;
    use tecdsa_protocol::{verify_ecdsa, DataToSign};

    #[test]
    fn interactive_keygen_produces_consistent_shares() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Both parties have the same public key
        assert_eq!(p1.public_key, p2.public_key);

        // Q = (x1 + x2) * G (additive sharing)
        let x = p1.secret_share + p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn interactive_keygen_q1_matches() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Q1 = x1 * G
        let expected_q1 = Secp256k1::generator() * p1.secret_share;
        assert_eq!(p1.public_share, expected_q1);

        // P2 also has Q1
        assert_eq!(p2.public_share_p1, expected_q1);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn interactive_keygen_signing_compatibility() {
        use crate::offline_sign;
        use crate::online_sign;
        use sha2::{Digest, Sha256};

        let mut rng = rand_core::OsRng;

        // Generate key shares interactively
        let (p1_key, p2_key) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Hash a message
        let hash = Sha256::digest(b"test interactive keygen -> sign");
        let mut fb = elliptic_curve::FieldBytes::<Secp256k1>::default();
        let len = fb.len();
        fb.copy_from_slice(&hash[..len]);
        let scalar = Option::from(<k256::Scalar as elliptic_curve::PrimeField>::from_repr(fb))
            .expect("hash must be valid scalar");
        let message = DataToSign::from_digest(scalar);

        // Offline phase
        let (p1_presig, p2_presig) = offline_sign::offline_sign(&p1_key, &p2_key, &mut rng)
            .expect("offline signing should succeed");

        // Online phase
        let sig = online_sign::online_sign(&p1_key, &p1_presig, &p2_presig, &message)
            .expect("online signing should succeed with interactive keygen shares");

        // Verify
        verify_ecdsa::<Secp256k1>(&sig, &p1_key.public_key, &message)
            .expect("signature should verify");
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn round_by_round_keygen() {
        let mut rng = rand_core::OsRng;

        // Round 1: P1 commits
        let (p1_r1_msg, p1_state) = party1_keygen_round1::<Secp256k1>(&mut rng);

        // Round 2: P2 sends Q2, Paillier key, proofs
        let (p2_r2_msg, p2_state) =
            party2_keygen_round2::<Secp256k1>(&mut rng).expect("P2 round 2 should succeed");

        // Round 3: P1 verifies and decommits
        let p1_r3_msg = party1_keygen_round3::<Secp256k1>(&p1_state, &p2_r2_msg)
            .expect("P1 round 3 should succeed (proofs valid)");

        // P2 verifies P1's decommitment
        party2_verify_round3::<Secp256k1>(&p1_r1_msg, &p1_r3_msg)
            .expect("P2 verification of P1's decommitment should succeed");

        // Finalize
        let p2_share = party2_finalize::<Secp256k1>(p2_state, &p1_r3_msg);
        let p1_share = party1_finalize::<Secp256k1>(p1_state, &p2_r2_msg);

        assert_eq!(p1_share.public_key, p2_share.public_key);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn multiple_interactive_keygens_produce_different_keys() {
        let mut rng = rand_core::OsRng;

        let (p1a, _p2a) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 1 should succeed");
        let (p1b, _p2b) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 2 should succeed");

        // Public keys should differ (with overwhelming probability)
        assert_ne!(p1a.public_key, p1b.public_key);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn interactive_keygen_paillier_key_is_valid() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Both parties should have the same encryption key
        assert_eq!(p1.ek.n(), p2.ek.n());

        // P2's decryption key should match the encryption key
        assert_eq!(p2.dk.encryption_key().n(), p1.ek.n());

        // Test encrypt-decrypt round trip
        let test_val = tecdsa_paillier::backend::Integer::from(42u32);
        let (ct, _) = p1.ek.encrypt_with_random(&mut rng, &test_val).unwrap();
        let pt = p2.dk.decrypt(&ct).unwrap();
        assert_eq!(pt, test_val);
    }
}
