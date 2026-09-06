// SPDX-License-Identifier: MIT OR Apache-2.0
//! Interactive distributed key generation for the Lindell 2017 two-party ECDSA
//! protocol (Protocol 3.1).
//!
//! This implements the full 7-round interactive keygen between P1 (server) and
//! P2 (client), replacing the trusted dealer with a secure two-party protocol.
//!
//! ## Protocol Overview
//!
//! **Round 1 (P1 -> P2)**: P1 samples `x_1`, computes `Q_1 = x_1 * G`, creates
//! a DLog proof, and commits to `(Q_1, proof)`. Sends commitment.
//!
//! **Round 2 (P2 -> P1)**: P2 samples `x_2`, computes `Q_2 = x_2 * G`, creates
//! a DLog proof. Sends `(Q_2, proof)`.
//!
//! **Round 3 (P1 -> P2)**: P1 verifies P2's DLog proof. Decommits `Q_1 + proof`.
//! Generates Paillier keypair `(ek, dk)`. Computes `c_key = Enc(x_1)`. Generates
//! NICorrectKeyProof for `ek`. Sends `(decommit, ek, c_key, correct_key_proof)`.
//!
//! **Rounds 4-7 (PDL verification)**: P2 verifies commitment opening, P1's DLog
//! proof, ciphertext validity, and correct-key proof. Then runs the interactive
//! PDL protocol (Protocol 6.1) to verify that `c_key` encrypts the discrete log
//! of `Q_1`.
//!
//! **Output**: P1 stores `(x_1, Q, dk)`. P2 stores `(x_2, Q, c_key, ek)`.
//! where `Q = x_1 * x_2 * G`.

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use rug::Integer;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::{
    zk::{correct_key_ni::NICorrectKeyProof, pdl, range_ni::RangeProofNi},
    BigIntExt,
};

use crate::{
    error::Lin17Error,
    key_share::{Lin17Party1KeyShare, Lin17Party2KeyShare},
};

// ---------------------------------------------------------------------------
// Round 1: P1 -> P2  (commitment to Q1 + DLog proof)
// ---------------------------------------------------------------------------

/// Round 1 message from P1: commitment to `(Q_1, dlog_proof)`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP1Round1Msg {
    /// Hash commitment to `Q_1 || dlog_proof`.
    pub commitment: HashCommitment,
}

/// P1's internal state after round 1.
pub struct KeyGenP1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret share `x_1`.
    pub x1: C::Scalar,
    /// Public key `Q_1 = x_1 * G`.
    pub q1: C::ProjectivePoint,
    /// DLog proof for `Q_1`.
    pub dlog_proof: DlogProof<C>,
    /// Commitment opening nonce.
    pub nonce: [u8; 32],
}

/// P1 round 1: sample `x_1`, compute `Q_1 = x_1 * G`, create DLog proof, commit.
pub fn party1_keygen_round1<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (KeyGenP1Round1Msg, KeyGenP1State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1 = C::random_scalar(rng);
    let q1 = C::generator() * x1;

    // DLog proof for Q_1
    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x1, &ephemeral, &q1, b"lin17-keygen-q1");

    // Commit to (Q_1, dlog_proof)
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
// Round 2: P2 -> P1  (Q2 + DLog proof)
// ---------------------------------------------------------------------------

/// Round 2 message from P2: `(Q_2, dlog_proof)`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP2Round2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// P2's public key share `Q_2 = x_2 * G`.
    pub q2: C::ProjectivePoint,
    /// DLog proof for `Q_2`.
    pub dlog_proof: DlogProof<C>,
}

/// P2's internal state after round 2.
pub struct KeyGenP2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret share `x_2`.
    pub x2: C::Scalar,
    /// Public key `Q_2 = x_2 * G`.
    pub q2: C::ProjectivePoint,
}

/// P2 round 2: sample `x_2`, compute `Q_2 = x_2 * G`, create DLog proof.
pub fn party2_keygen_round2<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (KeyGenP2Round2Msg<C>, KeyGenP2State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x2 = C::random_scalar(rng);
    let q2 = C::generator() * x2;

    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x2, &ephemeral, &q2, b"lin17-keygen-q2");

    let msg = KeyGenP2Round2Msg { q2, dlog_proof };
    let state = KeyGenP2State { x2, q2 };

    (msg, state)
}

// ---------------------------------------------------------------------------
// Round 3: P1 -> P2  (decommit Q1+proof, Paillier pk, c_key, correct_key_proof)
// ---------------------------------------------------------------------------

/// Round 3 message from P1: decommitment + Paillier key + c_key + proof.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP1Round3Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// P1's public key share `Q_1 = x_1 * G`.
    pub q1: C::ProjectivePoint,
    /// DLog proof for `Q_1`.
    pub dlog_proof: DlogProof<C>,
    /// Commitment opening nonce.
    pub nonce: [u8; 32],
    /// Paillier encryption key.
    pub ek: tecdsa_paillier::EncryptionKey,
    /// `c_key = Enc_pk(x_1)`.
    #[cfg_attr(feature = "serde", serde(with = "tecdsa_bigint::int_wire"))]
    pub c_key: tecdsa_paillier::Ciphertext,
    /// Paillier nonce used to encrypt `x_1` (needed for range proof).
    #[cfg_attr(feature = "serde", serde(with = "tecdsa_bigint::int_wire"))]
    pub c_key_nonce: Integer,
    /// Proof that P1 knows the factorization of `N`.
    pub correct_key_proof: NICorrectKeyProof,
    /// Range proof that `c_key` encrypts a value in `[0, q)`.
    pub range_proof: RangeProofNi,
}

/// P1 round 3: verify P2's DLog proof, generate Paillier keys, encrypt `x_1`,
/// create correct-key proof and range proof, decommit `Q_1`.
pub fn party1_keygen_round3<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<KeyGenP1Round3Msg<C>, Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify P2's DLog proof for Q_2
    if !p2_msg.dlog_proof.verify(&p2_msg.q2, b"lin17-keygen-q2") {
        return Err(Lin17Error::DlogVerification(
            "Keygen: P2's DLog proof for Q_2 failed".into(),
        ));
    }

    // Generate Paillier key pair
    let dk = tecdsa_paillier::DecryptionKey::generate(rng)
        .map_err(|e| Lin17Error::Paillier(format!("Paillier keygen failed: {e}")))?;
    let ek = dk.encryption_key().clone();

    // Encrypt x_1
    let x1_bytes = state.x1.to_repr();
    let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
    let (c_key, c_key_nonce) = dk
        .encrypt_with_random(rng, &x1_int)
        .map_err(|e| Lin17Error::Paillier(format!("encrypt x_1 failed: {e}")))?;

    // Create NICorrectKeyProof
    let correct_key_proof = NICorrectKeyProof::prove(&dk, b"lin17-correct-key-challenge");

    // Create range proof
    let q_int = tecdsa_curve::conv::curve_order::<C>();
    let range_proof = RangeProofNi::prove(&dk, &ek, &c_key, &x1_int, &c_key_nonce, &q_int, rng)?;

    Ok(KeyGenP1Round3Msg {
        q1: state.q1,
        dlog_proof: state.dlog_proof.clone(),
        nonce: state.nonce,
        ek,
        c_key,
        c_key_nonce,
        correct_key_proof,
        range_proof,
    })
}

/// Return the `DecryptionKey` generated for P1 during round 3.
///
/// This is a separate function because the `DecryptionKey` must be generated
/// once and stored, but round 3 needs it internally. The caller should hold
/// onto it for the PDL protocol and final key share construction.
///
/// Note: In the implementation, `party1_keygen_round3` creates the dk internally
/// but doesn't return it. We need a combined function that returns both.
pub fn party1_keygen_round3_with_dk<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP1Round3Msg<C>, tecdsa_paillier::DecryptionKey), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify P2's DLog proof for Q_2
    if !p2_msg.dlog_proof.verify(&p2_msg.q2, b"lin17-keygen-q2") {
        return Err(Lin17Error::DlogVerification(
            "Keygen: P2's DLog proof for Q_2 failed".into(),
        ));
    }

    // Generate Paillier key pair (one-time setup; see the precomputed variant).
    let dk = tecdsa_paillier::DecryptionKey::generate(rng)
        .map_err(|e| Lin17Error::Paillier(format!("Paillier keygen failed: {e}")))?;

    party1_keygen_round3_core::<C>(state, dk, rng)
}

/// Like [`party1_keygen_round3_with_dk`], but uses a **precomputed** Paillier
/// decryption key `dk` instead of generating one inside the round.
///
/// P1's Paillier keypair is a one-time, message-independent setup step. This
/// variant lets a caller (e.g. a benchmark harness) generate the keypair
/// up front and inject it, so the round itself measures only the encryption,
/// proofs, and decommitment work — not the (multi-second) safe-prime generation.
pub fn party1_keygen_round3_with_precomputed_dk<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    p2_msg: &KeyGenP2Round2Msg<C>,
    dk: tecdsa_paillier::DecryptionKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP1Round3Msg<C>, tecdsa_paillier::DecryptionKey), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify P2's DLog proof for Q_2
    if !p2_msg.dlog_proof.verify(&p2_msg.q2, b"lin17-keygen-q2") {
        return Err(Lin17Error::DlogVerification(
            "Keygen: P2's DLog proof for Q_2 failed".into(),
        ));
    }

    party1_keygen_round3_core::<C>(state, dk, rng)
}

/// Shared body of P1's round 3: encrypt `x_1` under `dk`, build the correct-key
/// and range proofs, and assemble the round-3 message. The `dk` is threaded
/// through and returned unchanged so the caller can retain it for PDL/finalize.
fn party1_keygen_round3_core<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    dk: tecdsa_paillier::DecryptionKey,
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP1Round3Msg<C>, tecdsa_paillier::DecryptionKey), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let ek = dk.encryption_key().clone();

    // Encrypt x_1
    let x1_bytes = state.x1.to_repr();
    let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
    let (c_key, c_key_nonce) = dk
        .encrypt_with_random(rng, &x1_int)
        .map_err(|e| Lin17Error::Paillier(format!("encrypt x_1 failed: {e}")))?;

    // Create NICorrectKeyProof
    let correct_key_proof = NICorrectKeyProof::prove(&dk, b"lin17-correct-key-challenge");

    // Create range proof
    let q_int = tecdsa_curve::conv::curve_order::<C>();
    let range_proof = RangeProofNi::prove(&dk, &ek, &c_key, &x1_int, &c_key_nonce, &q_int, rng)?;

    let msg = KeyGenP1Round3Msg {
        q1: state.q1,
        dlog_proof: state.dlog_proof.clone(),
        nonce: state.nonce,
        ek,
        c_key,
        c_key_nonce,
        correct_key_proof,
        range_proof,
    };

    Ok((msg, dk))
}

// ---------------------------------------------------------------------------
// Round 4-7: PDL verification (interactive)
// ---------------------------------------------------------------------------

/// P2 processes P1's round 3 message: verifies commitment, DLog proof,
/// ciphertext validity, correct-key proof, and range proof.
///
/// If all checks pass, returns the verified `Q_1` and `ek` for use in
/// subsequent PDL verification.
pub fn party2_verify_round3<C: TecdsaCurve>(
    _p2_state: &KeyGenP2State<C>,
    p1_round1: &KeyGenP1Round1Msg,
    p1_round3: &KeyGenP1Round3Msg<C>,
) -> Result<(), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Step 1: Verify commitment opening
    let commit_data = serialize_point_and_proof::<C>(&p1_round3.q1, &p1_round3.dlog_proof);
    if !p1_round1.commitment.verify(&commit_data, &p1_round3.nonce) {
        return Err(Lin17Error::CommitmentVerification(
            "Keygen: P1's commitment to Q_1 failed to open".into(),
        ));
    }

    // Step 2: Verify P1's DLog proof for Q_1
    if !p1_round3
        .dlog_proof
        .verify(&p1_round3.q1, b"lin17-keygen-q1")
    {
        return Err(Lin17Error::DlogVerification(
            "Keygen: P1's DLog proof for Q_1 failed".into(),
        ));
    }

    // Step 3: Verify c_key is in Z*_{N^2}
    let nn = p1_round3.ek.nn();
    if !p1_round3.c_key.in_mult_group_of(nn) {
        return Err(Lin17Error::CiphertextValidation(
            "Keygen: c_key not in Z*_{N^2}".into(),
        ));
    }

    // Step 4: Verify NICorrectKeyProof
    if !p1_round3
        .correct_key_proof
        .verify(&p1_round3.ek, b"lin17-correct-key-challenge")
    {
        return Err(Lin17Error::CorrectKeyVerification(
            "Keygen: NICorrectKeyProof verification failed".into(),
        ));
    }

    // Step 5: Verify range proof
    let q_int = tecdsa_curve::conv::curve_order::<C>();
    if !p1_round3
        .range_proof
        .verify(&p1_round3.ek, &p1_round3.c_key, &q_int)
    {
        return Err(Lin17Error::RangeProofVerification(
            "Keygen: range proof verification failed".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Finalize: compute key shares
// ---------------------------------------------------------------------------

/// After all verifications pass, P1 computes its key share.
pub fn party1_finalize_keygen<C: TecdsaCurve>(
    state: &KeyGenP1State<C>,
    p2_q2: &C::ProjectivePoint,
    dk: tecdsa_paillier::DecryptionKey,
) -> Lin17Party1KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Q = x_1 * Q_2 = x_1 * x_2 * G
    let public_key = *p2_q2 * state.x1;

    Lin17Party1KeyShare {
        secret_share: state.x1,
        public_key,
        dk,
    }
}

/// After all verifications pass, P2 computes its key share.
pub fn party2_finalize_keygen<C: TecdsaCurve>(
    state: &KeyGenP2State<C>,
    p1_q1: &C::ProjectivePoint,
    c_key: tecdsa_paillier::Ciphertext,
    ek: tecdsa_paillier::EncryptionKey,
) -> Lin17Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Q = x_2 * Q_1 = x_1 * x_2 * G
    let public_key = *p1_q1 * state.x2;

    Lin17Party2KeyShare {
        secret_share: state.x2,
        public_key,
        c_key,
        ek,
    }
}

// ---------------------------------------------------------------------------
// End-to-end convenience function
// ---------------------------------------------------------------------------

/// Run the complete interactive key generation protocol and return both parties'
/// key shares.
///
/// This is a convenience function that runs all rounds sequentially. In a real
/// deployment, messages would be exchanged over a network.
pub fn interactive_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(Lin17Party1KeyShare<C>, Lin17Party2KeyShare<C>), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // === Round 1: P1 commits to Q1 ===
    let (p1_r1_msg, p1_state) = party1_keygen_round1::<C>(rng);

    // === Round 2: P2 sends Q2 + proof ===
    let (p2_r2_msg, p2_state) = party2_keygen_round2::<C>(rng);

    // === Round 3: P1 verifies P2's proof, decommits, sends Paillier keys ===
    let (p1_r3_msg, dk) = party1_keygen_round3_with_dk::<C>(&p1_state, &p2_r2_msg, rng)?;

    // === P2 verifies P1's round 3 message ===
    party2_verify_round3::<C>(&p2_state, &p1_r1_msg, &p1_r3_msg)?;

    // === Rounds 4-7: PDL verification ===
    pdl::pdl_verify::<C>(
        &dk,
        &p1_r3_msg.ek,
        &p1_state.x1,
        &p1_r3_msg.c_key,
        &p1_r3_msg.q1,
        rng,
    )?;

    // === Finalize: compute key shares ===
    let p1_share = party1_finalize_keygen::<C>(&p1_state, &p2_r2_msg.q2, dk);
    let p2_share =
        party2_finalize_keygen::<C>(&p2_state, &p1_r3_msg.q1, p1_r3_msg.c_key, p1_r3_msg.ek);

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
    use k256::Secp256k1;
    use tecdsa_protocol::{verify_ecdsa, DataToSign};

    use super::*;

    #[test]
    fn interactive_keygen_produces_consistent_shares() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Both parties have the same public key
        assert_eq!(p1.public_key, p2.public_key);

        // Q = (x_1 * x_2) * G
        let x = p1.secret_share * p2.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(p1.public_key, expected_pk);
    }

    #[test]
    fn interactive_keygen_paillier_encrypts_x1() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Decrypt c_key and verify it equals x_1
        let decrypted = p1.dk.decrypt(&p2.c_key).expect("decryption failed");
        let x1_bytes = p1.secret_share.to_repr();
        let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
        assert_eq!(decrypted, x1_int);
    }

    #[test]
    fn interactive_keygen_signing_compatibility() {
        use sha2::{Digest, Sha256};

        use crate::sign;

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

        // Sign using the interactive keygen's key shares
        let signature = sign::sign(&p1_key, &p2_key, &message, &mut rng)
            .expect("signing should succeed with interactive keygen shares");

        // Verify
        verify_ecdsa::<Secp256k1>(&signature, &p1_key.public_key, &message)
            .expect("signature should verify");
    }

    #[test]
    fn round_by_round_keygen() {
        let mut rng = rand_core::OsRng;

        // Round 1
        let (p1_r1_msg, p1_state) = party1_keygen_round1::<Secp256k1>(&mut rng);

        // Round 2
        let (p2_r2_msg, p2_state) = party2_keygen_round2::<Secp256k1>(&mut rng);

        // Round 3
        let (p1_r3_msg, dk) =
            party1_keygen_round3_with_dk::<Secp256k1>(&p1_state, &p2_r2_msg, &mut rng)
                .expect("P1 round 3 should succeed");

        // P2 verifies
        party2_verify_round3::<Secp256k1>(&p2_state, &p1_r1_msg, &p1_r3_msg)
            .expect("P2 verification of P1's round 3 should succeed");

        // PDL verification
        pdl::pdl_verify::<Secp256k1>(
            &dk,
            &p1_r3_msg.ek,
            &p1_state.x1,
            &p1_r3_msg.c_key,
            &p1_r3_msg.q1,
            &mut rng,
        )
        .expect("PDL verification should pass");

        // Finalize
        let p1_share = party1_finalize_keygen::<Secp256k1>(&p1_state, &p2_r2_msg.q2, dk);
        let p2_share = party2_finalize_keygen::<Secp256k1>(
            &p2_state,
            &p1_r3_msg.q1,
            p1_r3_msg.c_key,
            p1_r3_msg.ek,
        );

        assert_eq!(p1_share.public_key, p2_share.public_key);
    }

    #[test]
    fn multiple_interactive_keygens_produce_different_keys() {
        let mut rng = rand_core::OsRng;

        let (p1a, _p2a) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 1 should succeed");
        let (p1b, _p2b) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 2 should succeed");

        // Public keys should differ (with overwhelming probability)
        assert_ne!(p1a.public_key, p1b.public_key);
    }
}
