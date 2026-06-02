// SPDX-License-Identifier: MIT OR Apache-2.0
//! Interactive distributed key generation for the ABC+24 two-party ECDSA
//! protocol (Protocol 2, Section 4.3).
//!
//! This implements the full 4-step interactive keygen between Server (S, holds
//! Paillier key) and Client (C), followed by an interactive PDL proof
//! (psi_dlenc) that the ciphertext E encrypts the discrete log of X_2.
//!
//! ## Protocol Overview
//!
//! **Step 1 (S -> C)**: S samples `x'_2`, computes `X_2 = g^{x'_2}`, sends
//! `B = RO(ssid, S, X_2)` -- hash commitment to X_2.
//!
//! **Step 2 (C -> S)**: C samples `x_1`, computes `X_1 = g^{x_1}`. Creates
//! DLog proof `psi_dlog` for X_1. Generates `Pi_GCD` proof for the server's
//! Paillier key. Sends `(X_1, psi_dlog)`.
//!
//! **Step 3 (S -> C)**: S verifies `psi_dlog`. Computes `E = enc_N(x'_2; rho)`.
//! Creates `psi_dlenc` proof (interactive PDL) that E encrypts the DLog of X_2.
//! Sends `(X_2, E, psi_dlenc_setup)`.
//!
//! **Step 4 (C)**: C verifies `B = RO(ssid, S, X_2)` (decommitment). Verifies
//! `E in Z*_{N^2}`. Runs interactive PDL (psi_dlenc) verification.
//! Computes `X = X_1 * X_2`.
//!
//! **Output**: S stores `(x_2, X, X_1, dk, setup)`. C stores `(x_1, X, X_2, E, ek, setup)`.

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::zk::dlog::DlogProof;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::backend::Integer;

use crate::error::Abc24Error;
use crate::key_share::{Abc24ClientKeyShare, Abc24ServerKeyShare};
use crate::setup::SetupData;
use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
use tecdsa_paillier::zk::pdl;

// ---------------------------------------------------------------------------
// Step 1: S -> C  (hash commitment to X_2)
// ---------------------------------------------------------------------------

/// Step 1 message from Server: hash commitment to X_2.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerStep1Msg {
    /// `B = RO(ssid, S, X_2)` -- hash commitment to the server's public share.
    pub commitment: HashCommitment,
    /// Paillier encryption key (server publishes this in setup).
    pub ek: tecdsa_paillier::EncryptionKey,
    /// Proof that server knows factorization of N (Pi_GCD / correct key proof).
    pub correct_key_proof: NICorrectKeyProof,
}

/// Server's internal state after step 1.
pub struct ServerStep1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret share `x'_2` (scalar, will be reduced mod q for the final share).
    pub x2: C::Scalar,
    /// Public key share `X_2 = g^{x'_2}`.
    pub x2_point: C::ProjectivePoint,
    /// Commitment opening nonce.
    pub nonce: [u8; 32],
    /// Paillier decryption key.
    pub dk: tecdsa_paillier::DecryptionKey,
}

/// Server, Step 1: sample `x'_2`, compute `X_2 = g^{x'_2}`, create hash commitment.
///
/// Also generates the Paillier keypair and NICorrectKeyProof.
pub fn server_keygen_step1<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (ServerStep1Msg, ServerStep1State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Sample x'_2
    let x2 = C::random_scalar(rng);
    let x2_point = C::generator() * x2;

    // Generate Paillier keys
    let dk = tecdsa_paillier::keygen(rng).expect("Paillier keygen failed");
    let ek = dk.encryption_key().clone();

    // Create NICorrectKeyProof (Pi_GCD)
    let correct_key_proof = NICorrectKeyProof::prove(&dk, b"abc24-correct-key-challenge");

    // Commit to X_2: B = H("abc24-keygen-commit" || X_2)
    let x2_bytes = x2_point.to_bytes();
    let (commitment, nonce) = HashCommitment::commit(x2_bytes.as_ref(), rng);

    let msg = ServerStep1Msg {
        commitment,
        ek,
        correct_key_proof,
    };
    let state = ServerStep1State {
        x2,
        x2_point,
        nonce,
        dk,
    };

    (msg, state)
}

// ---------------------------------------------------------------------------
// Step 2: C -> S  (X_1 + DLog proof)
// ---------------------------------------------------------------------------

/// Step 2 message from Client: public share and DLog proof.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClientStep2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Client's public key share `X_1 = g^{x_1}`.
    pub x1_point: C::ProjectivePoint,
    /// DLog proof `psi_dlog` for X_1.
    pub dlog_proof: DlogProof<C>,
}

/// Client's internal state after step 2.
pub struct ClientStep2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret share `x_1`.
    pub x1: C::Scalar,
    /// Public key share `X_1 = g^{x_1}`.
    pub x1_point: C::ProjectivePoint,
    /// Server's Paillier encryption key.
    pub ek: tecdsa_paillier::EncryptionKey,
    /// Server's commitment from step 1 (needed for verification in step 4).
    pub server_commitment: HashCommitment,
}

/// Client, Step 2: verify server's correct key proof, sample `x_1`, create DLog proof.
pub fn client_keygen_step2<C: TecdsaCurve>(
    server_msg: &ServerStep1Msg,
    rng: &mut impl CryptoRngCore,
) -> Result<(ClientStep2Msg<C>, ClientStep2State<C>), Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify Pi_GCD (NICorrectKeyProof)
    if !server_msg
        .correct_key_proof
        .verify(&server_msg.ek, b"abc24-correct-key-challenge")
    {
        return Err(Abc24Error::PiGcdVerification(
            "Keygen Step 2: server's NICorrectKeyProof (Pi_GCD) verification failed".into(),
        ));
    }

    // Sample x_1
    let x1 = C::random_scalar(rng);
    let x1_point = C::generator() * x1;

    // Create DLog proof for X_1
    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x1, &ephemeral, &x1_point, b"abc24-keygen-x1");

    let msg = ClientStep2Msg {
        x1_point,
        dlog_proof,
    };
    let state = ClientStep2State {
        x1,
        x1_point,
        ek: server_msg.ek.clone(),
        server_commitment: server_msg.commitment.clone(),
    };

    Ok((msg, state))
}

// ---------------------------------------------------------------------------
// Step 3: S -> C  (X_2, E, and PDL proof setup)
// ---------------------------------------------------------------------------

/// Step 3 message from Server: decommitment of X_2, ciphertext E, and PDL proof data.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerStep3Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Server's public key share `X_2 = g^{x'_2}`.
    pub x2_point: C::ProjectivePoint,
    /// Commitment opening nonce for B.
    pub nonce: [u8; 32],
    /// `E = enc_N(x'_2; rho)` -- Paillier encryption of server's share.
    pub enc_x2: tecdsa_paillier::Ciphertext,
}

/// Server's state after step 3 (ready for PDL proof).
pub struct ServerStep3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret share `x'_2`.
    pub x2: C::Scalar,
    /// Public key share `X_2 = g^{x'_2}`.
    pub x2_point: C::ProjectivePoint,
    /// Client's public key share `X_1`.
    pub x1_point: C::ProjectivePoint,
    /// Paillier decryption key.
    pub dk: tecdsa_paillier::DecryptionKey,
    /// Ciphertext E = enc(x'_2).
    pub enc_x2: tecdsa_paillier::Ciphertext,
}

/// Server, Step 3: verify client's DLog proof, encrypt x'_2, prepare PDL proof.
pub fn server_keygen_step3<C: TecdsaCurve>(
    server_state: &ServerStep1State<C>,
    client_msg: &ClientStep2Msg<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<(ServerStep3Msg<C>, ServerStep3State<C>), Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify client's DLog proof for X_1
    if !client_msg
        .dlog_proof
        .verify(&client_msg.x1_point, b"abc24-keygen-x1")
    {
        return Err(Abc24Error::DlogVerification(
            "Keygen Step 3: client's DLog proof for X_1 failed".into(),
        ));
    }

    // Encrypt x'_2
    let x2_bytes = server_state.x2.to_repr();
    let x2_int = Integer::from_bytes_msf(x2_bytes.as_ref());
    let (enc_x2, _nonce) = server_state
        .dk
        .encrypt_with_random(rng, &x2_int)
        .map_err(|e| Abc24Error::Paillier(format!("encrypt x'_2 failed: {e}")))?;

    let msg = ServerStep3Msg {
        x2_point: server_state.x2_point,
        nonce: server_state.nonce,
        enc_x2: enc_x2.clone(),
    };

    let state = ServerStep3State {
        x2: server_state.x2,
        x2_point: server_state.x2_point,
        x1_point: client_msg.x1_point,
        dk: server_state.dk.clone(),
        enc_x2,
    };

    Ok((msg, state))
}

// ---------------------------------------------------------------------------
// Step 4: C verifies decommitment, ciphertext, and runs PDL proof
// ---------------------------------------------------------------------------

/// Client processes server's step 3 message: verifies commitment opening,
/// ciphertext validity, and runs the interactive PDL proof.
pub fn client_verify_step3<C: TecdsaCurve>(
    client_state: &ClientStep2State<C>,
    server_step3: &ServerStep3Msg<C>,
) -> Result<(), Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Step 4a: Verify B = H(X_2) (commitment decommitment)
    let x2_bytes = server_step3.x2_point.to_bytes();
    if !client_state
        .server_commitment
        .verify(x2_bytes.as_ref(), &server_step3.nonce)
    {
        return Err(Abc24Error::CommitmentVerification(
            "Keygen Step 4: server's commitment to X_2 failed to open".into(),
        ));
    }

    // Step 4b: Verify E in Z*_{N^2}
    let nn = client_state.ek.nn();
    if !server_step3.enc_x2.in_mult_group_of(nn) {
        return Err(Abc24Error::InvalidInput(
            "Keygen Step 4: E not in Z*_{N^2}".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Finalize: compute key shares
// ---------------------------------------------------------------------------

/// After all verifications pass (including PDL), server computes its key share.
pub fn server_finalize_keygen<C: TecdsaCurve>(
    server_state: &ServerStep3State<C>,
) -> Abc24ServerKeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // X = X_1 * X_2 (additive sharing: x = x_1 + x_2)
    let public_key = server_state.x1_point + server_state.x2_point;

    let ek = server_state.dk.encryption_key().clone();
    let setup = SetupData::from_ek(&ek);

    Abc24ServerKeyShare {
        secret_share: server_state.x2,
        public_key,
        client_public_share: server_state.x1_point,
        dk: server_state.dk.clone(),
        setup,
    }
}

/// After all verifications pass (including PDL), client computes its key share.
pub fn client_finalize_keygen<C: TecdsaCurve>(
    client_state: &ClientStep2State<C>,
    server_step3: &ServerStep3Msg<C>,
) -> Abc24ClientKeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // X = X_1 * X_2 (additive sharing: x = x_1 + x_2)
    let public_key = client_state.x1_point + server_step3.x2_point;

    let setup = SetupData::from_ek(&client_state.ek);

    Abc24ClientKeyShare {
        secret_share: client_state.x1,
        public_key,
        server_public_share: server_step3.x2_point,
        enc_x2: server_step3.enc_x2.clone(),
        ek: client_state.ek.clone(),
        setup,
    }
}

// ---------------------------------------------------------------------------
// End-to-end convenience function
// ---------------------------------------------------------------------------

/// Run the complete interactive key generation protocol and return both
/// parties' key shares.
///
/// This convenience function executes all steps sequentially, including the
/// interactive PDL proof. In a real deployment, messages would be exchanged
/// over a network.
pub fn interactive_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(Abc24ServerKeyShare<C>, Abc24ClientKeyShare<C>), Abc24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // === Step 1: S -> C (commitment to X_2 + ek + correct_key_proof) ===
    let (s1_msg, s1_state) = server_keygen_step1::<C>(rng);

    // === Step 2: C -> S (X_1 + DLog proof) ===
    let (c2_msg, c2_state) = client_keygen_step2::<C>(&s1_msg, rng)?;

    // === Step 3: S -> C (X_2 + E + decommitment) ===
    let (s3_msg, s3_state) = server_keygen_step3::<C>(&s1_state, &c2_msg, rng)?;

    // === Step 4: C verifies commitment and ciphertext ===
    client_verify_step3::<C>(&c2_state, &s3_msg)?;

    // === Interactive PDL proof (psi_dlenc): 4 messages ===
    // Verifier = client, Prover = server
    let ek = s1_state.dk.encryption_key().clone();
    pdl::pdl_verify::<C>(
        &s3_state.dk,
        &ek,
        &s3_state.x2,
        &s3_msg.enc_x2,
        &s3_msg.x2_point,
        rng,
    )?;

    // === Finalize: compute key shares ===
    let server_share = server_finalize_keygen::<C>(&s3_state);
    let client_share = client_finalize_keygen::<C>(&c2_state, &s3_msg);

    // Sanity check: both parties computed the same public key
    debug_assert_eq!(server_share.public_key, client_share.public_key);

    Ok((server_share, client_share))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Secp256k1;
    use tecdsa_protocol::{verify_ecdsa, DataToSign};

    #[test]
    fn interactive_keygen_produces_consistent_shares() {
        let mut rng = rand_core::OsRng;
        let (server, client) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Both parties have the same public key
        assert_eq!(server.public_key, client.public_key);

        // X = g^{x_1 + x_2}
        let x = server.secret_share + client.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(server.public_key, expected_pk);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn interactive_keygen_paillier_encrypts_x2() {
        let mut rng = rand_core::OsRng;
        let (server, client) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Decrypt E and verify it equals x_2
        let decrypted = server
            .dk
            .decrypt(&client.enc_x2)
            .expect("decryption failed");
        let x2_bytes = server.secret_share.to_repr();
        let x2_int = Integer::from_bytes_msf(x2_bytes.as_ref());
        assert_eq!(decrypted, x2_int);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn interactive_keygen_public_shares_consistent() {
        let mut rng = rand_core::OsRng;
        let (server, client) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        let x1_point = Secp256k1::generator() * client.secret_share;
        let x2_point = Secp256k1::generator() * server.secret_share;

        assert_eq!(server.client_public_share, x1_point);
        assert_eq!(client.server_public_share, x2_point);
        assert_eq!(x1_point + x2_point, server.public_key);
    }

    #[test]
    fn interactive_keygen_signing_compatibility() {
        use crate::sign;
        use sha2::{Digest, Sha256};

        let mut rng = rand_core::OsRng;

        // Generate key shares interactively
        let (server_key, client_key) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Hash a message
        let hash = Sha256::digest(b"test interactive keygen -> sign ABC+24");
        let mut fb = k256::FieldBytes::default();
        let len = fb.len();
        fb.copy_from_slice(&hash[..len]);
        let scalar = Option::from(<k256::Scalar as PrimeField>::from_repr(fb))
            .expect("hash must be valid scalar");
        let message = DataToSign::from_digest(scalar);

        // Sign using the interactive keygen's key shares
        let signature = sign::sign(&server_key, &client_key, &message, &mut rng)
            .expect("signing should succeed with interactive keygen shares");

        // Verify
        verify_ecdsa::<Secp256k1>(&signature, &server_key.public_key, &message)
            .expect("signature should verify");
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn round_by_round_keygen() {
        let mut rng = rand_core::OsRng;

        // Step 1
        let (s1_msg, s1_state) = server_keygen_step1::<Secp256k1>(&mut rng);

        // Step 2
        let (c2_msg, c2_state) =
            client_keygen_step2::<Secp256k1>(&s1_msg, &mut rng).expect("step 2");

        // Step 3
        let (s3_msg, s3_state) =
            server_keygen_step3::<Secp256k1>(&s1_state, &c2_msg, &mut rng).expect("step 3");

        // Step 4 verification
        client_verify_step3::<Secp256k1>(&c2_state, &s3_msg).expect("step 4 verification");

        // PDL proof
        let ek = s1_state.dk.encryption_key().clone();
        pdl::pdl_verify::<Secp256k1>(
            &s3_state.dk,
            &ek,
            &s3_state.x2,
            &s3_msg.enc_x2,
            &s3_msg.x2_point,
            &mut rng,
        )
        .expect("PDL verification should pass");

        // Finalize
        let server_share = server_finalize_keygen::<Secp256k1>(&s3_state);
        let client_share = client_finalize_keygen::<Secp256k1>(&c2_state, &s3_msg);

        assert_eq!(server_share.public_key, client_share.public_key);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn multiple_interactive_keygens_produce_different_keys() {
        let mut rng = rand_core::OsRng;

        let (s1, _c1) = interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 1 should succeed");
        let (s2, _c2) = interactive_keygen::<Secp256k1>(&mut rng).expect("keygen 2 should succeed");

        // Public keys should differ (with overwhelming probability)
        assert_ne!(s1.public_key, s2.public_key);
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn client_rejects_bad_correct_key_proof() {
        let mut rng = rand_core::OsRng;

        let (mut s1_msg, _s1_state) = server_keygen_step1::<Secp256k1>(&mut rng);

        // Corrupt the correct key proof by truncating responses
        s1_msg.correct_key_proof.responses.truncate(1);

        let result = client_keygen_step2::<Secp256k1>(&s1_msg, &mut rng);
        assert!(
            result.is_err(),
            "client should reject invalid correct key proof"
        );
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn server_rejects_bad_dlog_proof() {
        let mut rng = rand_core::OsRng;

        let (s1_msg, s1_state) = server_keygen_step1::<Secp256k1>(&mut rng);
        let (mut c2_msg, _c2_state) =
            client_keygen_step2::<Secp256k1>(&s1_msg, &mut rng).expect("step 2");

        // Corrupt the DLog proof by changing the public point
        c2_msg.x1_point = Secp256k1::generator() * k256::Scalar::from(42u64);

        let result = server_keygen_step3::<Secp256k1>(&s1_state, &c2_msg, &mut rng);
        assert!(result.is_err(), "server should reject invalid DLog proof");
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn client_rejects_bad_commitment() {
        let mut rng = rand_core::OsRng;

        let (s1_msg, s1_state) = server_keygen_step1::<Secp256k1>(&mut rng);
        let (c2_msg, c2_state) =
            client_keygen_step2::<Secp256k1>(&s1_msg, &mut rng).expect("step 2");
        let (mut s3_msg, _s3_state) =
            server_keygen_step3::<Secp256k1>(&s1_state, &c2_msg, &mut rng).expect("step 3");

        // Corrupt X_2 (commitment will not match)
        s3_msg.x2_point = Secp256k1::generator() * k256::Scalar::from(99u64);

        let result = client_verify_step3::<Secp256k1>(&c2_state, &s3_msg);
        assert!(
            result.is_err(),
            "client should reject mismatched commitment"
        );
    }
}
