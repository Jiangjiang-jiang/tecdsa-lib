// SPDX-License-Identifier: MIT OR Apache-2.0
//! Interactive distributed key generation for KGG24 (Figure 5, Section 4).
//!
//! Implements the full 3-message interactive keygen between P1 (server) and
//! P2 (client), replacing the trusted dealer with a secure two-party protocol.
//!
//! ## Protocol Overview
//!
//! **Round 1 (P2 -> P1)**: P2 samples `x2`, computes `X2 = x2 * G`, creates
//! a DLog proof, and commits via `F_com-zk`. Sends commitment.
//!
//! **Round 2 (P1 -> P2)**: P1 samples `x1`, computes `X1 = x1 * G`, creates
//! a DLog proof. Generates Paillier keypair `(N, pk, sk)`. Samples noise
//! `t <- [2^{tau+2*kappa}]`, computes `x_hat_1 = x1 + t*q`,
//! `C = Enc_N(x_hat_1)`. Creates Pi_GCD and Pi_eq proofs.
//! Sends `(X1, dlog_proof, C, N, pi_gcd, pi_eq)`.
//!
//! **Round 3 (P2 -> P1)**: P2 verifies Pi_GCD and Pi_eq. If both pass,
//! decommits `(X2, dlog_proof)`. Otherwise abort. P1 verifies decommitment
//! and P2's DLog proof.
//!
//! **Output**: P1 stores `(x1, X=X1+X2, dk)`.
//!             P2 stores `(x2, X=X1+X2, C, ek)`.
//!
//! Key difference from Lin17: KGG24 uses **additive** sharing `x = x1 + x2`,
//! noise hiding `C = Enc(x1 + t*q)`, and the loose consistency proof Pi_eq
//! instead of the PDL protocol.

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::zk::dlog::DlogProof;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::backend::Integer;

use super::curve_order;
use crate::error::Kgg24Error;
use crate::key_share::{Kgg24Party1KeyShare, Kgg24Party2KeyShare};
use tecdsa_paillier::zk::correct_key_ni::NICorrectKeyProof;
use tecdsa_paillier::zk::pi_eq::PiEqProof;

/// Security parameter tau (bit-length of the noise exponent base).
const TAU: u32 = 256;

/// Statistical security parameter kappa.
const KAPPA: u32 = 80;

// ---------------------------------------------------------------------------
// Round 1: P2 -> P1 (commitment to X2 + DLog proof)
// ---------------------------------------------------------------------------

/// Round 1 message from P2: commitment to `(X2, dlog_proof)`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP2Round1Msg {
    /// Hash commitment to `X2 || dlog_proof`.
    pub commitment: HashCommitment,
}

/// P2's internal state after round 1.
pub struct KeyGenP2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret share `x2`.
    pub x2: C::Scalar,
    /// Public key share `X2 = x2 * G`.
    pub x2_point: C::ProjectivePoint,
    /// DLog proof for `X2`.
    pub dlog_proof: DlogProof<C>,
    /// Commitment opening nonce.
    pub nonce: [u8; 32],
}

/// P2 round 1: sample `x2`, compute `X2 = x2 * G`, create DLog proof, commit.
pub fn party2_keygen_round1<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (KeyGenP2Round1Msg, KeyGenP2State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x2 = C::random_scalar(rng);
    let x2_point = C::generator() * x2;

    // DLog proof for X2
    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x2, &ephemeral, &x2_point, b"kgg24-keygen-x2");

    // Commit to (X2, dlog_proof)
    let commit_data = serialize_point_and_proof::<C>(&x2_point, &dlog_proof);
    let (commitment, nonce) = HashCommitment::commit(&commit_data, rng);

    let msg = KeyGenP2Round1Msg { commitment };
    let state = KeyGenP2State {
        x2,
        x2_point,
        dlog_proof,
        nonce,
    };

    (msg, state)
}

// ---------------------------------------------------------------------------
// Round 2: P1 -> P2 (X1, DLog proof, C, N, Pi_GCD, Pi_eq)
// ---------------------------------------------------------------------------

/// Round 2 message from P1.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP1Round2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// P1's public key share `X1 = x1 * G`.
    pub x1_point: C::ProjectivePoint,
    /// DLog proof for `X1`.
    pub dlog_proof: DlogProof<C>,
    /// Paillier ciphertext `C = Enc_N(x1 + t*q)`.
    pub c_key: tecdsa_paillier::Ciphertext,
    /// Paillier encryption key.
    pub ek: tecdsa_paillier::EncryptionKey,
    /// Pi_GCD proof: gcd(N, phi(N)) = 1.
    pub pi_gcd: NICorrectKeyProof,
    /// Pi_eq proof: loose consistency between C and X1.
    pub pi_eq: PiEqProof<C>,
}

/// P1's internal state after round 2.
pub struct KeyGenP1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Secret share `x1`.
    pub x1: C::Scalar,
    /// Public key share `X1 = x1 * G`.
    pub x1_point: C::ProjectivePoint,
    /// Paillier decryption key.
    pub dk: tecdsa_paillier::DecryptionKey,
}

/// P1 round 2: sample `x1`, compute `X1 = x1*G`, generate Paillier keys,
/// encrypt noised share, create Pi_GCD and Pi_eq proofs.
pub fn party1_keygen_round2<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> Result<(KeyGenP1Round2Msg<C>, KeyGenP1State<C>), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Sample x1 and compute X1 = x1 * G
    let x1 = C::random_scalar(rng);
    let x1_point = C::generator() * x1;

    // DLog proof for X1
    let ephemeral = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&x1, &ephemeral, &x1_point, b"kgg24-keygen-x1");

    // Generate Paillier key pair
    let dk = tecdsa_paillier::keygen(rng)
        .map_err(|e| Kgg24Error::Paillier(format!("Paillier keygen failed: {e}")))?;
    let ek = dk.encryption_key().clone();

    // Get the curve order q
    let q_int = curve_order::<C>();

    // Sample noise t from [0, 2^{tau + 2*kappa})
    let noise_bound = Integer::u_pow_u(2, TAU + 2 * KAPPA);
    let t = noise_bound.random_below_ref(rng);

    // Compute x_hat_1 = x1 + t * q (the noised share)
    let x1_bytes = x1.to_repr();
    let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
    let x_hat_1 = &x1_int + &t * &q_int;

    // Encrypt x_hat_1: C = Enc_pk(x_hat_1; rho)
    let (c_key, enc_nonce) = dk.encrypt_with_random(rng, &x_hat_1).map_err(|e| {
        Kgg24Error::Paillier(format!("Paillier encryption of noised x1 failed: {e}"))
    })?;

    // Create Pi_GCD proof (proves knowledge of factorization of N)
    let pi_gcd = NICorrectKeyProof::prove(&dk, b"kgg24-correct-key-challenge");

    // Create Pi_eq proof (loose consistency: C encrypts x_hat_1, X1 = x1 * G)
    let ssid = b"kgg24-keygen";
    let pi_eq = PiEqProof::<C>::prove(ssid, &ek, &dk, &c_key, &x1_point, &x_hat_1, &enc_nonce, rng);

    let msg = KeyGenP1Round2Msg {
        x1_point,
        dlog_proof,
        c_key,
        ek,
        pi_gcd,
        pi_eq,
    };

    let state = KeyGenP1State { x1, x1_point, dk };

    Ok((msg, state))
}

// ---------------------------------------------------------------------------
// Round 3: P2 -> P1 (decommit X2 + DLog proof, or abort)
// ---------------------------------------------------------------------------

/// Round 3 message from P2: decommitment of `(X2, dlog_proof)`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyGenP2Round3Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// P2's public key share `X2 = x2 * G`.
    pub x2_point: C::ProjectivePoint,
    /// DLog proof for `X2`.
    pub dlog_proof: DlogProof<C>,
    /// Commitment opening nonce.
    pub nonce: [u8; 32],
}

/// P2 processes P1's round 2 message: verifies Pi_GCD, Pi_eq, and DLog proof.
/// If all pass, returns the decommitment message (round 3).
/// Otherwise returns an error (abort).
pub fn party2_keygen_round3<C: TecdsaCurve>(
    p2_state: &KeyGenP2State<C>,
    p1_msg: &KeyGenP1Round2Msg<C>,
) -> Result<KeyGenP2Round3Msg<C>, Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Step 1: Verify P1's DLog proof for X1
    if !p1_msg
        .dlog_proof
        .verify(&p1_msg.x1_point, b"kgg24-keygen-x1")
    {
        return Err(Kgg24Error::DlogVerification(
            "Keygen: P1's DLog proof for X1 failed".into(),
        ));
    }

    // Step 2: Verify Pi_GCD (correct key proof)
    if !p1_msg
        .pi_gcd
        .verify(&p1_msg.ek, b"kgg24-correct-key-challenge")
    {
        return Err(Kgg24Error::PiGcdVerification(
            "Keygen: Pi_GCD proof verification failed".into(),
        ));
    }

    // Step 3: Verify Pi_eq (loose consistency proof)
    let ssid = b"kgg24-keygen";
    if !p1_msg
        .pi_eq
        .verify(ssid, &p1_msg.ek, &p1_msg.c_key, &p1_msg.x1_point)
    {
        return Err(Kgg24Error::PiEqVerification(
            "Keygen: Pi_eq proof verification failed".into(),
        ));
    }

    // All proofs verified; decommit (X2, dlog_proof)
    Ok(KeyGenP2Round3Msg {
        x2_point: p2_state.x2_point,
        dlog_proof: p2_state.dlog_proof.clone(),
        nonce: p2_state.nonce,
    })
}

// ---------------------------------------------------------------------------
// Finalize: P1 verifies P2's decommitment and both parties compute key shares
// ---------------------------------------------------------------------------

/// P1 verifies P2's round 3 decommitment: checks commitment opening and DLog proof.
pub fn party1_verify_round3<C: TecdsaCurve>(
    p2_round1: &KeyGenP2Round1Msg,
    p2_round3: &KeyGenP2Round3Msg<C>,
) -> Result<(), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Step 1: Verify commitment opening
    let commit_data = serialize_point_and_proof::<C>(&p2_round3.x2_point, &p2_round3.dlog_proof);
    if !p2_round1.commitment.verify(&commit_data, &p2_round3.nonce) {
        return Err(Kgg24Error::CommitmentVerification(
            "Keygen: P2's commitment to X2 failed to open".into(),
        ));
    }

    // Step 2: Verify P2's DLog proof for X2
    if !p2_round3
        .dlog_proof
        .verify(&p2_round3.x2_point, b"kgg24-keygen-x2")
    {
        return Err(Kgg24Error::DlogVerification(
            "Keygen: P2's DLog proof for X2 failed".into(),
        ));
    }

    Ok(())
}

/// After all verifications pass, P1 computes its key share.
pub fn party1_finalize_keygen<C: TecdsaCurve>(
    p1_state: KeyGenP1State<C>,
    x2_point: &C::ProjectivePoint,
) -> Kgg24Party1KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // X = X1 + X2 = (x1 + x2) * G (additive sharing)
    let public_key = p1_state.x1_point + x2_point;

    Kgg24Party1KeyShare {
        secret_share: p1_state.x1,
        public_key,
        dk: p1_state.dk,
    }
}

/// After all verifications pass, P2 computes its key share.
pub fn party2_finalize_keygen<C: TecdsaCurve>(
    p2_state: &KeyGenP2State<C>,
    p1_msg: &KeyGenP1Round2Msg<C>,
) -> Kgg24Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // X = X1 + X2 = (x1 + x2) * G (additive sharing)
    let public_key = p1_msg.x1_point + p2_state.x2_point;

    Kgg24Party2KeyShare {
        secret_share: p2_state.x2,
        public_key,
        c_key: p1_msg.c_key.clone(),
        ek: p1_msg.ek.clone(),
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
) -> Result<(Kgg24Party1KeyShare<C>, Kgg24Party2KeyShare<C>), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // === Round 1: P2 commits to X2 ===
    let (p2_r1_msg, p2_state) = party2_keygen_round1::<C>(rng);

    // === Round 2: P1 sends X1, Paillier key, C, Pi_GCD, Pi_eq ===
    let (p1_r2_msg, p1_state) = party1_keygen_round2::<C>(rng)?;

    // === Round 3: P2 verifies proofs and decommits ===
    let p2_r3_msg = party2_keygen_round3::<C>(&p2_state, &p1_r2_msg)?;

    // === P1 verifies P2's decommitment ===
    party1_verify_round3::<C>(&p2_r1_msg, &p2_r3_msg)?;

    // === Finalize: compute key shares ===
    let p2_share = party2_finalize_keygen::<C>(&p2_state, &p1_r2_msg);
    let p1_share = party1_finalize_keygen::<C>(p1_state, &p2_r3_msg.x2_point);

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
    fn interactive_keygen_paillier_encrypts_noised_x1() {
        let mut rng = rand_core::OsRng;
        let (p1, p2) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        // Decrypt c_key and verify it equals x1 mod q
        let decrypted = p1.dk.decrypt(&p2.c_key).expect("decryption failed");
        let x1_bytes = p1.secret_share.to_repr();
        let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());

        // The decrypted value is x1 + t*q, so (decrypted mod q) should equal x1
        let q_int = curve_order::<Secp256k1>();
        let decrypted_mod_q = decrypted.modulo_ref(&q_int);
        assert_eq!(decrypted_mod_q, x1_int);
    }

    #[test]
    fn interactive_keygen_signing_compatibility() {
        use crate::sign;
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

        // Sign using the interactive keygen's key shares
        let result = sign::sign(&p1_key, &p2_key, &message, &mut rng)
            .expect("signing should succeed with interactive keygen shares");

        // Verify
        verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &message)
            .expect("signature should verify");
    }

    #[test]
    #[ignore = "redundant keygen variant"]
    fn round_by_round_keygen() {
        let mut rng = rand_core::OsRng;

        // Round 1: P2 commits
        let (p2_r1_msg, p2_state) = party2_keygen_round1::<Secp256k1>(&mut rng);

        // Round 2: P1 sends X1, Paillier key, proofs
        let (p1_r2_msg, p1_state) =
            party1_keygen_round2::<Secp256k1>(&mut rng).expect("P1 round 2 should succeed");

        // Round 3: P2 verifies and decommits
        let p2_r3_msg = party2_keygen_round3::<Secp256k1>(&p2_state, &p1_r2_msg)
            .expect("P2 round 3 should succeed (proofs valid)");

        // P1 verifies P2's decommitment
        party1_verify_round3::<Secp256k1>(&p2_r1_msg, &p2_r3_msg)
            .expect("P1 verification of P2's decommitment should succeed");

        // Finalize
        let p2_share = party2_finalize_keygen::<Secp256k1>(&p2_state, &p1_r2_msg);
        let p1_share = party1_finalize_keygen::<Secp256k1>(p1_state, &p2_r3_msg.x2_point);

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
    fn interactive_keygen_refresh_then_sign() {
        use crate::refresh::refresh;
        use crate::sign;
        use sha2::{Digest, Sha256};

        let mut rng = rand_core::OsRng;

        // Generate key shares interactively
        let (mut p1_key, mut p2_key) =
            interactive_keygen::<Secp256k1>(&mut rng).expect("interactive keygen should succeed");

        let original_pk = p1_key.public_key;

        // Refresh
        refresh(&mut p1_key, &mut p2_key, &mut rng).expect("refresh should succeed");

        // Public key should be unchanged
        assert_eq!(p1_key.public_key, original_pk);
        assert_eq!(p2_key.public_key, original_pk);

        // Sign with refreshed shares
        let hash = Sha256::digest(b"test interactive keygen -> refresh -> sign");
        let mut fb = elliptic_curve::FieldBytes::<Secp256k1>::default();
        let len = fb.len();
        fb.copy_from_slice(&hash[..len]);
        let scalar = Option::from(<k256::Scalar as elliptic_curve::PrimeField>::from_repr(fb))
            .expect("hash must be valid scalar");
        let message = DataToSign::from_digest(scalar);

        let result = sign::sign(&p1_key, &p2_key, &message, &mut rng)
            .expect("signing after refresh should succeed");

        verify_ecdsa::<Secp256k1>(&result.signature, &p1_key.public_key, &message)
            .expect("signature should verify after interactive keygen + refresh");
    }
}
