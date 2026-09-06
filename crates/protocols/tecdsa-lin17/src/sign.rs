// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signing protocol for Lindell 2017 two-party ECDSA (Protocol 3.2).
//!
//! The signing protocol has 4 messages exchanged between two parties with
//! asymmetric roles (Party 1 = server, Party 2 = client):
//!
//! 1. **P_1 -> P_2**: Commit to `R_1 = k_1 * G` with DLog proof
//! 2. **P_2 -> P_1**: Send `R_2 = k_2 * G` with DLog proof
//! 3. **P_1 -> P_2**: Decommit `R_1` (reveal commitment opening + DLog proof)
//! 4. **P_2 -> P_1**: Send `c_3` (Paillier ciphertext of partial signature)
//!
//! After round 4, P_1 decrypts, computes the final signature, verifies it, and outputs.
//!
//! ## ECDSA Equation
//!
//! The protocol computes:
//! ```text
//! s = k_1^{-1} * (rho*q + k_2^{-1} * m' + k_2^{-1} * r * x_2 * x_1) mod q
//!   = k^{-1} * (m' + r * x) mod q
//! ```
//! where `k = k_1 * k_2` and `x = x_1 * x_2`.

use elliptic_curve::{
    group::Curve as CurveGroup, ops::LinearCombination, sec1::ModulusSize, Field, FieldBytes,
    FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use rug::Integer;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, ScalarExt, TecdsaCurve};
use tecdsa_paillier::BigIntExt;
use tecdsa_protocol::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    error::Lin17Error,
    key_share::{Lin17Party1KeyShare, Lin17Party2KeyShare},
};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Round 1 message from P_1: commitment to R_1 and DLog proof.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party1Round1Msg {
    /// Hash commitment to `R_1 || dlog_proof`.
    pub commitment: HashCommitment,
}

/// Round 2 message from P_2: ephemeral public key and DLog proof.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party2Round2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Ephemeral public key `R_2 = k_2 * G`.
    pub r2: C::ProjectivePoint,
    /// DLog proof for `R_2`.
    pub dlog_proof: DlogProof<C>,
}

/// Round 3 message from P_1: decommitment of R_1 with DLog proof.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party1Round3Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Ephemeral public key `R_1 = k_1 * G`.
    pub r1: C::ProjectivePoint,
    /// DLog proof for `R_1`.
    pub dlog_proof: DlogProof<C>,
    /// Commitment opening nonce.
    pub nonce: [u8; 32],
}

/// Round 4 message from P_2: Paillier ciphertext of partial signature.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party2Round4Msg {
    /// `c_3 = Enc(rho*q + k_2^{-1}*m') (+) (c_key ^ (k_2^{-1} * r * x_2))`.
    #[cfg_attr(feature = "serde", serde(with = "tecdsa_bigint::int_wire"))]
    pub c3: tecdsa_paillier::Ciphertext,
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a ProjectivePoint + DlogProof to bytes for commitment.
fn serialize_r1_and_proof<C: TecdsaCurve>(r1: &C::ProjectivePoint, proof: &DlogProof<C>) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::group::GroupEncoding;
    let mut data = Vec::new();
    data.extend_from_slice(r1.to_bytes().as_ref());
    data.extend_from_slice(proof.commitment.to_bytes().as_ref());
    data.extend_from_slice(proof.response.to_repr().as_ref());
    data
}

// ---------------------------------------------------------------------------
// Party 1 signing functions
// ---------------------------------------------------------------------------

/// Party 1 ephemeral state during signing.
pub struct Party1SignState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Ephemeral secret `k_1`.
    pub k1: C::Scalar,
    /// Ephemeral public key `R_1 = k_1 * G`.
    pub r1: C::ProjectivePoint,
}

/// Party 1, Round 1: generate ephemeral key pair and commit.
///
/// Returns `(message, state, commitment_data)` where `commitment_data` contains
/// the decommitment info needed for round 3.
pub fn party1_round1<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Party1Round1Msg, Party1SignState<C>, Party1Round3Msg<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Sample ephemeral secret k_1
    let k1 = C::random_scalar(rng);
    let r1 = C::generator() * k1;

    // Create DLog proof for R_1 = k_1 * G
    let ephemeral_nonce = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&k1, &ephemeral_nonce, &r1, b"lin17-sign-r1");

    // Commit to R_1 and the DLog proof
    let commit_data = serialize_r1_and_proof::<C>(&r1, &dlog_proof);
    let (commitment, nonce) = HashCommitment::commit(&commit_data, rng);

    let msg = Party1Round1Msg { commitment };
    let state = Party1SignState { k1, r1 };
    let decommit = Party1Round3Msg {
        r1,
        dlog_proof,
        nonce,
    };

    (msg, state, decommit)
}

/// Party 1, Round 3: verify P_2's DLog proof and return decommitment.
///
/// This is a validation step; the decommitment message was already prepared
/// in round 1. Returns an error if P_2's proof is invalid.
pub fn party1_round3<C: TecdsaCurve>(party2_msg: &Party2Round2Msg<C>) -> Result<(), Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify P_2's DLog proof for R_2
    if !party2_msg
        .dlog_proof
        .verify(&party2_msg.r2, b"lin17-sign-r2")
    {
        return Err(Lin17Error::DlogVerification(
            "Party 2 ephemeral DLog proof failed".into(),
        ));
    }
    Ok(())
}

/// Party 1, Final: decrypt partial signature, compute and verify final ECDSA signature.
///
/// Given `c_3` from P_2, P_1:
/// 1. Computes `R = k_1 * R_2`, `r = x_coord(R) mod q`
/// 2. Decrypts `s' = Dec(c_3)`
/// 3. Computes `s'' = k_1^{-1} * s' mod q`
/// 4. Sets `s = min(s'', q - s'')` (low-S normalization)
/// 5. Verifies the signature and outputs `(r, s)`
pub fn party1_finalize<C: TecdsaCurve>(
    key_share: &Lin17Party1KeyShare<C>,
    state: &Party1SignState<C>,
    party2_r2: &C::ProjectivePoint,
    party2_msg: &Party2Round4Msg,
    message: &DataToSign<C>,
) -> Result<Signature<C>, Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    // Compute R = k_1 * R_2
    let r_point = *party2_r2 * state.k1;
    let r_affine = r_point.to_affine();
    let r = C::xcoord_mod_q(&r_affine);

    // Decrypt c_3 to get s'
    let s_prime_int = key_share
        .dk
        .decrypt(&party2_msg.c3)
        .map_err(|e| Lin17Error::Paillier(format!("decryption failed: {e}")))?;

    // Convert s' from big integer to scalar (reduce mod q)
    let s_prime_bytes = s_prime_int.to_bytes_msf();
    let s_prime_scalar = C::scalar_from_bytes(&s_prime_bytes);

    // Compute s'' = k_1^{-1} * s' mod q
    let k1_inv = state
        .k1
        .invert()
        .into_option()
        .ok_or_else(|| Lin17Error::ProtocolState("k_1 is zero, cannot invert".into()))?;
    let s_double_prime = k1_inv * s_prime_scalar;

    // Low-S normalization: s = min(s'', q - s'')
    let s = low_s_normalize::<C>(s_double_prime);

    let signature = Signature { r, s };

    // Verify the signature before outputting
    verify_ecdsa::<C>(&signature, &key_share.public_key, message).map_err(|e| {
        Lin17Error::EcdsaVerification(format!("final signature verification failed: {e}"))
    })?;

    Ok(signature)
}

// ---------------------------------------------------------------------------
// Party 2 signing functions
// ---------------------------------------------------------------------------

/// Party 2 ephemeral state during signing.
pub struct Party2SignState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Ephemeral secret `k_2`.
    pub k2: C::Scalar,
    /// Ephemeral public key `R_2 = k_2 * G`.
    pub r2: C::ProjectivePoint,
}

/// Party 2, Round 2: generate ephemeral key pair and DLog proof.
pub fn party2_round2<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Party2Round2Msg<C>, Party2SignState<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Sample ephemeral secret k_2
    let k2 = C::random_scalar(rng);
    let r2 = C::generator() * k2;

    // Create DLog proof for R_2 = k_2 * G
    let ephemeral_nonce = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&k2, &ephemeral_nonce, &r2, b"lin17-sign-r2");

    let msg = Party2Round2Msg { r2, dlog_proof };
    let state = Party2SignState { k2, r2 };

    (msg, state)
}

/// Party 2, Round 4: verify P_1's decommitment and compute partial signature.
///
/// Given P_1's decommitted `R_1` and DLog proof, P_2:
/// 1. Verifies the commitment opening
/// 2. Verifies the DLog proof for R_1
/// 3. Computes `R = k_2 * R_1`, `r = x_coord(R) mod q`
/// 4. Computes `c_1 = Enc(rho * q + k_2^{-1} * m')` with fresh randomness
/// 5. Computes `v = k_2^{-1} * r * x_2 mod q`
/// 6. Computes `c_2 = c_key ^ v` (Paillier homomorphic scalar mult)
/// 7. Computes `c_3 = c_1 (+) c_2` (Paillier homomorphic add)
/// 8. Sends `c_3` to P_1
pub fn party2_round4<C: TecdsaCurve>(
    key_share: &Lin17Party2KeyShare<C>,
    state: &Party2SignState<C>,
    party1_round1: &Party1Round1Msg,
    party1_round3: &Party1Round3Msg<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Party2Round4Msg, Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Step 1: Verify commitment opening
    let commit_data = serialize_r1_and_proof::<C>(&party1_round3.r1, &party1_round3.dlog_proof);
    if !party1_round1
        .commitment
        .verify(&commit_data, &party1_round3.nonce)
    {
        return Err(Lin17Error::CommitmentVerification(
            "Party 1 commitment opening failed".into(),
        ));
    }

    // Step 2: Verify DLog proof for R_1
    if !party1_round3
        .dlog_proof
        .verify(&party1_round3.r1, b"lin17-sign-r1")
    {
        return Err(Lin17Error::DlogVerification(
            "Party 1 ephemeral DLog proof failed".into(),
        ));
    }

    // Step 3: Compute R = k_2 * R_1, r = x_coord(R) mod q
    let r_point = party1_round3.r1 * state.k2;
    let r_affine = r_point.to_affine();
    let r = C::xcoord_mod_q(&r_affine);

    // Step 4: Compute k_2^{-1} mod q
    let k2_inv = state
        .k2
        .invert()
        .into_option()
        .ok_or_else(|| Lin17Error::ProtocolState("k_2 is zero, cannot invert".into()))?;

    // Get the message digest as a scalar
    let m_prime = *message.digest();

    // Sample rho from Z_{q^2} for masking
    // q is the curve order. We need q^2 as the sampling range.
    let q_int = C::order();
    let q_squared = Integer::from(&q_int * &q_int);

    // rho <- Z_{q^2}: sample a random value in [0, q^2)
    let rho = q_squared.sample_below_ref(rng);

    // Compute: rho * q + k_2^{-1} * m' mod q
    let k2_inv_bytes = k2_inv.to_bytes_vec();
    let k2_inv_int = Integer::from_bytes_msf(&k2_inv_bytes);

    let m_prime_bytes = m_prime.to_bytes_vec();
    let m_prime_int = Integer::from_bytes_msf(&m_prime_bytes);

    // k_2^{-1} * m' mod q
    let k2inv_m = Integer::from(&k2_inv_int * &m_prime_int) % &q_int;

    // partial_sig = rho * q + (k_2^{-1} * m' mod q)
    let partial_sig = rho * &q_int + &k2inv_m;

    // Step 5: Encrypt partial_sig: c_1 = Enc(partial_sig)
    let (c1, _nonce) = key_share
        .ek
        .encrypt_with_random(rng, &partial_sig)
        .map_err(|e| Lin17Error::Paillier(format!("encryption of partial_sig failed: {e}")))?;

    // Step 6: Compute v = k_2^{-1} * r * x_2 mod q
    let r_bytes = r.to_bytes_vec();
    let r_int = Integer::from_bytes_msf(&r_bytes);

    let x2_bytes = key_share.secret_share.to_bytes_vec();
    let x2_int = Integer::from_bytes_msf(&x2_bytes);

    let r_x2_mod_q = (r_int * x2_int) % &q_int;
    let v = (k2_inv_int * r_x2_mod_q) % q_int;

    // Step 7: c_2 = c_key ^ v (Paillier homomorphic scalar multiplication)
    let c2 = key_share
        .ek
        .omul(&v, &key_share.c_key)
        .map_err(|e| Lin17Error::Paillier(format!("homomorphic scalar mult failed: {e}")))?;

    // Step 8: c_3 = c_1 (+) c_2 (Paillier homomorphic addition)
    let c3 = key_share
        .ek
        .oadd(&c1, &c2)
        .map_err(|e| Lin17Error::Paillier(format!("homomorphic addition failed: {e}")))?;

    Ok(Party2Round4Msg { c3 })
}

// ---------------------------------------------------------------------------
// Utility functions (delegating to tecdsa_curve::conv)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// End-to-end signing convenience function
// ---------------------------------------------------------------------------

/// Run the complete Lin17 two-party signing protocol and return the ECDSA signature.
///
/// This is a convenience function that runs all 4 rounds sequentially.
/// In a real deployment, messages would be exchanged over a network.
pub fn sign<C: TecdsaCurve>(
    p1_key: &Lin17Party1KeyShare<C>,
    p2_key: &Lin17Party2KeyShare<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Signature<C>, Lin17Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    // Round 1: P_1 commits to R_1
    let (p1_round1_msg, p1_state, p1_decommit) = party1_round1::<C>(rng);

    // Round 2: P_2 sends R_2 + DLog proof
    let (p2_round2_msg, p2_state) = party2_round2::<C>(rng);

    // Round 3: P_1 verifies P_2's proof and decommits R_1
    party1_round3::<C>(&p2_round2_msg)?;

    // Round 4: P_2 verifies P_1's decommitment and sends partial signature
    let p2_round4_msg = party2_round4::<C>(
        p2_key,
        &p2_state,
        &p1_round1_msg,
        &p1_decommit,
        message,
        rng,
    )?;

    // Finalize: P_1 decrypts and verifies the signature
    party1_finalize::<C>(p1_key, &p1_state, &p2_state.r2, &p2_round4_msg, message)
}
