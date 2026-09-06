// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signing protocol for KGG24 two-party ECDSA (Section 4 / Figure 6).
//!
//! The signing protocol has 3 messages exchanged between two parties with
//! asymmetric roles (Party 1 = server, Party 2 = client):
//!
//! 1. **P_1 -> P_2**: Commit to `R_1 = k_1 * G` with DLog proof
//! 2. **P_2 -> P_1**: Send `R_2 = k_2 * G` with DLog proof
//! 3. **P_1 -> P_2**: Decommit `R_1` (reveal commitment opening + DLog proof)
//! 4. **P_2 -> P_1**: Send `c_3` (Paillier ciphertext of partial signature)
//!
//! After receiving `c_3`, P_1 decrypts, performs the divisibility check, computes
//! the final signature, verifies it, and outputs.
//!
//! ## ECDSA Equation (additive sharing)
//!
//! With additive sharing `x = x_1 + x_2` and multiplicative nonce `k = k_1 * k_2`:
//! ```text
//! s = k^{-1}(m + rx) = k_1^{-1} * k_2^{-1} * (m + r*(x_1 + x_2))
//! ```
//!
//! P_2 computes via Paillier homomorphism:
//! ```text
//! c_1 = Enc(rho*q + k_tilde_2_inv * m')            -- encrypted message contribution
//! c_2 = C ^{r * k_tilde_2_inv}                     -- encrypted x_1 contribution (via c_key)
//! c_3 = c_1 (+) c_2                                -- homomorphic add
//! ```
//!
//! where `k_tilde_2_inv = k_2^{-1} + rho_bar * q` is the blinded inverse.
//!
//! Decryption gives: `k_2^{-1}*(m + r*x_2) + r*k_2^{-1}*(x_1 + t*q) + noise`
//! After mod q: `k_2^{-1}*(m + r*(x_1 + x_2))` (the t*q and rho*q terms vanish)
//!
//! P_1 computes: `s = k_1^{-1} * [dec(c_3)]_q = k^{-1}(m + rx)`
//!
//! ## Divisibility check (Section 4, no global abort)
//!
//! P_1 checks: `s_2 = s_0 - s_1 + ell*q` is `< N / 2^{tau+2*kappa}` and `== 0 (mod q)`.
//! If this fails, the protocol sets a `needs_refresh` flag but still tries to
//! output a valid signature. A subsequent refresh replaces the corrupted shares.

use elliptic_curve::{
    group::Curve as CurveGroup, ops::LinearCombination, sec1::ModulusSize, Field, FieldBytes,
    FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::BigIntExt;
use tecdsa_protocol::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    error::Kgg24Error,
    key_share::{Kgg24Party1KeyShare, Kgg24Party2KeyShare},
    keygen::curve_order,
};

/// Security parameter tau (bit-length of the noise exponent base).
const TAU: u32 = 256;

/// Statistical security parameter kappa.
const KAPPA: u32 = 80;

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

/// Message from P_2 to P_1: Paillier ciphertext of partial signature.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party2PartialSigMsg {
    /// `c_3 = Enc(rho*q + k_tilde_2_inv*m' + r*k_tilde_2_inv*x_2) (+) (C ^ (r*k_tilde_2_inv))`.
    #[cfg_attr(feature = "serde", serde(with = "tecdsa_bigint::int_wire"))]
    pub c3: tecdsa_paillier::Ciphertext,
}

/// Result of Party 1's finalization, including whether a refresh is needed.
pub struct SignResult<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The ECDSA signature, if valid.
    pub signature: Signature<C>,
    /// Whether the divisibility check failed, indicating a refresh should be performed.
    pub needs_refresh: bool,
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
    let dlog_proof = DlogProof::<C>::prove(&k1, &ephemeral_nonce, &r1, b"kgg24-sign-r1");

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
pub fn party1_round3<C: TecdsaCurve>(party2_msg: &Party2Round2Msg<C>) -> Result<(), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify P_2's DLog proof for R_2
    if !party2_msg
        .dlog_proof
        .verify(&party2_msg.r2, b"kgg24-sign-r2")
    {
        return Err(Kgg24Error::DlogVerification(
            "Party 2 ephemeral DLog proof failed".into(),
        ));
    }
    Ok(())
}

/// Party 1, Final: decrypt partial signature, perform divisibility check,
/// compute and verify final ECDSA signature.
///
/// Given `c_3` from P_2, P_1:
/// 1. Computes `R = k_1 * R_2`, `r = x_coord(R) mod q`
/// 2. Decrypts `s_0 = Dec(c_3)`
/// 3. Computes `s_1 = [s_0]_q` (reduce mod q)
/// 4. Performs divisibility check on `s_2 = s_0 - s_1 + ell*q`
/// 5. Computes `s = k_1^{-1} * s_1 mod q`, applies low-S
/// 6. Verifies the signature and outputs `(r, s)` with refresh flag
pub fn party1_finalize<C: TecdsaCurve>(
    key_share: &Kgg24Party1KeyShare<C>,
    state: &Party1SignState<C>,
    party2_r2: &C::ProjectivePoint,
    party2_msg: &Party2PartialSigMsg,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignResult<C>, Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    // Compute R = k_1 * R_2
    let r_point = *party2_r2 * state.k1;
    let r_affine = r_point.to_affine();
    let r = C::xcoord_mod_q(&r_affine);

    // Decrypt c_3 to get s_0
    let s0_int = key_share
        .dk
        .decrypt(&party2_msg.c3)
        .map_err(|e| Kgg24Error::Paillier(format!("decryption failed: {e}")))?;

    // Compute s_1 = [s_0]_q (reduce mod q)
    let q_int = curve_order::<C>();
    let s1_int = tecdsa_paillier::backend::Integer::from(s0_int.modulo_ref(&q_int));

    // --- Divisibility check (Section 4) ---
    // s_2 = s_0 - s_1 + ell * q where ell is random in [0, q^2 * 2^{tau+kappa})
    let ell_bound = tecdsa_paillier::backend::Integer::from(&q_int * &q_int)
        * tecdsa_paillier::backend::Integer::two_pow(TAU + KAPPA);
    let ell = ell_bound.sample_below_ref(rng);
    let s2_int = (s0_int - &s1_int) + (ell * &q_int);

    // Check: s_2 < N / 2^{tau + 2*kappa}
    let n = key_share.dk.encryption_key().n().clone();
    let divisor = tecdsa_paillier::backend::Integer::two_pow(TAU + 2 * KAPPA);
    let threshold = n / divisor;

    let needs_refresh = if s2_int.cmp_abs(&threshold) == std::cmp::Ordering::Greater {
        true
    } else {
        // Check: s_2 == 0 (mod q)
        let s2_mod_q = s2_int.modulo(&q_int);
        s2_mod_q != tecdsa_paillier::backend::Integer::zero()
    };

    // --- Compute the actual signature regardless of the divisibility check ---
    // Convert s_1 to scalar
    let s_prime_scalar = int_to_scalar::<C>(&s1_int);

    // Compute s = k_1^{-1} * s_1 mod q
    let k1_inv = state
        .k1
        .invert()
        .into_option()
        .ok_or_else(|| Kgg24Error::ProtocolState("k_1 is zero, cannot invert".into()))?;
    let s_double_prime = k1_inv * s_prime_scalar;

    // Low-S normalization: s = min(s'', q - s'')
    let s = low_s_normalize::<C>(s_double_prime);

    let signature = Signature { r, s };

    // Verify the signature before outputting
    verify_ecdsa::<C>(&signature, &key_share.public_key, message).map_err(|e| {
        Kgg24Error::EcdsaVerification(format!("final signature verification failed: {e}"))
    })?;

    Ok(SignResult {
        signature,
        needs_refresh,
    })
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
    let dlog_proof = DlogProof::<C>::prove(&k2, &ephemeral_nonce, &r2, b"kgg24-sign-r2");

    let msg = Party2Round2Msg { r2, dlog_proof };
    let state = Party2SignState { k2, r2 };

    (msg, state)
}

/// Party 2: verify P_1's decommitment and compute partial signature.
///
/// Given P_1's decommitted `R_1` and DLog proof, P_2:
/// 1. Verifies the commitment opening
/// 2. Verifies the DLog proof for R_1
/// 3. Computes `R = k_2 * R_1`, `r = x_coord(R) mod q`
/// 4. Computes blinded inverse: `k_tilde_2_inv = k_2^{-1} + rho_bar * q`
/// 5. Computes `c_1 = Enc(rho*q + k_tilde_2_inv * m' + k_tilde_2_inv * r * x_2)`
/// 6. Computes `c_2 = C ^ (r * k_tilde_2_inv)` (homomorphic scalar mult on c_key)
/// 7. Computes `c_3 = c_1 (+) c_2` (homomorphic add)
/// 8. Sends `c_3` to P_1
pub fn party2_compute_partial_sig<C: TecdsaCurve>(
    key_share: &Kgg24Party2KeyShare<C>,
    state: &Party2SignState<C>,
    party1_round1: &Party1Round1Msg,
    party1_round3: &Party1Round3Msg<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Party2PartialSigMsg, Kgg24Error>
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
        return Err(Kgg24Error::CommitmentVerification(
            "Party 1 commitment opening failed".into(),
        ));
    }

    // Step 2: Verify DLog proof for R_1
    if !party1_round3
        .dlog_proof
        .verify(&party1_round3.r1, b"kgg24-sign-r1")
    {
        return Err(Kgg24Error::DlogVerification(
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
        .ok_or_else(|| Kgg24Error::ProtocolState("k_2 is zero, cannot invert".into()))?;

    let q_int = curve_order::<C>();

    // Blinded inverse: k_tilde_2_inv = [k_2^{-1}]_q + rho_bar * q
    // where rho_bar is sampled from [0, q)
    let rho_bar = q_int.sample_below_ref(rng);
    let k2_inv_bytes = scalar_to_bytes(&k2_inv);
    let k2_inv_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&k2_inv_bytes);
    let k_tilde_2_inv = k2_inv_int + rho_bar * &q_int;

    // Step 5: Compute the message digest as integer
    let m_prime = *message.digest();
    let m_prime_bytes = scalar_to_bytes(&m_prime);
    let m_prime_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&m_prime_bytes);

    // Get r as integer
    let r_bytes = scalar_to_bytes(&r);
    let r_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&r_bytes);

    // Get x_2 as integer
    let x2_bytes = scalar_to_bytes(&key_share.secret_share);
    let x2_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&x2_bytes);

    // Sample rho from [0, 3*q^3 * 2^{4*tau + 2*kappa}) for masking
    let q_cubed = tecdsa_paillier::backend::Integer::from(&q_int * &q_int) * &q_int;
    let rho_bound =
        (q_cubed * 3u8) * tecdsa_paillier::backend::Integer::two_pow(4 * TAU + 2 * KAPPA);
    let rho = rho_bound.sample_below_ref(rng);

    // Compute: partial_plaintext = rho * q + k_tilde_2_inv * m' + k_tilde_2_inv * r * x_2
    // This is the "message + P_2's share contribution" part
    let k_tilde_m = tecdsa_paillier::backend::Integer::from(&k_tilde_2_inv * &m_prime_int);
    let k_tilde_r_x2 = tecdsa_paillier::backend::Integer::from(&k_tilde_2_inv * &r_int) * &x2_int;
    let partial_plaintext = rho * q_int + &k_tilde_m + &k_tilde_r_x2;

    // Step 6: Encrypt partial_plaintext: c_1 = Enc(partial_plaintext)
    let (c1, _nonce) = key_share
        .ek
        .encrypt_with_random(rng, &partial_plaintext)
        .map_err(|e| Kgg24Error::Paillier(format!("encryption of partial_sig failed: {e}")))?;

    // Step 7: Compute c_2 = C ^ (r * k_tilde_2_inv) (homomorphic scalar mult on c_key)
    // This extracts r * k_tilde_2_inv * (x_1 + t*q) from C = Enc(x_1 + t*q)
    let scalar_for_c = r_int * k_tilde_2_inv;
    let c2 = key_share
        .ek
        .omul(&scalar_for_c, &key_share.c_key)
        .map_err(|e| Kgg24Error::Paillier(format!("homomorphic scalar mult failed: {e}")))?;

    // Step 8: c_3 = c_1 (+) c_2 (homomorphic add)
    let c3 = key_share
        .ek
        .oadd(&c1, &c2)
        .map_err(|e| Kgg24Error::Paillier(format!("homomorphic addition failed: {e}")))?;

    Ok(Party2PartialSigMsg { c3 })
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

use tecdsa_curve::conv::scalar_to_bytes;

fn int_to_scalar<C: TecdsaCurve>(value: &tecdsa_paillier::backend::Integer) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    tecdsa_curve::conv::bytes_to_scalar::<C>(&value.to_bytes_msf())
}

// ---------------------------------------------------------------------------
// End-to-end signing convenience function
// ---------------------------------------------------------------------------

/// Run the complete KGG24 two-party signing protocol and return the ECDSA signature.
///
/// This is a convenience function that runs all 3 rounds sequentially.
/// In a real deployment, messages would be exchanged over a network.
///
/// Returns `SignResult` containing both the signature and the `needs_refresh` flag.
pub fn sign<C: TecdsaCurve>(
    p1_key: &Kgg24Party1KeyShare<C>,
    p2_key: &Kgg24Party2KeyShare<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignResult<C>, Kgg24Error>
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

    // P_2 verifies P_1's decommitment and sends partial signature
    let p2_partial_msg = party2_compute_partial_sig::<C>(
        p2_key,
        &p2_state,
        &p1_round1_msg,
        &p1_decommit,
        message,
        rng,
    )?;

    // Finalize: P_1 decrypts, performs divisibility check, and verifies the signature
    party1_finalize::<C>(
        p1_key,
        &p1_state,
        &p2_state.r2,
        &p2_partial_msg,
        message,
        rng,
    )
}

/// Convenience function that returns only the signature (discarding the refresh flag).
pub fn sign_simple<C: TecdsaCurve>(
    p1_key: &Kgg24Party1KeyShare<C>,
    p2_key: &Kgg24Party2KeyShare<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Signature<C>, Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    sign(p1_key, p2_key, message, rng).map(|r| r.signature)
}
