// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline signing protocol for XAL+21 (3 steps, message-independent).
//!
//! The offline phase prepares a presignature that can later be used with the
//! online phase to sign any message. It consists of 3 logical steps:
//!
//! ## Step 1 -- Commit P_2's nonce
//!
//! P_2 samples `k_2`, computes `R_2 = k_2 * G`, and sends a commitment
//! `f_2 = H(R_2, nizk3)` to P_1.
//!
//! ## Step 2 -- MtA and re-sharing consistency check
//!
//! P_1 samples `x'_1` and runs `MtA(x'_1, k_2)` with P_2.
//! P_1 then computes `cc = t_A + x'_1 * r_1 - x_1 mod q` and sends
//! `(Q'_1, r_1, cc)` to P_2.
//!
//! P_2 verifies the consistency check:
//!   `(t_B + cc) * G == (r_1 + k_2) * Q'_1 - Q_1`
//!
//! P_2 then computes `x'_2 = x_2 - (t_B + cc) mod q`.
//!
//! ## Step 3 -- Nonce key exchange
//!
//! P_1 samples `k_1`, computes `R_1 = k_1 * G`, and sends `(R_1, nizk4)`.
//! P_2 verifies `nizk4` and sends `(R_2, nizk3)`.
//! P_1 verifies the commitment `f_2` and `nizk3`.
//!
//! Both compute `R = k_1 * (k_2 + r_1) * G` and `r = x_coord(R) mod q`.
//!
//! ## Correctness
//!
//! After the offline phase:
//! - `x'_1 * (k_2 + r_1) + x'_2 = x` (re-sharing correctness)
//! - `k = k_1 * (r_1 + k_2)` (linear nonce)
//!
//! ## MtA Genericity
//!
//! The MtA sub-protocol is abstracted via the `tecdsa_protocol::MtA` trait.
//! By default, `PaillierMtA` is used, but any backend implementing `MtA`
//! can be substituted.

use elliptic_curve::{
    group::Curve as CurveGroup, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_protocol::MtA;

use crate::{
    error::Xal21Error,
    key_share::{Xal21Party1KeyShare, Xal21Party2KeyShare},
    keygen::{curve_order, int_to_scalar},
};

/// Default MtA backend: Paillier-based MtA with Alice/Bob range proofs.
pub type DefaultMtA = tecdsa_paillier::mta::PaillierMtA<tecdsa_paillier::mta::Gg18Proofs>;

// ---------------------------------------------------------------------------
// Presignature output types
// ---------------------------------------------------------------------------

/// Party 1's presignature output from the offline phase.
///
/// Contains all the state P_1 needs for the online signing phase.
pub struct Party1Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Ephemeral secret `k_1`.
    pub k1: C::Scalar,
    /// Re-shared secret `x'_1`.
    pub x1_prime: C::Scalar,
    /// The ECDSA nonce-derived value `r = x_coord(R) mod q`.
    pub r: C::Scalar,
    /// The joint nonce point `R`.
    pub R: C::ProjectivePoint,
}

/// Party 2's presignature output from the offline phase.
///
/// Contains all the state P_2 needs for the online signing phase.
pub struct Party2Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// P_2's nonce `k_2`.
    pub k2: C::Scalar,
    /// P_1's blinding factor `r_1` (received during step 2).
    pub r1: C::Scalar,
    /// Re-shared secret `x'_2`.
    pub x2_prime: C::Scalar,
    /// The ECDSA nonce-derived value `r = x_coord(R) mod q`.
    pub r: C::Scalar,
}

impl<C: TecdsaCurve> zeroize::Zeroize for Party1Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k1.zeroize();
        self.x1_prime.zeroize();
    }
}

impl<C: TecdsaCurve> Drop for Party1Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl<C: TecdsaCurve> zeroize::Zeroize for Party2Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k2.zeroize();
        self.x2_prime.zeroize();
    }
}

impl<C: TecdsaCurve> Drop for Party2Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

// ---------------------------------------------------------------------------
// Step 1: P_2 commits nonce
// ---------------------------------------------------------------------------

/// P_2's nonce commitment (Step 1 output sent to P_1).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Step1Commitment {
    /// Hash commitment `f_2 = H(R_2 || nizk3)`.
    pub f2: HashCommitment,
}

/// P_2's Step 1 internal state.
pub struct Step1P2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Ephemeral nonce `k_2`.
    pub k2: C::Scalar,
    /// Ephemeral nonce point `R_2 = k_2 * G`.
    pub R2: C::ProjectivePoint,
    /// DLog proof for `R_2`.
    pub nizk3: DlogProof<C>,
    /// Commitment nonce for decommitting.
    pub commit_nonce: [u8; 32],
}

/// P_2, Step 1: sample nonce `k_2`, compute `R_2 = k_2 * G`, and commit.
pub fn step1_p2_commit<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Step1Commitment, Step1P2State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k2 = C::random_scalar(rng);
    let R2 = C::generator() * k2;

    // Create DLog proof for R_2
    let ephemeral = C::random_scalar(rng);
    let nizk3 = DlogProof::<C>::prove(&k2, &ephemeral, &R2, b"xal21-sign-R2");

    // Commit to R_2 and the proof
    let commit_data = serialize_point_and_proof::<C>(&R2, &nizk3);
    let (f2, commit_nonce) = HashCommitment::commit(&commit_data, rng);

    let msg = Step1Commitment { f2 };
    let state = Step1P2State {
        k2,
        R2,
        nizk3,
        commit_nonce,
    };

    (msg, state)
}

// ---------------------------------------------------------------------------
// Step 2: MtA + re-sharing (generic over MtA backend)
// ---------------------------------------------------------------------------

/// Message from P_1 to P_2 after MtA: re-sharing data + receiver's MtA message.
///
/// Generic over the MtA backend `M`.
pub struct Step2P1ToP2Msg<C: TecdsaCurve, M: MtA>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Re-shared public key `Q'_1 = x'_1 * G`.
    pub Q1_prime: C::ProjectivePoint,
    /// Random blinding factor `r_1`.
    pub r1: C::Scalar,
    /// Consistency value `cc = t_A + x'_1 * r_1 - x_1 mod q`.
    pub cc: C::Scalar,
    /// MtA receiver message (contains the affine ciphertext + ZK proof).
    pub mta_msg: M::ReceiverMsg,
}

/// P_1's Step 2 internal state (kept between step 2 and step 3).
pub struct Step2P1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Re-shared secret `x'_1`.
    pub x1_prime: C::Scalar,
    /// Random blinding factor `r_1`.
    pub r1: C::Scalar,
}

/// P_2, Step 2a: encrypt `k_2` for the MtA protocol.
///
/// P_2 encrypts its nonce `k_2` using `M::sender_encrypt` and sends the
/// result to P_1.
///
/// Returns `(sender_msg, sender_state)` where `sender_state` is kept
/// for `step2_p2_verify`.
pub fn step2_p2_encrypt_k2<C: TecdsaCurve, M: MtA>(
    setup: &M::Setup,
    k2: &C::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<(M::SenderMsg, M::SenderState), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k2_bytes = crate::keygen::scalar_to_bytes(k2);
    let q_bytes = q_bytes::<C>();

    M::sender_encrypt(setup, &k2_bytes, &q_bytes, rng)
        .map_err(|e| Xal21Error::Paillier(format!("MtA sender_encrypt failed: {e}")))
}

/// P_1, Step 2: receive MtA message from P_2, compute re-sharing data.
///
/// P_1 performs:
/// 1. Call `M::receiver_compute` with input `x'_1` to get `alpha` (= t_A, the MtA share)
/// 2. Sample `r_1` and compute `cc = t_A + x'_1 * r_1 - x_1 mod q`
/// 3. Send `(Q'_1, r_1, cc, receiver_msg)` to P_2
pub fn step2_p1_compute<C: TecdsaCurve, M: MtA>(
    key_share: &Xal21Party1KeyShare<C>,
    setup: &M::Setup,
    sender_msg: &M::SenderMsg,
    rng: &mut impl CryptoRngCore,
) -> Result<(Step2P1ToP2Msg<C, M>, Step2P1State<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Sample x'_1 and compute Q'_1 = x'_1 * G
    let x1_prime = C::random_scalar(rng);
    let Q1_prime = C::generator() * x1_prime;

    let x1p_bytes = crate::keygen::scalar_to_bytes(&x1_prime);
    let q_bytes = q_bytes::<C>();

    // MtA receiver step: homomorphically compute on the sender's ciphertext
    let (receiver_msg, alpha_bytes) =
        M::receiver_compute(setup, &x1p_bytes, &q_bytes, sender_msg, rng).map_err(|e| {
            Xal21Error::MtaProofVerification(format!("MtA receiver_compute failed: {e}"))
        })?;

    // t_A = alpha (the receiver's MtA output share)
    let alpha_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&alpha_bytes);
    let t_A = int_to_scalar::<C>(&alpha_int);

    // Sample r_1 and compute cc = t_A + x'_1 * r_1 - x_1 mod q
    let r1 = C::random_scalar(rng);
    let cc = t_A + x1_prime * r1 - key_share.secret_share;

    let msg = Step2P1ToP2Msg {
        Q1_prime,
        r1,
        cc,
        mta_msg: receiver_msg,
    };

    let state = Step2P1State { x1_prime, r1 };

    Ok((msg, state))
}

/// P_2, Step 2: receive re-sharing data from P_1, decrypt MtA, verify consistency,
/// compute `x'_2`.
///
/// P_2 performs:
/// 1. Call `M::sender_decrypt` to get `beta` (= t_B, the MtA share)
/// 2. Verify consistency: `(t_B + cc) * G == (r_1 + k_2) * Q'_1 - Q_1`
/// 3. Compute `x'_2 = x_2 - (t_B + cc) mod q`
pub fn step2_p2_verify<C: TecdsaCurve, M: MtA>(
    key_share: &Xal21Party2KeyShare<C>,
    setup: &M::Setup,
    sender_state: &M::SenderState,
    k2: &C::Scalar,
    p1_msg: &Step2P1ToP2Msg<C, M>,
) -> Result<C::Scalar, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q_bytes = q_bytes::<C>();

    // 1. Decrypt to get t_B
    let beta_bytes = M::sender_decrypt(setup, sender_state, &q_bytes, &p1_msg.mta_msg)
        .map_err(|e| Xal21Error::Paillier(format!("MtA sender_decrypt failed: {e}")))?;

    let beta_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&beta_bytes);
    let t_B = int_to_scalar::<C>(&beta_int);

    // 2. Verify consistency check:
    // (t_B + cc) * G == (r_1 + k_2) * Q'_1 - Q_1
    let tb_plus_cc = t_B + p1_msg.cc;
    let lhs = C::generator() * tb_plus_cc;

    let r1_plus_k2 = p1_msg.r1 + *k2;
    let rhs = p1_msg.Q1_prime * r1_plus_k2 - key_share.public_share_p1;

    if lhs != rhs {
        return Err(Xal21Error::ConsistencyCheck(
            "re-sharing consistency check failed: (t_B + cc)*G != (r_1 + k_2)*Q'_1 - Q_1".into(),
        ));
    }

    // 3. Compute x'_2 = x_2 - (t_B + cc) mod q
    let x2_prime = key_share.secret_share - tb_plus_cc;

    Ok(x2_prime)
}

// ---------------------------------------------------------------------------
// Step 3: Nonce key exchange
// ---------------------------------------------------------------------------

/// P_1's nonce message (Step 3).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Step3P1Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Ephemeral nonce point `R_1 = k_1 * G`.
    pub R1: C::ProjectivePoint,
    /// DLog proof for `R_1`.
    pub nizk4: DlogProof<C>,
}

/// P_2's decommitment message (Step 3).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Step3P2Decommit<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Ephemeral nonce point `R_2 = k_2 * G`.
    pub R2: C::ProjectivePoint,
    /// DLog proof for `R_2`.
    pub nizk3: DlogProof<C>,
    /// Commitment nonce for verifying `f_2`.
    pub commit_nonce: [u8; 32],
}

/// P_1, Step 3a: sample `k_1`, compute `R_1 = k_1 * G`, create DLog proof.
pub fn step3_p1_send_nonce<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Step3P1Msg<C>, C::Scalar)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k1 = C::random_scalar(rng);
    let R1 = C::generator() * k1;

    let ephemeral = C::random_scalar(rng);
    let nizk4 = DlogProof::<C>::prove(&k1, &ephemeral, &R1, b"xal21-sign-R1");

    let msg = Step3P1Msg { R1, nizk4 };
    (msg, k1)
}

/// P_2, Step 3b: verify P_1's nonce proof, decommit `R_2`, compute `R` and `r`.
///
/// P_2 computes: `R = (r_1 + k_2) * R_1`, `r = x_coord(R) mod q`.
pub fn step3_p2_decommit_and_compute_R<C: TecdsaCurve>(
    state: &Step1P2State<C>,
    p1_msg: &Step3P1Msg<C>,
    r1: &C::Scalar,
    x2_prime: C::Scalar,
) -> Result<(Step3P2Decommit<C>, Party2Presignature<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify P_1's DLog proof for R_1
    if !p1_msg.nizk4.verify(&p1_msg.R1, b"xal21-sign-R1") {
        return Err(Xal21Error::DlogVerification(
            "P_1 nonce DLog proof (nizk4) failed".into(),
        ));
    }

    // Compute R = (r_1 + k_2) * R_1
    let r1_plus_k2 = *r1 + state.k2;
    let R = p1_msg.R1 * r1_plus_k2;
    let R_affine = R.to_affine();
    let r = C::xcoord_mod_q(&R_affine);

    let decommit = Step3P2Decommit {
        R2: state.R2,
        nizk3: state.nizk3.clone(),
        commit_nonce: state.commit_nonce,
    };

    let presig = Party2Presignature {
        k2: state.k2,
        r1: *r1,
        x2_prime,
        r,
    };

    Ok((decommit, presig))
}

/// P_1, Step 3c: verify P_2's decommitment and nonce proof, compute `R` and `r`.
///
/// P_1 computes: `R = k_1 * R_2 + (k_1 * r_1) * G`, `r = x_coord(R) mod q`.
pub fn step3_p1_verify_and_compute_R<C: TecdsaCurve>(
    f2: &Step1Commitment,
    p2_decommit: &Step3P2Decommit<C>,
    k1: C::Scalar,
    step2_state: &Step2P1State<C>,
) -> Result<Party1Presignature<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Verify the commitment opening: f_2 should commit to (R_2, nizk3)
    let commit_data = serialize_point_and_proof::<C>(&p2_decommit.R2, &p2_decommit.nizk3);
    if !f2.f2.verify(&commit_data, &p2_decommit.commit_nonce) {
        return Err(Xal21Error::CommitmentVerification(
            "P_2 nonce commitment (f_2) verification failed".into(),
        ));
    }

    // Verify P_2's DLog proof for R_2
    if !p2_decommit.nizk3.verify(&p2_decommit.R2, b"xal21-sign-R2") {
        return Err(Xal21Error::DlogVerification(
            "P_2 nonce DLog proof (nizk3) failed".into(),
        ));
    }

    // Compute R = k_1 * R_2 + (k_1 * r_1) * G
    let k1_R2 = p2_decommit.R2 * k1;
    let k1_r1_G = C::generator() * (k1 * step2_state.r1);
    let R = k1_R2 + k1_r1_G;
    let R_affine = R.to_affine();
    let r = C::xcoord_mod_q(&R_affine);

    Ok(Party1Presignature {
        k1,
        x1_prime: step2_state.x1_prime,
        r,
        R,
    })
}

// ---------------------------------------------------------------------------
// End-to-end offline signing convenience function (generic)
// ---------------------------------------------------------------------------

/// Run the complete offline signing protocol with an arbitrary MtA backend.
///
/// This is the generic version that accepts any `M: MtA` implementation
/// along with its setup material.
pub fn offline_sign_generic<C: TecdsaCurve, M: MtA>(
    p1_key: &Xal21Party1KeyShare<C>,
    p2_key: &Xal21Party2KeyShare<C>,
    mta_setup: &M::Setup,
    rng: &mut impl CryptoRngCore,
) -> Result<(Party1Presignature<C>, Party2Presignature<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Step 1: P_2 commits nonce
    let (step1_msg, step1_state) = step1_p2_commit::<C>(rng);

    // Step 2a: P_2 encrypts k_2 for MtA
    let (sender_msg, sender_state) = step2_p2_encrypt_k2::<C, M>(mta_setup, &step1_state.k2, rng)?;

    // Step 2b: P_1 computes re-sharing data
    let (step2_msg, step2_state) = step2_p1_compute::<C, M>(p1_key, mta_setup, &sender_msg, rng)?;

    // Step 2c: P_2 verifies consistency and computes x'_2
    let x2_prime = step2_p2_verify::<C, M>(
        p2_key,
        mta_setup,
        &sender_state,
        &step1_state.k2,
        &step2_msg,
    )?;

    // Step 3a: P_1 sends nonce
    let (step3_p1_msg, k1) = step3_p1_send_nonce::<C>(rng);

    // Step 3b: P_2 decommits and computes R
    let (step3_p2_decommit, p2_presig) =
        step3_p2_decommit_and_compute_R::<C>(&step1_state, &step3_p1_msg, &step2_msg.r1, x2_prime)?;

    // Step 3c: P_1 verifies decommitment and computes R
    let p1_presig =
        step3_p1_verify_and_compute_R::<C>(&step1_msg, &step3_p2_decommit, k1, &step2_state)?;

    // Sanity check: both parties should compute the same r
    debug_assert_eq!(p1_presig.r, p2_presig.r, "r mismatch between parties");

    Ok((p1_presig, p2_presig))
}

/// Run the complete offline signing protocol using the default Paillier MtA.
///
/// This is a convenience function that constructs the `PaillierMtaSetup` from
/// the key shares and calls `offline_sign_generic::<C, DefaultMtA>`.
pub fn offline_sign<C: TecdsaCurve>(
    p1_key: &Xal21Party1KeyShare<C>,
    p2_key: &Xal21Party2KeyShare<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<(Party1Presignature<C>, Party2Presignature<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mta_setup = tecdsa_paillier::mta::PaillierMtaSetup {
        ek: p2_key.ek.clone(),
        dk: p2_key.dk.clone(),
        proof_setup: tecdsa_paillier::mta::Gg18ProofSetup {
            ntilde: p2_key.ntilde.clone(),
        },
    };

    offline_sign_generic::<C, DefaultMtA>(p1_key, p2_key, &mta_setup, rng)
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Serialize a ProjectivePoint + DlogProof to bytes for commitment.
fn serialize_point_and_proof<C: TecdsaCurve>(
    point: &C::ProjectivePoint,
    proof: &DlogProof<C>,
) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::group::GroupEncoding;
    let mut data = Vec::new();
    data.extend_from_slice(point.to_bytes().as_ref());
    data.extend_from_slice(proof.commitment.to_bytes().as_ref());
    data.extend_from_slice(proof.response.to_repr().as_ref());
    data
}

/// Compute the curve order q as big-endian bytes.
fn q_bytes<C: TecdsaCurve>() -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q_int = curve_order::<C>();
    q_int.to_bytes_msf()
}
