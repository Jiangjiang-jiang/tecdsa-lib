// SPDX-License-Identifier: MIT OR Apache-2.0
//! OT-based MtA (Multiplicative-to-Additive) sub-protocol via RVOLE.
//!
//! Implements `tecdsa_protocol::MtAInteractive` using the RVOLE multiplication
//! protocol from [`crate::rvole`], following DKLs23 (Section 5.1).
//!
//! # Protocol mapping
//!
//! The RVOLE multiplication protocol produces correlated randomness where
//! `sender_out[i] + receiver_out[i] = a[i] * b_rvole` for a **random** `b_rvole`
//! chosen internally by the receiver.  To support the `MtAInteractive` trait
//! (which requires an externally supplied `b_input`), the receiver computes a
//! correction `delta = b_input - b_rvole` and sends it alongside the RVOLE data.
//! The sender adjusts its output by `a * delta` so that the final shares satisfy
//! `alpha + beta = a * b_input`.
//!
//! # Message flow
//!
//! ```text
//! Sender(a)                           Receiver(b)
//!    |                                    |
//!    |--- InitMsg (OTE init + nonce) ---->|
//!    |                                    |  MulReceiver::init + run_phase1
//!    |<-- ResponseMsg (OTE data + delta) -|  delta = b - b_rvole
//!    |                                    |
//!    |  MulSender::run(a)                 |
//!    |--- ComputeMsg (mul data) --------->|
//!    |                                    |  MulReceiver::run_phase2
//!    |  alpha = sender_out + a*delta      |  beta = receiver_out
//! ```

use elliptic_curve::{CurveArithmetic, FieldBytes, PrimeField};
use k256::Secp256k1;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tecdsa_curve::conv::scalar_to_bytes;
use tecdsa_protocol::MtAInteractive;

use crate::{
    base_ot::OtError,
    rvole::{MulDataToKeep, MulDataToReceiver, MulReceiver, MulSender, L},
    soft_spoken::{random_scalar, OteDataToSender, OteInitSenderMsg},
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for RVOLE-based MtA.
#[derive(Debug, thiserror::Error)]
pub enum RvoleMtaError {
    /// Underlying OT error.
    #[error("RVOLE MtA: OT error: {0}")]
    Ot(OtError),

    /// Invalid scalar bytes (wrong length or not a valid field element).
    #[error("RVOLE MtA: invalid scalar bytes: {0}")]
    InvalidScalar(String),

    /// RVOLE protocol produced fewer than L outputs.
    #[error("RVOLE MtA: unexpected output count: expected {expected}, got {got}")]
    OutputCount { expected: usize, got: usize },
}

impl From<OtError> for RvoleMtaError {
    fn from(e: OtError) -> Self {
        Self::Ot(e)
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// RVOLE-based MtA backend implementing `MtAInteractive`.
///
/// Internally uses `MulSender`/`MulReceiver` from [`crate::rvole`] over
/// `k256::Secp256k1`.  The trait interface uses `&[u8]` for generality;
/// byte/scalar conversions happen inside each method.
pub struct RvoleMtA;

/// Setup material for RVOLE-based MtA.
#[derive(Clone, Debug)]
pub struct RvoleSetup {
    /// Session identifier for domain separation.
    pub session_id: Vec<u8>,
}

/// Sender's state after `sender_init`, wrapping the initialized `MulSender`.
pub struct RvoleSenderState {
    /// The underlying RVOLE sender.
    mul_sender: MulSender,
    /// Session ID for domain separation in subsequent RVOLE rounds.
    session_id: Vec<u8>,
}

/// Receiver's state after `receiver_respond`, wrapping RVOLE phase-1 outputs.
pub struct RvoleReceiverState {
    /// The underlying RVOLE receiver.
    mul_receiver: MulReceiver,
    /// Session ID for domain separation in phase 2.
    session_id: Vec<u8>,
    /// Data kept from phase 1 for use in phase 2.
    data_to_keep: MulDataToKeep,
}

/// Message from sender to receiver: OTE initialization + nonce for gadget.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RvoleInitMsg {
    /// Nonce bytes for deriving the public gadget vector.
    pub nonce_bytes: Vec<u8>,
    /// OTE sender initialization message.
    pub ote_init_msg: OteInitSenderMsg,
}

/// Message from receiver to sender: OTE phase-1 data + correction scalar.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RvoleResponseMsg {
    /// OTE data from the receiver's phase 1.
    pub ote_data: OteDataToSender,
    /// Correction scalar `delta = b_input - b_rvole` (big-endian field bytes).
    /// Allows the sender to adjust its output for the desired `b_input`.
    pub delta_bytes: Vec<u8>,
}

/// Message from sender to receiver: RVOLE multiplication data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RvoleComputeMsg {
    /// Multiplication data from `MulSender::run`.
    pub mul_data: MulDataToReceiver,
}

// ---------------------------------------------------------------------------
// Scalar conversion helpers
// ---------------------------------------------------------------------------

type Scalar = <Secp256k1 as CurveArithmetic>::Scalar;

/// Parse big-endian bytes as a secp256k1 scalar.
///
/// The input must be exactly 32 bytes and represent a valid field element.
fn bytes_to_scalar(bytes: &[u8]) -> Result<Scalar, RvoleMtaError> {
    let fb = FieldBytes::<Secp256k1>::try_from(bytes).map_err(|_| {
        RvoleMtaError::InvalidScalar(format!(
            "expected {} bytes, got {}",
            FieldBytes::<Secp256k1>::default().len(),
            bytes.len()
        ))
    })?;
    Option::from(<Scalar as PrimeField>::from_repr(fb))
        .ok_or_else(|| RvoleMtaError::InvalidScalar("bytes do not represent a valid scalar".into()))
}

// ---------------------------------------------------------------------------
// MtAInteractive implementation
// ---------------------------------------------------------------------------

impl MtAInteractive for RvoleMtA {
    type Setup = RvoleSetup;
    type SenderState = RvoleSenderState;
    type ReceiverState = RvoleReceiverState;
    type InitMsg = RvoleInitMsg;
    type ResponseMsg = RvoleResponseMsg;
    type ComputeMsg = RvoleComputeMsg;
    type Error = RvoleMtaError;

    /// Step 1: Sender initializes the RVOLE multiplication protocol.
    ///
    /// Samples a random nonce for the public gadget vector and calls
    /// `MulSender::init`.  The nonce and OTE init message are sent to
    /// the receiver.
    fn sender_init(
        setup: &Self::Setup,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::InitMsg, Self::SenderState), Self::Error> {
        let nonce = random_scalar::<Secp256k1>(rng);
        let nonce_bytes = scalar_to_bytes(&nonce);

        let (mul_sender, ote_init_msg) =
            MulSender::init::<Secp256k1>(&setup.session_id, &nonce, rng);

        let init_msg = RvoleInitMsg {
            nonce_bytes,
            ote_init_msg,
        };

        let sender_state = RvoleSenderState {
            mul_sender,
            session_id: setup.session_id.clone(),
        };

        Ok((init_msg, sender_state))
    }

    /// Step 2: Receiver initializes and runs RVOLE phase 1.
    ///
    /// The receiver:
    /// 1. Calls `MulReceiver::init` with the sender's OTE init message.
    /// 2. Calls `MulReceiver::run_phase1` to sample choice bits and derive
    ///    the internal random scalar `b_rvole`.
    /// 3. Computes `delta = b_input - b_rvole` so the sender can correct
    ///    its output.
    /// 4. Returns the OTE data and `delta` as the response message.
    fn receiver_respond(
        setup: &Self::Setup,
        b_bytes: &[u8],
        _q_bytes: &[u8],
        init_msg: &Self::InitMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ResponseMsg, Self::ReceiverState), Self::Error> {
        let b_input = bytes_to_scalar(b_bytes)?;

        // Reconstruct nonce from the init message.
        let nonce = bytes_to_scalar(&init_msg.nonce_bytes)?;

        // Initialize the RVOLE receiver.
        let mul_receiver =
            MulReceiver::init::<Secp256k1>(&setup.session_id, &nonce, &init_msg.ote_init_msg)?;

        // Run phase 1: get random b_rvole, data to keep, and OTE data to send.
        let (b_rvole, data_to_keep, ote_data) =
            mul_receiver.run_phase1::<Secp256k1>(&setup.session_id, rng)?;

        // Compute correction: delta = b_input - b_rvole
        let delta = b_input - b_rvole;
        let delta_bytes = scalar_to_bytes(&delta);

        let response_msg = RvoleResponseMsg {
            ote_data,
            delta_bytes,
        };

        let receiver_state = RvoleReceiverState {
            mul_receiver,
            session_id: setup.session_id.clone(),
            data_to_keep,
        };

        Ok((response_msg, receiver_state))
    }

    /// Step 3: Sender runs the RVOLE multiplication and computes its share.
    ///
    /// The sender:
    /// 1. Parses `a_bytes` as a scalar.
    /// 2. Calls `MulSender::run` with `[a, a]` (L=2 parallel instances;
    ///    we use index 0 for the actual MtA output).
    /// 3. Computes `alpha = sender_out[0] + a * delta` to correct for the
    ///    receiver's desired `b_input`.
    /// 4. Returns the RVOLE data for the receiver and `alpha` bytes.
    fn sender_compute(
        state: Self::SenderState,
        a_bytes: &[u8],
        _q_bytes: &[u8],
        response_msg: &Self::ResponseMsg,
    ) -> Result<(Self::ComputeMsg, Vec<u8>), Self::Error> {
        let a = bytes_to_scalar(a_bytes)?;
        let delta = bytes_to_scalar(&response_msg.delta_bytes)?;

        // Build the sender input vector: L copies of `a`.
        let sender_input: Vec<Scalar> = vec![a; L as usize];

        // Use a deterministic RNG seeded from session context for the sender
        // run (the MulSender::run needs rng for pad sampling).
        // We use OsRng here since the trait method doesn't provide an rng.
        let mut rng = rand_core::OsRng;

        let (sender_output, mul_data) = state.mul_sender.run::<Secp256k1>(
            &state.session_id,
            &sender_input,
            &response_msg.ote_data,
            &mut rng,
        )?;

        if sender_output.is_empty() {
            return Err(RvoleMtaError::OutputCount {
                expected: 1,
                got: 0,
            });
        }

        // Correct sender output: alpha = sender_out[0] + a * delta
        let alpha = sender_output[0] + a * delta;
        let alpha_bytes = scalar_to_bytes(&alpha);

        let compute_msg = RvoleComputeMsg { mul_data };

        Ok((compute_msg, alpha_bytes))
    }

    /// Step 4: Receiver completes the RVOLE and computes its share.
    ///
    /// The receiver:
    /// 1. Calls `MulReceiver::run_phase2` to verify consistency and obtain
    ///    output shares.
    /// 2. Returns `beta = receiver_out[0]`.  The sender's correction via
    ///    `delta` ensures `alpha + beta = a * b_input`.
    fn receiver_finish(
        state: Self::ReceiverState,
        compute_msg: &Self::ComputeMsg,
        _q_bytes: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let receiver_output = state.mul_receiver.run_phase2::<Secp256k1>(
            &state.session_id,
            &state.data_to_keep,
            &compute_msg.mul_data,
        )?;

        if receiver_output.is_empty() {
            return Err(RvoleMtaError::OutputCount {
                expected: 1,
                got: 0,
            });
        }

        // beta = receiver_out[0]
        // The relation is: sender_out[0] + receiver_out[0] = a * b_rvole
        // After correction: alpha = sender_out[0] + a * delta
        // So: alpha + receiver_out[0] = sender_out[0] + a*delta + receiver_out[0]
        //                             = a*b_rvole + a*delta
        //                             = a*(b_rvole + delta)
        //                             = a*b_input
        // Therefore: beta = receiver_out[0]
        let beta = receiver_output[0];
        let beta_bytes = scalar_to_bytes(&beta);

        Ok(beta_bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    /// secp256k1 curve order as big-endian bytes (32 bytes).
    ///
    /// q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    fn q_bytes() -> Vec<u8> {
        vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ]
    }

    /// Full MtAInteractive round-trip: verify alpha + beta = a * b mod q.
    #[test]
    fn rvole_mta_interactive_roundtrip() {
        let mut rng = OsRng;
        let setup = RvoleSetup {
            session_id: b"test-rvole-mta-interactive".to_vec(),
        };
        let q = q_bytes();

        // Sender's input: a
        let a = random_scalar::<Secp256k1>(&mut rng);
        let a_bytes = scalar_to_bytes(&a);

        // Receiver's input: b
        let b = random_scalar::<Secp256k1>(&mut rng);
        let b_bytes = scalar_to_bytes(&b);

        // Step 1: Sender init
        let (init_msg, sender_state) =
            RvoleMtA::sender_init(&setup, &mut rng).expect("sender_init should succeed");

        // Step 2: Receiver respond
        let (response_msg, receiver_state) =
            RvoleMtA::receiver_respond(&setup, &b_bytes, &q, &init_msg, &mut rng)
                .expect("receiver_respond should succeed");

        // Step 3: Sender compute
        let (compute_msg, alpha_bytes) =
            RvoleMtA::sender_compute(sender_state, &a_bytes, &q, &response_msg)
                .expect("sender_compute should succeed");

        // Step 4: Receiver finish
        let beta_bytes = RvoleMtA::receiver_finish(receiver_state, &compute_msg, &q)
            .expect("receiver_finish should succeed");

        // Verify: alpha + beta = a * b mod q
        let alpha = bytes_to_scalar(&alpha_bytes).expect("valid alpha");
        let beta = bytes_to_scalar(&beta_bytes).expect("valid beta");
        let expected = a * b;
        let actual = alpha + beta;

        assert_eq!(actual, expected, "alpha + beta should equal a * b mod q");
    }

    /// Test that the RVOLE-based MtA works with small known values.
    #[test]
    fn rvole_mta_interactive_small_values() {
        let mut rng = OsRng;
        let setup = RvoleSetup {
            session_id: b"test-rvole-mta-small".to_vec(),
        };
        let q = q_bytes();

        // Use small scalar values for easy verification.
        let a = k256::Scalar::from(42u64);
        let b = k256::Scalar::from(99u64);

        let a_bytes = scalar_to_bytes(&a);
        let b_bytes = scalar_to_bytes(&b);

        let (init_msg, sender_state) =
            RvoleMtA::sender_init(&setup, &mut rng).expect("sender_init");

        let (response_msg, receiver_state) =
            RvoleMtA::receiver_respond(&setup, &b_bytes, &q, &init_msg, &mut rng)
                .expect("receiver_respond");

        let (compute_msg, alpha_bytes) =
            RvoleMtA::sender_compute(sender_state, &a_bytes, &q, &response_msg)
                .expect("sender_compute");

        let beta_bytes =
            RvoleMtA::receiver_finish(receiver_state, &compute_msg, &q).expect("receiver_finish");

        let alpha = bytes_to_scalar(&alpha_bytes).expect("valid alpha");
        let beta = bytes_to_scalar(&beta_bytes).expect("valid beta");

        assert_eq!(
            alpha + beta,
            k256::Scalar::from(42u64 * 99u64),
            "alpha + beta should equal 42 * 99 = 4158"
        );
    }
}
