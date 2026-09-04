// SPDX-License-Identifier: MIT OR Apache-2.0
//! Random Vector OLE (RVOLE) / Multiplication from OT extension.
//!
//! Produces correlated randomness: the sender inputs `a` (a vector of scalars)
//! and obtains output shares, while the receiver obtains a random scalar `b`
//! and corresponding output shares such that for each `i`:
//!
//! ```text
//!   sender_output[i] + receiver_output[i] = a[i] * b   (mod q)
//! ```
//!
//! This realizes Functionality 3.5 in DKLs23 (<https://eprint.iacr.org/2023/765.pdf>),
//! implemented via Protocol 1 of DKLs19 (<https://eprint.iacr.org/2019/523.pdf>)
//! with the optimizations from DKLs23 Section 5.1.
//!
//! # Protocol flow
//!
//! 1. **Receiver phase 1**: samples choice bits, derives `b` from public gadget,
//!    runs OTE receiver phase 1, computes shared random values.
//! 2. **Sender phase**: runs OTE sender, computes verification data, computes
//!    output shares and adjustment values.
//! 3. **Receiver phase 2**: completes OTE, verifies sender consistency, computes
//!    output shares.
//!
//! # Ported from
//!
//! Apache-2.0/MIT dual-licensed DKLs23 reference implementation at
//! `dkls23-core/src/utilities/multiplication.rs`.

use elliptic_curve::{ops::Reduce, CurveArithmetic, Field, FieldBytes, PrimeField};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tecdsa_curve::conv::scalar_to_bytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    base_ot::OtError,
    soft_spoken::{
        random_scalar, tagged_hash, tagged_hash_as_scalar, HashOutput,
        OtExtensionReceiver, OtExtensionSender, OteDataToSender, OteInitSenderMsg, PrgOutput,
        BATCH_SIZE,
    },
};

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

/// Constant `L` from Functionality 3.5 in DKLs23.
///
/// Controls the number of parallel multiplication instances per invocation.
pub const L: u8 = 2;

/// OT width for the underlying OT extension: `2 * L` correlations per batch.
pub const OT_WIDTH: u8 = 2 * L;

// ──────────────────────────────────────────────────────────────────────────────
// Domain-separation tags
// ──────────────────────────────────────────────────────────────────────────────

const TAG_MUL_GADGET: &[u8] = b"tecdsa/mul/gadget/v1";
const TAG_MUL_CHI_TILDE: &[u8] = b"tecdsa/mul/chi-tilde/v1";
const TAG_MUL_CHI_HAT: &[u8] = b"tecdsa/mul/chi-hat/v1";
const TAG_MUL_VERIFY: &[u8] = b"tecdsa/mul/verify/v1";

// ──────────────────────────────────────────────────────────────────────────────
// Public gadget vector
// ──────────────────────────────────────────────────────────────────────────────

/// Deterministically generate the public gadget vector from a session ID and nonce.
///
/// Both parties must call this with the same `(session_id, nonce)` to obtain
/// the same vector.
pub fn compute_public_gadget<C: CurveArithmetic>(
    session_id: &[u8],
    nonce: &C::Scalar,
) -> Vec<C::Scalar>
where
    C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
{
    let mut gadget = Vec::with_capacity(BATCH_SIZE as usize);
    let mut counter = *nonce;
    for _ in 0..BATCH_SIZE {
        counter += <C::Scalar as Field>::ONE;
        let counter_bytes = scalar_to_bytes(&counter);
        gadget.push(tagged_hash_as_scalar::<C>(
            TAG_MUL_GADGET,
            &[session_id, &counter_bytes],
        ));
    }
    gadget
}

// ──────────────────────────────────────────────────────────────────────────────
// MulSender
// ──────────────────────────────────────────────────────────────────────────────

/// Sender side of the RVOLE / multiplication protocol.
///
/// Wraps an [`OtExtensionSender`] and the shared public gadget vector.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MulSender {
    /// Public gadget vector (BATCH_SIZE scalars, serialized).
    #[zeroize(skip)]
    pub gadget_bytes: Vec<Vec<u8>>,
    /// Underlying OTE sender state.
    pub ote_sender: OtExtensionSender,
}

/// Data transmitted from the multiplication sender to the receiver.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MulDataToReceiver {
    /// Tau vectors from the OTE protocol.
    pub vector_of_tau: Vec<Vec<Vec<u8>>>,
    /// Hash of verification matrix r.
    pub verify_r: HashOutput,
    /// Verification vector u (L scalar values, serialized).
    pub verify_u: Vec<Vec<u8>>,
    /// Adjustment values gamma_sender (L scalars, serialized).
    pub gamma_sender: Vec<Vec<u8>>,
}

/// Data kept by the receiver between phases.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MulDataToKeep {
    /// The receiver's random value b.
    pub b_bytes: Vec<u8>,
    /// Choice bits used in OTE.
    pub choice_bits: Vec<bool>,
    /// Extended seeds from OTE phase 1.
    #[serde(with = "crate::soft_spoken::serde_prg_vec")]
    pub extended_seeds: Vec<PrgOutput>,
    /// Shared random values chi_tilde (L scalars, serialized).
    pub chi_tilde: Vec<Vec<u8>>,
    /// Shared random values chi_hat (L scalars, serialized).
    pub chi_hat: Vec<Vec<u8>>,
}

/// Initialization message from the multiplication receiver to the sender.
///
/// Contains the nonce for the public gadget and the OTE init message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MulInitReceiverMsg {
    /// Nonce for the public gadget vector (scalar bytes).
    pub nonce_bytes: Vec<u8>,
    /// OTE sender init message (with roles reversed).
    pub ote_sender_msg: OteInitSenderMsg,
}

// ──────────────────────────────────────────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────────────────────────────────────────

impl MulSender {
    /// Initialize the multiplication sender.
    ///
    /// The sender acts as OTE sender (which acts as base-OT receiver).
    /// Also computes the shared public gadget vector from the nonce.
    ///
    /// Returns `(sender, init_message_for_receiver)`.
    pub fn init<C: CurveArithmetic>(
        session_id: &[u8],
        nonce: &C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> (Self, OteInitSenderMsg)
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        let (ote_sender, ote_msg) = OtExtensionSender::init(session_id, rng);

        let gadget = compute_public_gadget::<C>(session_id, nonce);
        let gadget_bytes: Vec<Vec<u8>> = gadget.iter().map(scalar_to_bytes).collect();

        let sender = MulSender {
            gadget_bytes,
            ote_sender,
        };

        (sender, ote_msg)
    }

    /// Run the sender's multiplication protocol.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    /// * `input` - L scalar values (the sender's private input)
    /// * `data` - OTE data from the receiver
    ///
    /// # Returns
    ///
    /// `(sender_output, data_to_receiver)` where `sender_output` has L scalars.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the underlying OTE fails.
    pub fn run<C: CurveArithmetic>(
        &self,
        session_id: &[u8],
        input: &[C::Scalar],
        data: &OteDataToSender,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<C::Scalar>, MulDataToReceiver), OtError>
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        // Reconstruct public gadget from bytes.
        let public_gadget: Vec<C::Scalar> = self
            .gadget_bytes
            .iter()
            .map(|b| {
                let fb = FieldBytes::<C>::try_from(b.as_slice())
                    .expect("scalar bytes length should match");
                Option::from(<C::Scalar as PrimeField>::from_repr(fb))
                    .expect("gadget scalar should be valid")
            })
            .collect();

        // ── RANDOMIZED MULTIPLICATION ────────────────────────────────────

        // Step 2: Sample pads a_tilde, check values a_hat, and build correlations.
        let mut a_tilde = Vec::with_capacity(L as usize);
        let mut a_hat = Vec::with_capacity(L as usize);
        for _ in 0..L {
            a_tilde.push(random_scalar::<C>(rng));
            a_hat.push(random_scalar::<C>(rng));
        }

        let mut correlations: Vec<Vec<C::Scalar>> = Vec::with_capacity(OT_WIDTH as usize);
        for i in 0..L as usize {
            correlations.push(vec![a_tilde[i]; BATCH_SIZE as usize]);
        }
        for i in 0..L as usize {
            correlations.push(vec![a_hat[i]; BATCH_SIZE as usize]);
        }

        // Step 3: Run OTE.
        let ote_sid = [b"OT Extension protocol" as &[u8], session_id].concat();
        let (ot_outputs, vector_of_tau) =
            self.ote_sender
                .run::<C>(&ote_sid, OT_WIDTH, &correlations, data)?;

        let (z_tilde, z_hat) = ot_outputs.split_at(L as usize);

        // Step 4: Compute shared random values from OTE transcript.
        let transcript = build_transcript(data);

        let mut chi_tilde = Vec::with_capacity(L as usize);
        let mut chi_hat = Vec::with_capacity(L as usize);
        for i in 0..L {
            chi_tilde.push(tagged_hash_as_scalar::<C>(
                TAG_MUL_CHI_TILDE,
                &[session_id, &i.to_be_bytes(), &transcript],
            ));
            chi_hat.push(tagged_hash_as_scalar::<C>(
                TAG_MUL_CHI_HAT,
                &[session_id, &i.to_be_bytes(), &transcript],
            ));
        }

        // Step 5: Compute verification values.
        let mut rows_r_bytes: Vec<Vec<u8>> = Vec::with_capacity(L as usize);
        let mut verify_u: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L as usize {
            let mut entries_bytes: Vec<Vec<u8>> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE as usize {
                let entry = chi_tilde[i] * z_tilde[i][j] + chi_hat[i] * z_hat[i][j];
                entries_bytes.push(scalar_to_bytes(&entry));
            }
            rows_r_bytes.push(entries_bytes.concat());

            let u_entry = chi_tilde[i] * a_tilde[i] + chi_hat[i] * a_hat[i];
            verify_u.push(u_entry);
        }
        let r_bytes: Vec<u8> = rows_r_bytes.concat();
        let verify_r = tagged_hash(TAG_MUL_VERIFY, &[session_id, &r_bytes]);

        // Step 7: Compute gamma.
        let mut gamma: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L as usize {
            gamma.push(input[i] - a_tilde[i]);
        }

        // Step 8: Compute output.
        let mut output: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L as usize {
            let mut sum = <C::Scalar as Field>::ZERO;
            for j in 0..BATCH_SIZE as usize {
                sum += public_gadget[j] * z_tilde[i][j];
            }
            output.push(sum);
        }

        // Serialize tau, verify_u, gamma for transport.
        let tau_bytes: Vec<Vec<Vec<u8>>> = vector_of_tau
            .iter()
            .map(|tau| tau.iter().map(scalar_to_bytes).collect())
            .collect();
        let verify_u_bytes: Vec<Vec<u8>> =
            verify_u.iter().map(scalar_to_bytes).collect();
        let gamma_bytes: Vec<Vec<u8>> = gamma.iter().map(scalar_to_bytes).collect();

        let data_to_receiver = MulDataToReceiver {
            vector_of_tau: tau_bytes,
            verify_r,
            verify_u: verify_u_bytes,
            gamma_sender: gamma_bytes,
        };

        Ok((output, data_to_receiver))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// MulReceiver
// ──────────────────────────────────────────────────────────────────────────────

/// Receiver side of the RVOLE / multiplication protocol.
///
/// Wraps an [`OtExtensionReceiver`] and the shared public gadget vector.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MulReceiver {
    /// Public gadget vector (BATCH_SIZE scalars, serialized).
    #[zeroize(skip)]
    pub gadget_bytes: Vec<Vec<u8>>,
    /// Underlying OTE receiver state.
    pub ote_receiver: OtExtensionReceiver,
}

impl MulReceiver {
    /// Initialize the multiplication receiver.
    ///
    /// The receiver acts as OTE receiver (which acts as base-OT sender).
    ///
    /// Returns `(receiver, nonce)` where `nonce` must be sent to the sender.
    pub fn init<C: CurveArithmetic>(
        session_id: &[u8],
        nonce: &C::Scalar,
        sender_ote_msg: &OteInitSenderMsg,
    ) -> Result<Self, OtError>
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        let ote_receiver = OtExtensionReceiver::init(session_id, sender_ote_msg)?;

        let gadget = compute_public_gadget::<C>(session_id, nonce);
        let gadget_bytes: Vec<Vec<u8>> = gadget.iter().map(scalar_to_bytes).collect();

        Ok(MulReceiver {
            gadget_bytes,
            ote_receiver,
        })
    }

    /// Run phase 1 of the receiver's multiplication protocol.
    ///
    /// Samples choice bits, derives the receiver's random value `b`, and
    /// runs OTE receiver phase 1.
    ///
    /// # Returns
    ///
    /// `(b, data_to_keep, data_to_sender)` where:
    /// - `b` is the receiver's random scalar
    /// - `data_to_keep` is needed for phase 2
    /// - `data_to_sender` must be sent to the sender
    pub fn run_phase1<C: CurveArithmetic>(
        &self,
        session_id: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(C::Scalar, MulDataToKeep, OteDataToSender), OtError>
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        // Reconstruct public gadget from bytes.
        let public_gadget: Vec<C::Scalar> = self
            .gadget_bytes
            .iter()
            .map(|bytes| {
                let fb = FieldBytes::<C>::try_from(bytes.as_slice())
                    .expect("scalar bytes length should match");
                Option::from(<C::Scalar as PrimeField>::from_repr(fb))
                    .expect("gadget scalar should be valid")
            })
            .collect();

        // Step 1: Sample choice bits and compute b.
        let mut choice_bits = Vec::with_capacity(BATCH_SIZE as usize);
        let mut b = <C::Scalar as Field>::ZERO;
        for j in 0..BATCH_SIZE as usize {
            let bit = rng.next_u32() & 1 == 1;
            if bit {
                b += public_gadget[j];
            }
            choice_bits.push(bit);
        }

        // Step 3: Run OTE receiver phase 1.
        let ote_sid = [b"OT Extension protocol" as &[u8], session_id].concat();
        let (extended_seeds, data_to_sender) =
            self.ote_receiver.run_phase1(&ote_sid, &choice_bits, rng)?;

        // Step 4: Compute shared random values.
        let transcript = build_transcript(&data_to_sender);

        let mut chi_tilde = Vec::with_capacity(L as usize);
        let mut chi_hat = Vec::with_capacity(L as usize);
        for i in 0..L {
            chi_tilde.push(tagged_hash_as_scalar::<C>(
                TAG_MUL_CHI_TILDE,
                &[session_id, &i.to_be_bytes(), &transcript],
            ));
            chi_hat.push(tagged_hash_as_scalar::<C>(
                TAG_MUL_CHI_HAT,
                &[session_id, &i.to_be_bytes(), &transcript],
            ));
        }

        let b_bytes = scalar_to_bytes(&b);
        let chi_tilde_bytes: Vec<Vec<u8>> =
            chi_tilde.iter().map(scalar_to_bytes).collect();
        let chi_hat_bytes: Vec<Vec<u8>> = chi_hat.iter().map(scalar_to_bytes).collect();

        let data_to_keep = MulDataToKeep {
            b_bytes,
            choice_bits,
            extended_seeds,
            chi_tilde: chi_tilde_bytes,
            chi_hat: chi_hat_bytes,
        };

        Ok((b, data_to_keep, data_to_sender))
    }

    /// Run phase 2 of the receiver's multiplication protocol.
    ///
    /// Completes the OTE, verifies sender consistency, and computes
    /// the receiver's output shares.
    ///
    /// # Returns
    ///
    /// L scalar values (the receiver's output shares).
    ///
    /// # Errors
    ///
    /// Returns `Err` if dimensions are wrong, OTE fails, or consistency
    /// check fails.
    pub fn run_phase2<C: CurveArithmetic>(
        &self,
        session_id: &[u8],
        data_kept: &MulDataToKeep,
        data_received: &MulDataToReceiver,
    ) -> Result<Vec<C::Scalar>, OtError>
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        if data_received.verify_u.len() != L as usize
            || data_received.gamma_sender.len() != L as usize
        {
            return Err(OtError("received data has incorrect dimensions".into()));
        }

        // Reconstruct public gadget.
        let public_gadget: Vec<C::Scalar> = self
            .gadget_bytes
            .iter()
            .map(|bytes| {
                let fb = FieldBytes::<C>::try_from(bytes.as_slice())
                    .expect("scalar bytes length should match");
                Option::from(<C::Scalar as PrimeField>::from_repr(fb))
                    .expect("gadget scalar should be valid")
            })
            .collect();

        // Deserialize tau vectors.
        let vector_of_tau: Vec<Vec<C::Scalar>> = data_received
            .vector_of_tau
            .iter()
            .map(|tau_row| {
                tau_row
                    .iter()
                    .map(|bytes| {
                        let fb = FieldBytes::<C>::try_from(bytes.as_slice())
                            .expect("scalar bytes length should match");
                        Option::from(<C::Scalar as PrimeField>::from_repr(fb))
                            .expect("tau scalar should be valid")
                    })
                    .collect()
            })
            .collect();

        // Step 3 (conclusion): Complete OTE.
        let ote_sid = [b"OT Extension protocol" as &[u8], session_id].concat();
        let ot_outputs = self.ote_receiver.run_phase2::<C>(
            &ote_sid,
            OT_WIDTH,
            &data_kept.choice_bits,
            &data_kept.extended_seeds,
            &vector_of_tau,
        )?;

        let (z_tilde, z_hat) = ot_outputs.split_at(L as usize);

        // Deserialize kept scalars.
        let chi_tilde: Vec<C::Scalar> = data_kept
            .chi_tilde
            .iter()
            .map(|bytes| {
                let fb = FieldBytes::<C>::try_from(bytes.as_slice())
                    .expect("scalar bytes length should match");
                Option::from(<C::Scalar as PrimeField>::from_repr(fb))
                    .expect("chi_tilde scalar should be valid")
            })
            .collect();
        let chi_hat: Vec<C::Scalar> = data_kept
            .chi_hat
            .iter()
            .map(|bytes| {
                let fb = FieldBytes::<C>::try_from(bytes.as_slice())
                    .expect("scalar bytes length should match");
                Option::from(<C::Scalar as PrimeField>::from_repr(fb))
                    .expect("chi_hat scalar should be valid")
            })
            .collect();
        let verify_u: Vec<C::Scalar> = data_received
            .verify_u
            .iter()
            .map(|bytes| {
                let fb = FieldBytes::<C>::try_from(bytes.as_slice())
                    .expect("scalar bytes length should match");
                Option::from(<C::Scalar as PrimeField>::from_repr(fb))
                    .expect("verify_u scalar should be valid")
            })
            .collect();
        let gamma_sender: Vec<C::Scalar> = data_received
            .gamma_sender
            .iter()
            .map(|bytes| {
                let fb = FieldBytes::<C>::try_from(bytes.as_slice())
                    .expect("scalar bytes length should match");
                Option::from(<C::Scalar as PrimeField>::from_repr(fb))
                    .expect("gamma_sender scalar should be valid")
            })
            .collect();
        let b: C::Scalar = {
            let fb = FieldBytes::<C>::try_from(data_kept.b_bytes.as_slice())
                .expect("b scalar bytes length should match");
            Option::from(<C::Scalar as PrimeField>::from_repr(fb))
                .expect("b scalar should be valid")
        };

        // Step 6: Verify consistency.
        let mut rows_r_bytes: Vec<Vec<u8>> = Vec::with_capacity(L as usize);
        for i in 0..L as usize {
            let mut entries_bytes: Vec<Vec<u8>> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE as usize {
                let mut entry = -(chi_tilde[i] * z_tilde[i][j]) - (chi_hat[i] * z_hat[i][j]);
                if data_kept.choice_bits[j] {
                    entry += verify_u[i];
                }
                entries_bytes.push(scalar_to_bytes(&entry));
            }
            rows_r_bytes.push(entries_bytes.concat());
        }
        let r_bytes: Vec<u8> = rows_r_bytes.concat();
        let expected_verify_r = tagged_hash(TAG_MUL_VERIFY, &[session_id, &r_bytes]);

        if !bool::from(data_received.verify_r.ct_eq(&expected_verify_r)) {
            return Err(OtError(
                "Sender cheated in multiplication: Consistency check failed!".into(),
            ));
        }

        // Step 8: Compute output.
        let mut output = Vec::with_capacity(L as usize);
        for i in 0..L as usize {
            let mut sum = <C::Scalar as Field>::ZERO;
            for j in 0..BATCH_SIZE as usize {
                sum += public_gadget[j] * z_tilde[i][j];
            }
            let final_val = b * gamma_sender[i] + sum;
            output.push(final_val);
        }

        Ok(output)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────────────────────────────────────

/// Build a deterministic transcript from OTE data for deriving shared random values.
fn build_transcript(data: &OteDataToSender) -> Vec<u8> {
    let mut transcript = Vec::new();
    for row in &data.u {
        transcript.extend_from_slice(row);
    }
    transcript.extend_from_slice(&data.verify_x);
    for t in &data.verify_t {
        transcript.extend_from_slice(t);
    }
    transcript
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use k256::Secp256k1;
    use rand_core::OsRng;

    use super::*;

    /// Full multiplication round-trip: verify sender_output + receiver_output = a * b.
    #[test]
    fn multiplication_roundtrip() {
        let mut rng = OsRng;
        let session_id = b"test-mul-roundtrip";

        // Sample nonce for public gadget.
        let nonce = random_scalar::<Secp256k1>(&mut rng);

        // ── INIT ─────────────────────────────────────────────────────────

        let (mul_sender, ote_msg) = MulSender::init::<Secp256k1>(session_id, &nonce, &mut rng);
        let mul_receiver = MulReceiver::init::<Secp256k1>(session_id, &nonce, &ote_msg)
            .expect("mul receiver init should succeed");

        // ── PROTOCOL ─────────────────────────────────────────────────────

        // Sender's input: L random scalars.
        let mut sender_input = Vec::with_capacity(L as usize);
        for _ in 0..L {
            sender_input.push(random_scalar::<Secp256k1>(&mut rng));
        }

        // Receiver phase 1.
        let (b, data_to_keep, data_to_sender) = mul_receiver
            .run_phase1::<Secp256k1>(session_id, &mut rng)
            .expect("receiver phase1 should succeed");

        // Sender runs.
        let (sender_output, data_to_receiver) = mul_sender
            .run::<Secp256k1>(session_id, &sender_input, &data_to_sender, &mut rng)
            .expect("sender run should succeed");

        // Receiver phase 2.
        let receiver_output = mul_receiver
            .run_phase2::<Secp256k1>(session_id, &data_to_keep, &data_to_receiver)
            .expect("receiver phase2 should succeed");

        // ── VERIFY ───────────────────────────────────────────────────────

        for i in 0..L as usize {
            let sum = sender_output[i] + receiver_output[i];
            let expected = sender_input[i] * b;
            assert_eq!(
                sum, expected,
                "sender_output[{i}] + receiver_output[{i}] should equal input[{i}] * b"
            );
        }
    }

    /// Multiplication with multiple runs using the same initialization.
    #[test]
    fn multiplication_two_runs() {
        let mut rng = OsRng;
        let session_id = b"test-mul-two-runs";

        let nonce = random_scalar::<Secp256k1>(&mut rng);

        let (mul_sender, ote_msg) = MulSender::init::<Secp256k1>(session_id, &nonce, &mut rng);
        let mul_receiver = MulReceiver::init::<Secp256k1>(session_id, &nonce, &ote_msg)
            .expect("mul receiver init should succeed");

        for run in 0..2u8 {
            let run_sid = [session_id.as_slice(), &[run]].concat();

            let mut sender_input = Vec::with_capacity(L as usize);
            for _ in 0..L {
                sender_input.push(random_scalar::<Secp256k1>(&mut rng));
            }

            let (b, data_to_keep, data_to_sender) = mul_receiver
                .run_phase1::<Secp256k1>(&run_sid, &mut rng)
                .expect("receiver phase1 should succeed");

            let (sender_output, data_to_receiver) = mul_sender
                .run::<Secp256k1>(&run_sid, &sender_input, &data_to_sender, &mut rng)
                .expect("sender run should succeed");

            let receiver_output = mul_receiver
                .run_phase2::<Secp256k1>(&run_sid, &data_to_keep, &data_to_receiver)
                .expect("receiver phase2 should succeed");

            for i in 0..L as usize {
                let sum = sender_output[i] + receiver_output[i];
                let expected = sender_input[i] * b;
                assert_eq!(
                    sum, expected,
                    "run {run}: sum should equal product at index {i}"
                );
            }
        }
    }

    /// Receiver rejects tampered verify_r.
    #[test]
    fn multiplication_rejects_tampered_verify_r() {
        let mut rng = OsRng;
        let session_id = b"test-mul-tamper-r";

        let nonce = random_scalar::<Secp256k1>(&mut rng);

        let (mul_sender, ote_msg) = MulSender::init::<Secp256k1>(session_id, &nonce, &mut rng);
        let mul_receiver = MulReceiver::init::<Secp256k1>(session_id, &nonce, &ote_msg)
            .expect("init should succeed");

        let mut sender_input = Vec::with_capacity(L as usize);
        for _ in 0..L {
            sender_input.push(random_scalar::<Secp256k1>(&mut rng));
        }

        let (_, data_to_keep, data_to_sender) = mul_receiver
            .run_phase1::<Secp256k1>(session_id, &mut rng)
            .expect("phase1 should succeed");

        let (_, mut data_to_receiver) = mul_sender
            .run::<Secp256k1>(session_id, &sender_input, &data_to_sender, &mut rng)
            .expect("sender should succeed");

        // Tamper verify_r.
        data_to_receiver.verify_r[0] ^= 1;

        let result =
            mul_receiver.run_phase2::<Secp256k1>(session_id, &data_to_keep, &data_to_receiver);
        assert!(result.is_err(), "tampered verify_r should fail");
        let err = result.unwrap_err();
        assert!(
            err.0.contains("Consistency check failed"),
            "error should mention consistency check, got: {}",
            err.0
        );
    }

    /// Receiver rejects wrong verify_u dimensions.
    #[test]
    fn multiplication_rejects_wrong_dimensions() {
        let mut rng = OsRng;
        let session_id = b"test-mul-wrong-dim";

        let nonce = random_scalar::<Secp256k1>(&mut rng);

        let (mul_sender, ote_msg) = MulSender::init::<Secp256k1>(session_id, &nonce, &mut rng);
        let mul_receiver = MulReceiver::init::<Secp256k1>(session_id, &nonce, &ote_msg)
            .expect("init should succeed");

        let mut sender_input = Vec::with_capacity(L as usize);
        for _ in 0..L {
            sender_input.push(random_scalar::<Secp256k1>(&mut rng));
        }

        let (_, data_to_keep, data_to_sender) = mul_receiver
            .run_phase1::<Secp256k1>(session_id, &mut rng)
            .expect("phase1 should succeed");

        let (_, mut data_to_receiver) = mul_sender
            .run::<Secp256k1>(session_id, &sender_input, &data_to_sender, &mut rng)
            .expect("sender should succeed");

        // Remove one verify_u entry.
        data_to_receiver.verify_u.pop();

        let result =
            mul_receiver.run_phase2::<Secp256k1>(session_id, &data_to_keep, &data_to_receiver);
        assert!(result.is_err(), "wrong dimensions should fail");
    }
}
