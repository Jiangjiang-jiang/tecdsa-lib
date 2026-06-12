use elliptic_curve::{ops::Reduce, CurveArithmetic, Field, FieldBytes, PrimeField};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    base_ot::OtError,
    soft_spoken::{
        random_scalar, scalar_to_bytes, tagged_hash, tagged_hash_as_scalar, HashOutput,
        OtExtensionReceiver, OtExtensionSender, OteDataToSender, OteInitSenderMsg, PrgOutput,
        BATCH_SIZE,
    },
};

pub const L: u8 = 2;

pub const OT_WIDTH: u8 = 2 * L;

const TAG_MUL_GADGET: &[u8] = b"tecdsa/mul/gadget/v1";
const TAG_MUL_CHI_TILDE: &[u8] = b"tecdsa/mul/chi-tilde/v1";
const TAG_MUL_CHI_HAT: &[u8] = b"tecdsa/mul/chi-hat/v1";
const TAG_MUL_VERIFY: &[u8] = b"tecdsa/mul/verify/v1";

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
        let counter_bytes = scalar_to_bytes::<C>(&counter);
        gadget.push(tagged_hash_as_scalar::<C>(
            TAG_MUL_GADGET,
            &[session_id, &counter_bytes],
        ));
    }
    gadget
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MulSender {
    #[zeroize(skip)]
    pub gadget_bytes: Vec<Vec<u8>>,
    pub ote_sender: OtExtensionSender,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MulDataToReceiver {
    pub vector_of_tau: Vec<Vec<Vec<u8>>>,
    pub verify_r: HashOutput,
    pub verify_u: Vec<Vec<u8>>,
    pub gamma_sender: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MulDataToKeep {
    pub b_bytes: Vec<u8>,
    pub choice_bits: Vec<bool>,
    #[serde(with = "crate::soft_spoken::serde_prg_vec")]
    pub extended_seeds: Vec<PrgOutput>,
    pub chi_tilde: Vec<Vec<u8>>,
    pub chi_hat: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MulInitReceiverMsg {
    pub nonce_bytes: Vec<u8>,
    pub ote_sender_msg: OteInitSenderMsg,
}

impl MulSender {
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
        let gadget_bytes: Vec<Vec<u8>> = gadget.iter().map(|s| scalar_to_bytes::<C>(s)).collect();

        let sender = MulSender {
            gadget_bytes,
            ote_sender,
        };

        (sender, ote_msg)
    }

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

        let ote_sid = [b"OT Extension protocol" as &[u8], session_id].concat();
        let (ot_outputs, vector_of_tau) =
            self.ote_sender
                .run::<C>(&ote_sid, OT_WIDTH, &correlations, data)?;

        let (z_tilde, z_hat) = ot_outputs.split_at(L as usize);

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

        let mut rows_r_bytes: Vec<Vec<u8>> = Vec::with_capacity(L as usize);
        let mut verify_u: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L as usize {
            let mut entries_bytes: Vec<Vec<u8>> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE as usize {
                let entry = chi_tilde[i] * z_tilde[i][j] + chi_hat[i] * z_hat[i][j];
                entries_bytes.push(scalar_to_bytes::<C>(&entry));
            }
            rows_r_bytes.push(entries_bytes.concat());

            let u_entry = chi_tilde[i] * a_tilde[i] + chi_hat[i] * a_hat[i];
            verify_u.push(u_entry);
        }
        let r_bytes: Vec<u8> = rows_r_bytes.concat();
        let verify_r = tagged_hash(TAG_MUL_VERIFY, &[session_id, &r_bytes]);

        let mut gamma: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L as usize {
            gamma.push(input[i] - a_tilde[i]);
        }

        let mut output: Vec<C::Scalar> = Vec::with_capacity(L as usize);
        for i in 0..L as usize {
            let mut sum = <C::Scalar as Field>::ZERO;
            for j in 0..BATCH_SIZE as usize {
                sum += public_gadget[j] * z_tilde[i][j];
            }
            output.push(sum);
        }

        let tau_bytes: Vec<Vec<Vec<u8>>> = vector_of_tau
            .iter()
            .map(|tau| tau.iter().map(|s| scalar_to_bytes::<C>(s)).collect())
            .collect();
        let verify_u_bytes: Vec<Vec<u8>> =
            verify_u.iter().map(|s| scalar_to_bytes::<C>(s)).collect();
        let gamma_bytes: Vec<Vec<u8>> = gamma.iter().map(|s| scalar_to_bytes::<C>(s)).collect();

        let data_to_receiver = MulDataToReceiver {
            vector_of_tau: tau_bytes,
            verify_r,
            verify_u: verify_u_bytes,
            gamma_sender: gamma_bytes,
        };

        Ok((output, data_to_receiver))
    }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MulReceiver {
    #[zeroize(skip)]
    pub gadget_bytes: Vec<Vec<u8>>,
    pub ote_receiver: OtExtensionReceiver,
}

impl MulReceiver {
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
        let gadget_bytes: Vec<Vec<u8>> = gadget.iter().map(|s| scalar_to_bytes::<C>(s)).collect();

        Ok(MulReceiver {
            gadget_bytes,
            ote_receiver,
        })
    }

    pub fn run_phase1<C: CurveArithmetic>(
        &self,
        session_id: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(C::Scalar, MulDataToKeep, OteDataToSender), OtError>
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
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

        let mut choice_bits = Vec::with_capacity(BATCH_SIZE as usize);
        let mut b = <C::Scalar as Field>::ZERO;
        for j in 0..BATCH_SIZE as usize {
            let bit = rng.next_u32() & 1 == 1;
            if bit {
                b += public_gadget[j];
            }
            choice_bits.push(bit);
        }

        let ote_sid = [b"OT Extension protocol" as &[u8], session_id].concat();
        let (extended_seeds, data_to_sender) =
            self.ote_receiver.run_phase1(&ote_sid, &choice_bits, rng)?;

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

        let b_bytes = scalar_to_bytes::<C>(&b);
        let chi_tilde_bytes: Vec<Vec<u8>> =
            chi_tilde.iter().map(|s| scalar_to_bytes::<C>(s)).collect();
        let chi_hat_bytes: Vec<Vec<u8>> = chi_hat.iter().map(|s| scalar_to_bytes::<C>(s)).collect();

        let data_to_keep = MulDataToKeep {
            b_bytes,
            choice_bits,
            extended_seeds,
            chi_tilde: chi_tilde_bytes,
            chi_hat: chi_hat_bytes,
        };

        Ok((b, data_to_keep, data_to_sender))
    }

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

        let ote_sid = [b"OT Extension protocol" as &[u8], session_id].concat();
        let ot_outputs = self.ote_receiver.run_phase2::<C>(
            &ote_sid,
            OT_WIDTH,
            &data_kept.choice_bits,
            &data_kept.extended_seeds,
            &vector_of_tau,
        )?;

        let (z_tilde, z_hat) = ot_outputs.split_at(L as usize);

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

        let mut rows_r_bytes: Vec<Vec<u8>> = Vec::with_capacity(L as usize);
        for i in 0..L as usize {
            let mut entries_bytes: Vec<Vec<u8>> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE as usize {
                let mut entry = -(chi_tilde[i] * z_tilde[i][j]) - (chi_hat[i] * z_hat[i][j]);
                if data_kept.choice_bits[j] {
                    entry += verify_u[i];
                }
                entries_bytes.push(scalar_to_bytes::<C>(&entry));
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

#[cfg(test)]
mod tests {
    use k256::Secp256k1;
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn multiplication_roundtrip() {
        let mut rng = OsRng;
        let session_id = b"test-mul-roundtrip";

        let nonce = random_scalar::<Secp256k1>(&mut rng);

        let (mul_sender, ote_msg) = MulSender::init::<Secp256k1>(session_id, &nonce, &mut rng);
        let mul_receiver = MulReceiver::init::<Secp256k1>(session_id, &nonce, &ote_msg)
            .expect("mul receiver init should succeed");

        let mut sender_input = Vec::with_capacity(L as usize);
        for _ in 0..L {
            sender_input.push(random_scalar::<Secp256k1>(&mut rng));
        }

        let (b, data_to_keep, data_to_sender) = mul_receiver
            .run_phase1::<Secp256k1>(session_id, &mut rng)
            .expect("receiver phase1 should succeed");

        let (sender_output, data_to_receiver) = mul_sender
            .run::<Secp256k1>(session_id, &sender_input, &data_to_sender, &mut rng)
            .expect("sender run should succeed");

        let receiver_output = mul_receiver
            .run_phase2::<Secp256k1>(session_id, &data_to_keep, &data_to_receiver)
            .expect("receiver phase2 should succeed");

        for i in 0..L as usize {
            let sum = sender_output[i] + receiver_output[i];
            let expected = sender_input[i] * b;
            assert_eq!(
                sum, expected,
                "sender_output[{i}] + receiver_output[{i}] should equal input[{i}] * b"
            );
        }
    }

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

        data_to_receiver.verify_u.pop();

        let result =
            mul_receiver.run_phase2::<Secp256k1>(session_id, &data_to_keep, &data_to_receiver);
        assert!(result.is_err(), "wrong dimensions should fail");
    }
}
