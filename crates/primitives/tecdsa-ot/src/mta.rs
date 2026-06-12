use elliptic_curve::{CurveArithmetic, FieldBytes, PrimeField};
use k256::Secp256k1;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tecdsa_protocol::MtAInteractive;

use crate::{
    base_ot::OtError,
    rvole::{MulDataToKeep, MulDataToReceiver, MulReceiver, MulSender, L},
    soft_spoken::{random_scalar, scalar_to_bytes, OteDataToSender, OteInitSenderMsg},
};

#[derive(Debug, thiserror::Error)]
pub enum RvoleMtaError {
    #[error("RVOLE MtA: OT error: {0}")]
    Ot(OtError),

    #[error("RVOLE MtA: invalid scalar bytes: {0}")]
    InvalidScalar(String),

    #[error("RVOLE MtA: unexpected output count: expected {expected}, got {got}")]
    OutputCount { expected: usize, got: usize },
}

impl From<OtError> for RvoleMtaError {
    fn from(e: OtError) -> Self {
        Self::Ot(e)
    }
}

pub struct RvoleMtA;

#[derive(Clone, Debug)]
pub struct RvoleSetup {
    pub session_id: Vec<u8>,
}

pub struct RvoleSenderState {
    mul_sender: MulSender,
    session_id: Vec<u8>,
}

pub struct RvoleReceiverState {
    mul_receiver: MulReceiver,
    session_id: Vec<u8>,
    data_to_keep: MulDataToKeep,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RvoleInitMsg {
    pub nonce_bytes: Vec<u8>,
    pub ote_init_msg: OteInitSenderMsg,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RvoleResponseMsg {
    pub ote_data: OteDataToSender,
    pub delta_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RvoleComputeMsg {
    pub mul_data: MulDataToReceiver,
}

type Scalar = <Secp256k1 as CurveArithmetic>::Scalar;

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

fn scalar_to_be_bytes(s: &Scalar) -> Vec<u8> {
    scalar_to_bytes::<Secp256k1>(s)
}

impl MtAInteractive for RvoleMtA {
    type Setup = RvoleSetup;
    type SenderState = RvoleSenderState;
    type ReceiverState = RvoleReceiverState;
    type InitMsg = RvoleInitMsg;
    type ResponseMsg = RvoleResponseMsg;
    type ComputeMsg = RvoleComputeMsg;
    type Error = RvoleMtaError;

    fn sender_init(
        setup: &Self::Setup,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::InitMsg, Self::SenderState), Self::Error> {
        let nonce = random_scalar::<Secp256k1>(rng);
        let nonce_bytes = scalar_to_bytes::<Secp256k1>(&nonce);

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

    fn receiver_respond(
        setup: &Self::Setup,
        b_bytes: &[u8],
        _q_bytes: &[u8],
        init_msg: &Self::InitMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ResponseMsg, Self::ReceiverState), Self::Error> {
        let b_input = bytes_to_scalar(b_bytes)?;

        let nonce = bytes_to_scalar(&init_msg.nonce_bytes)?;

        let mul_receiver =
            MulReceiver::init::<Secp256k1>(&setup.session_id, &nonce, &init_msg.ote_init_msg)?;

        let (b_rvole, data_to_keep, ote_data) =
            mul_receiver.run_phase1::<Secp256k1>(&setup.session_id, rng)?;

        let delta = b_input - b_rvole;
        let delta_bytes = scalar_to_be_bytes(&delta);

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

    fn sender_compute(
        state: Self::SenderState,
        a_bytes: &[u8],
        _q_bytes: &[u8],
        response_msg: &Self::ResponseMsg,
    ) -> Result<(Self::ComputeMsg, Vec<u8>), Self::Error> {
        let a = bytes_to_scalar(a_bytes)?;
        let delta = bytes_to_scalar(&response_msg.delta_bytes)?;

        let sender_input: Vec<Scalar> = vec![a; L as usize];

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

        let alpha = sender_output[0] + a * delta;
        let alpha_bytes = scalar_to_be_bytes(&alpha);

        let compute_msg = RvoleComputeMsg { mul_data };

        Ok((compute_msg, alpha_bytes))
    }

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

        let beta = receiver_output[0];
        let beta_bytes = scalar_to_be_bytes(&beta);

        Ok(beta_bytes)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    fn q_bytes() -> Vec<u8> {
        vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ]
    }

    #[test]
    fn rvole_mta_interactive_roundtrip() {
        let mut rng = OsRng;
        let setup = RvoleSetup {
            session_id: b"test-rvole-mta-interactive".to_vec(),
        };
        let q = q_bytes();

        let a = random_scalar::<Secp256k1>(&mut rng);
        let a_bytes = scalar_to_be_bytes(&a);

        let b = random_scalar::<Secp256k1>(&mut rng);
        let b_bytes = scalar_to_be_bytes(&b);

        let (init_msg, sender_state) =
            RvoleMtA::sender_init(&setup, &mut rng).expect("sender_init should succeed");

        let (response_msg, receiver_state) =
            RvoleMtA::receiver_respond(&setup, &b_bytes, &q, &init_msg, &mut rng)
                .expect("receiver_respond should succeed");

        let (compute_msg, alpha_bytes) =
            RvoleMtA::sender_compute(sender_state, &a_bytes, &q, &response_msg)
                .expect("sender_compute should succeed");

        let beta_bytes = RvoleMtA::receiver_finish(receiver_state, &compute_msg, &q)
            .expect("receiver_finish should succeed");

        let alpha = bytes_to_scalar(&alpha_bytes).expect("valid alpha");
        let beta = bytes_to_scalar(&beta_bytes).expect("valid beta");
        let expected = a * b;
        let actual = alpha + beta;

        assert_eq!(actual, expected, "alpha + beta should equal a * b mod q");
    }

    #[test]
    fn rvole_mta_interactive_small_values() {
        let mut rng = OsRng;
        let setup = RvoleSetup {
            session_id: b"test-rvole-mta-small".to_vec(),
        };
        let q = q_bytes();

        let a = k256::Scalar::from(42u64);
        let b = k256::Scalar::from(99u64);

        let a_bytes = scalar_to_be_bytes(&a);
        let b_bytes = scalar_to_be_bytes(&b);

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
