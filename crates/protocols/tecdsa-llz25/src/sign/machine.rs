#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    non_snake_case
)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{
    ecdsa::Signature, state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine,
};

use super::{combine_signatures, compute_partial_signature, PartialSignature};
use crate::{error::Llz25Error, presign::machine::Llz25Presignature};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Llz25SignMsg {
    Round1(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartialSigPayload {
    w_i_bytes: Vec<u8>,
    u_i_bytes: Vec<u8>,
}

struct ReceivedPartial {
    partial: PartialSignature,
}

enum SignRound {
    Round1(Round1State),
    Done(Signature<k256::Secp256k1>),
    Poisoned,
}

struct Round1State {
    received: BTreeMap<PartyId, ReceivedPartial>,
    outgoing: Vec<Outgoing<Llz25SignMsg>>,
}

pub struct Llz25SignMachine {
    round: SignRound,
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    r_value: k256::Scalar,
    public_key: k256::ProjectivePoint,
    message: Vec<u8>,
}

impl Llz25SignMachine {
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        presignature: Llz25Presignature,
        msg: &[u8],
    ) -> Result<Self, Llz25Error> {
        if !all_parties.contains(&my_id) {
            return Err(Llz25Error::Protocol("my_id not in all_parties".into()));
        }

        let (partial, r_value) = compute_partial_signature(
            &presignature.key_share.public_key,
            &presignature.all_messages,
            &presignature.coefficients,
            msg,
        );

        let payload = PartialSigPayload {
            w_i_bytes: scalar_to_bytes(&partial.w_i),
            u_i_bytes: scalar_to_bytes(&partial.u_i),
        };
        let payload_bytes = bincode::serde::encode_to_vec(&payload, bincode::config::standard())
            .map_err(|e| Llz25Error::Protocol(format!("serialize partial sig: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Llz25SignMsg::Round1(payload_bytes),
        }];

        let mut received = BTreeMap::new();
        received.insert(my_id, ReceivedPartial { partial });

        let state = Round1State { received, outgoing };

        Ok(Self {
            round: SignRound::Round1(state),
            my_id,
            all_parties,
            r_value,
            public_key: presignature.key_share.public_key,
            message: msg.to_vec(),
        })
    }

    pub fn new_with_setup(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        presignature: Llz25Presignature,
        msg: &[u8],
        _setup: tecdsa_class_group::cl::ClSetup,
    ) -> Result<Self, Llz25Error> {
        Self::new(my_id, all_parties, presignature, msg)
    }

    fn deserialize_partial(data: &[u8]) -> Result<PartialSignature, TecdsaError> {
        let (payload, _): (PartialSigPayload, _) =
            bincode::serde::decode_from_slice(data, bincode::config::standard())
                .map_err(|e| TecdsaError::Other(format!("deser partial sig: {e}")))?;
        let w_i = scalar_from_bytes(&payload.w_i_bytes)?;
        let u_i = scalar_from_bytes(&payload.u_i_bytes)?;
        Ok(PartialSignature { w_i, u_i })
    }

    fn finalize(&self, state: Round1State) -> tecdsa_core::Result<Signature<k256::Secp256k1>> {
        let partials: Vec<PartialSignature> =
            state.received.into_values().map(|r| r.partial).collect();

        combine_signatures(&partials, &self.r_value, &self.public_key, &self.message)
            .map_err(|e| TecdsaError::Other(format!("combine_signatures: {e}")))
    }
}

fn scalar_to_bytes(s: &k256::Scalar) -> Vec<u8> {
    use elliptic_curve::PrimeField;
    let repr = s.to_repr();
    let slice: &[u8] = repr.as_ref();
    slice.to_vec()
}

fn scalar_from_bytes(bytes: &[u8]) -> Result<k256::Scalar, TecdsaError> {
    use elliptic_curve::PrimeField;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TecdsaError::Other("invalid scalar length".into()))?;
    let repr = k256::FieldBytes::from(arr);
    k256::Scalar::from_repr(repr)
        .into_option()
        .ok_or_else(|| TecdsaError::Other("invalid scalar".into()))
}

impl StateMachine for Llz25SignMachine {
    type Output = Signature<k256::Secp256k1>;
    type Inbound = Llz25SignMsg;
    type Outbound = Llz25SignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let round = std::mem::replace(&mut self.round, SignRound::Poisoned);

        match round {
            SignRound::Round1(mut state) => {
                let Llz25SignMsg::Round1(data) = msg;

                if !self.all_parties.contains(&from) {
                    self.round = SignRound::Round1(state);
                    return Err(TecdsaError::Other(format!("unknown party: {from}")));
                }

                if state.received.contains_key(&from) {
                    self.round = SignRound::Round1(state);
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }

                let partial = match Self::deserialize_partial(&data) {
                    Ok(p) => p,
                    Err(e) => {
                        self.round = SignRound::Round1(state);
                        return Err(e);
                    }
                };

                state.received.insert(from, ReceivedPartial { partial });

                if state.received.len() == self.all_parties.len() {
                    let output = self.finalize(state)?;
                    self.round = SignRound::Done(output);
                } else {
                    self.round = SignRound::Round1(state);
                }
            }
            SignRound::Done(_) => {
                return Err(TecdsaError::Other("sign already complete".into()));
            }
            SignRound::Poisoned => {
                return Err(TecdsaError::Other("sign machine is poisoned".into()));
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            SignRound::Round1(s) => std::mem::take(&mut s.outgoing),
            SignRound::Done(_) | SignRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, SignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            SignRound::Done(output) => Ok(output),
            _ => Err(TecdsaError::Other("sign not complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            SignRound::Round1(_) => 1,
            SignRound::Done(_) => 2,
            SignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
