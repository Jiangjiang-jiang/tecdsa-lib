use std::collections::BTreeMap;

use tecdsa_class_group::{cl::ClSetup, zk::r_key::RKeyProof};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use super::{
    deserialize_round1, deserialize_round2, deserialize_round3,
    msg::Tx25KeygenMsg,
    rounds::{
        finalize_keygen, transition_r1_to_r2, transition_r2_to_r3, KeygenRound, Round1Msg,
        Round1State, Round2Msg, Round3Msg,
    },
    serialize_round1,
};
use crate::key_share::Tx25KeyShare;

pub struct Tx25KeygenMachine {
    pub(crate) round: KeygenRound,
    pub(crate) setup: ClSetup,
    pub(crate) all_parties: Vec<PartyId>,
}

impl Tx25KeygenMachine {
    pub fn new_with_setup(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit_security: bool,
        mut setup: ClSetup,
    ) -> tecdsa_core::Result<Self> {
        let (cl_sk_raw, cl_pk_raw) = setup
            .keygen()
            .map_err(|e| TecdsaError::Other(format!("CL keygen failed: {e}")))?;
        Self::new_with_keypair(
            my_id,
            all_parties,
            threshold,
            cl_setup_seed,
            use_128bit_security,
            setup,
            cl_sk_raw,
            cl_pk_raw,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_keypair(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit_security: bool,
        mut setup: ClSetup,
        cl_sk_raw: tecdsa_class_group::cl::SecretKey,
        cl_pk_raw: tecdsa_class_group::cl::PublicKey,
    ) -> tecdsa_core::Result<Self> {
        if !all_parties.contains(&my_id) {
            return Err(TecdsaError::Other("my_id not found in all_parties".into()));
        }
        let n = all_parties.len();
        if threshold == 0 || threshold as usize > n {
            return Err(TecdsaError::Other(format!(
                "threshold {threshold} out of range for {n} parties"
            )));
        }

        let cl_sk_decimal = setup
            .sk_to_bytes(&cl_sk_raw)
            .map_err(|e| TecdsaError::Other(format!("sk_to_bytes failed: {e}")))?;

        let cl_pk_qfi = cl_pk_raw.elt().clone();

        let proof = RKeyProof::prove(&mut setup, &cl_pk_raw, &cl_sk_decimal)
            .map_err(|e| TecdsaError::Other(format!("R_key prove failed: {e}")))?;

        let r1_payload = serialize_round1(&cl_pk_qfi, &proof)
            .map_err(|e| TecdsaError::Other(format!("R1 serialize failed: {e}")))?;

        let mut outgoing = Vec::new();
        for party in &all_parties {
            if *party != my_id {
                outgoing.push(Outgoing {
                    to: Recipient::Party(*party),
                    msg: Tx25KeygenMsg::Round1(r1_payload.clone()),
                });
            }
        }

        let state = Round1State {
            my_id,
            all_parties: all_parties.clone(),
            threshold,
            cl_sk_raw,
            cl_pk_raw,
            cl_sk_decimal,
            cl_pk_qfi,
            received: BTreeMap::new(),
            outgoing,
            cl_setup_seed: cl_setup_seed.to_string(),
            use_128bit_security,
        };

        Ok(Self {
            round: KeygenRound::Round1(state),
            setup,
            all_parties,
        })
    }

    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit_security: bool,
    ) -> tecdsa_core::Result<Self> {
        let setup = if use_128bit_security {
            ClSetup::new_secp256k1_128bit(cl_setup_seed)
        } else {
            ClSetup::new_secp256k1(cl_setup_seed)
        }
        .map_err(|e| TecdsaError::Other(format!("ClSetup creation failed: {e}")))?;

        Self::new_with_setup(
            my_id,
            all_parties,
            threshold,
            cl_setup_seed,
            use_128bit_security,
            setup,
        )
    }

    fn expected_count(&self) -> usize {
        self.all_parties.len() - 1
    }
}

impl StateMachine for Tx25KeygenMachine {
    type Output = Tx25KeyShare;
    type Inbound = Tx25KeygenMsg;
    type Outbound = Tx25KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        let my_id = match &self.round {
            KeygenRound::Round1(s) => s.my_id,
            KeygenRound::Round2(s) => s.my_id,
            KeygenRound::Round3(s) => s.my_id,
            _ => PartyId(u16::MAX),
        };
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        if !self.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!(
                "message from unknown party {from}"
            )));
        }

        let round = std::mem::replace(&mut self.round, KeygenRound::Poisoned);

        match (round, msg) {
            (KeygenRound::Round1(mut state), Tx25KeygenMsg::Round1(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round1(state);
                    return Err(TecdsaError::Other(format!(
                        "duplicate R1 message from party {from}"
                    )));
                }

                let (peer_pk_qfi, peer_proof) = deserialize_round1(&data)
                    .map_err(|e| TecdsaError::Other(format!("R1 deserialize from {from}: {e}")))?;

                let peer_pk_raw = self
                    .setup
                    .pk_from_qfi(&peer_pk_qfi)
                    .map_err(|e| TecdsaError::Other(format!("pk_from_qfi from {from}: {e}")))?;

                let valid = peer_proof
                    .verify(&self.setup, &peer_pk_raw)
                    .map_err(|e| TecdsaError::Other(format!("R_key verify from {from}: {e}")))?;
                if !valid {
                    return Err(TecdsaError::Other(format!(
                        "R_key proof verification failed for party {from}"
                    )));
                }

                state.received.insert(
                    from,
                    Round1Msg {
                        cl_pk_qfi: peer_pk_qfi,
                    },
                );

                if state.received.len() == self.expected_count() {
                    let new_state = transition_r1_to_r2(&mut self.setup, state)?;
                    self.round = KeygenRound::Round2(new_state);
                } else {
                    self.round = KeygenRound::Round1(state);
                }

                Ok(())
            }

            (KeygenRound::Round2(mut state), Tx25KeygenMsg::Round2(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round2(state);
                    return Err(TecdsaError::Other(format!(
                        "duplicate R2 message from party {from}"
                    )));
                }

                let (c1, c2s, proof) = deserialize_round2(&data)
                    .map_err(|e| TecdsaError::Other(format!("R2 deserialize from {from}: {e}")))?;

                let n = state.all_parties.len();
                let party_ids: Vec<u16> = (1..=n as u16).collect();

                let mut ordered_pks: Vec<tecdsa_class_group::cl::ClPublicKey> =
                    Vec::with_capacity(n);
                for pid in &state.all_parties {
                    let qfi = state.cl_pk_qfis.get(pid).ok_or_else(|| {
                        TecdsaError::Other(format!("missing pk qfi for party {pid}"))
                    })?;
                    let pk = self
                        .setup
                        .pk_from_qfi(qfi)
                        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi for {pid}: {e}")))?;
                    ordered_pks.push(pk);
                }

                let valid = crate::pvss::pvss_verify(
                    &self.setup,
                    &party_ids,
                    &ordered_pks,
                    state.threshold,
                    &c1,
                    &c2s,
                    &proof,
                )
                .map_err(|e| TecdsaError::Other(format!("PVSS verify from {from}: {e}")))?;

                if !valid {
                    return Err(TecdsaError::Other(format!(
                        "PVSS R_Sh proof verification failed for party {from}"
                    )));
                }

                state.received.insert(from, Round2Msg { c1, c2s });

                if state.received.len() == self.expected_count() {
                    let new_state = transition_r2_to_r3(&mut self.setup, state)?;
                    self.round = KeygenRound::Round3(new_state);
                } else {
                    self.round = KeygenRound::Round2(state);
                }

                Ok(())
            }

            (KeygenRound::Round3(mut state), Tx25KeygenMsg::Round3(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round3(state);
                    return Err(TecdsaError::Other(format!(
                        "duplicate R3 message from party {from}"
                    )));
                }

                let (public_share, proof, pd) = deserialize_round3(&data)
                    .map_err(|e| TecdsaError::Other(format!("R3 deserialize from {from}: {e}")))?;

                let from_pk_qfi = state.cl_pk_qfis.get(&from).ok_or_else(|| {
                    TecdsaError::Other(format!("missing CL pk qfi for party {from}"))
                })?;
                let from_pk_raw = self
                    .setup
                    .pk_from_qfi(from_pk_qfi)
                    .map_err(|e| TecdsaError::Other(format!("pk_from_qfi from {from}: {e}")))?;

                let from_c1 = state.pvss_c1_qfis.get(&from).ok_or_else(|| {
                    TecdsaError::Other(format!("missing PVSS c1 qfi for party {from}"))
                })?;

                let dummy_c2 = self
                    .setup
                    .identity()
                    .map_err(|e| TecdsaError::Other(format!("identity: {e}")))?;
                let ct_for_verify = self
                    .setup
                    .ct_from_components(&from_c1, &dummy_c2)
                    .map_err(|e| TecdsaError::Other(format!("ct_from_components: {e}")))?;

                let valid = proof
                    .verify(&self.setup, &from_pk_raw, &ct_for_verify, &pd)
                    .map_err(|e| TecdsaError::Other(format!("R_Dec_DL verify from {from}: {e}")))?;
                if !valid {
                    return Err(TecdsaError::Other(format!(
                        "R_Dec_DL proof verification failed for party {from}"
                    )));
                }

                state.received.insert(from, Round3Msg { public_share });

                if state.received.len() == self.expected_count() {
                    let output = finalize_keygen(state)?;
                    self.round = KeygenRound::Done(output);
                } else {
                    self.round = KeygenRound::Round3(state);
                }

                Ok(())
            }

            (KeygenRound::Done(_), _) => Err(TecdsaError::Other("keygen already complete".into())),
            (KeygenRound::Poisoned, _) => {
                Err(TecdsaError::Other("keygen machine is poisoned".into()))
            }
            (round, _) => {
                self.round = round;
                Err(TecdsaError::Other(
                    "unexpected message type for current round".into(),
                ))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            KeygenRound::Round1(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Round2(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Round3(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Done(_) | KeygenRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, KeygenRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            KeygenRound::Done(share) => Ok(share),
            _ => Err(TecdsaError::Other("keygen not complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            KeygenRound::Round1(_) => 1,
            KeygenRound::Round2(_) => 2,
            KeygenRound::Round3(_) => 3,
            KeygenRound::Done(_) => 4,
            KeygenRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
