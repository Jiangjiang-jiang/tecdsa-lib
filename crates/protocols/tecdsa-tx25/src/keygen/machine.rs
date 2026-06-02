// SPDX-License-Identifier: GPL-3.0-or-later
//! TX25 keygen state machine implementation.

use std::collections::BTreeMap;

use tecdsa_class_group::bicycl_glue::ClSetup;
use tecdsa_class_group::zk::r_key::RKeyProof;
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use crate::key_share::Tx25KeyShare;

use super::msg::Tx25KeygenMsg;
use super::rounds::{
    finalize_keygen, transition_r1_to_r2, transition_r2_to_r3, KeygenRound, Round1Msg, Round1State,
    Round2Msg, Round3Msg,
};
use super::{
    abc_to_qfi, deserialize_round1, deserialize_round2, deserialize_round3, qfi_to_abc,
    serialize_round1,
};

// ---------------------------------------------------------------------------
// Public machine
// ---------------------------------------------------------------------------

/// TX25 key generation state machine.
///
/// Drives a single party through the 3-round keygen protocol
/// (CL key generation + PVSS distribution + share combination).
///
/// Since bicycl-rs v0.2.2, `ClSetup` is `Send`, so it is stored directly
/// in the machine and reused across round transitions.
pub struct Tx25KeygenMachine {
    pub(crate) round: KeygenRound,
    pub(crate) setup: ClSetup,
    pub(crate) all_parties: Vec<PartyId>,
}

impl Tx25KeygenMachine {
    /// Create a new TX25 keygen state machine.
    ///
    /// Immediately runs Round 1 (CL key generation + R_key proof) and
    /// queues the Round 1 broadcast for all other parties.
    ///
    /// # Arguments
    ///
    /// * `my_id` - This party's identifier.
    /// * `all_parties` - All party identifiers in consistent order.
    /// * `threshold` - Reconstruction threshold `t` (need `t+1` to sign).
    /// * `cl_setup_seed` - Seed for CL setup creation.
    /// * `use_128bit_security` - If true, use 128-bit security CL parameters
    ///   (1828-bit discriminant).  If false, use insecure p=7 parameters
    ///   (for fast testing only).
    ///
    /// # Errors
    ///
    /// Returns an error if CL key generation or proof generation fails.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit_security: bool,
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

        // TX25 requires honest majority: n >= 2t - 1.
        if (n as u16) < 2 * threshold - 1 {
            return Err(TecdsaError::Other(format!(
                "TX25 requires n >= 2t-1 for honest majority: n={n}, t={threshold}"
            )));
        }

        // Create CL setup.
        let mut setup = if use_128bit_security {
            ClSetup::new_secp256k1_128bit(cl_setup_seed)
        } else {
            ClSetup::new_secp256k1(cl_setup_seed)
        }
        .map_err(|e| TecdsaError::Other(format!("ClSetup creation failed: {e}")))?;

        // Step 1: Generate CL keypair.
        let (cl_sk_raw, cl_pk_raw) = setup
            .keygen()
            .map_err(|e| TecdsaError::Other(format!("CL keygen failed: {e}")))?;
        let cl_sk_decimal = setup
            .sk_to_bytes(&cl_sk_raw)
            .map_err(|e| TecdsaError::Other(format!("sk_to_bytes failed: {e}")))?;

        // Serialize CL public key as (a, b, c) decimal strings.
        let pk_elt = setup
            .pk_element(&cl_pk_raw)
            .map_err(|e| TecdsaError::Other(format!("pk_element failed: {e}")))?;
        let cl_pk_abc = qfi_to_abc(&setup, &pk_elt)
            .map_err(|e| TecdsaError::Other(format!("qfi_to_abc failed: {e}")))?;

        // Step 2: Generate R_key proof.
        let proof = RKeyProof::prove(&mut setup, &cl_pk_raw, &cl_sk_decimal)
            .map_err(|e| TecdsaError::Other(format!("R_key prove failed: {e}")))?;

        // Step 3: Serialize and queue Round 1 broadcast.
        let r1_payload = serialize_round1(&setup, &cl_pk_abc, &proof)
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
            cl_pk_abc,
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

    /// Returns the number of other parties (excluding self) whose messages
    /// are still needed in the current round.
    fn expected_count(&self) -> usize {
        self.all_parties.len() - 1
    }
}

impl StateMachine for Tx25KeygenMachine {
    type Output = Tx25KeyShare;
    type Inbound = Tx25KeygenMsg;
    type Outbound = Tx25KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        // Reject messages from self.
        let my_id = match &self.round {
            KeygenRound::Round1(s) => s.my_id,
            KeygenRound::Round2(s) => s.my_id,
            KeygenRound::Round3(s) => s.my_id,
            _ => PartyId(u16::MAX), // Done/Poisoned will be caught below
        };
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        if !self.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!(
                "message from unknown party {from}"
            )));
        }

        // Take the round out to work with it, replacing with Poisoned.
        let round = std::mem::replace(&mut self.round, KeygenRound::Poisoned);

        match (round, msg) {
            // -- Round 1: collect CL public keys + R_key proofs --
            (KeygenRound::Round1(mut state), Tx25KeygenMsg::Round1(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round1(state);
                    return Err(TecdsaError::Other(format!(
                        "duplicate R1 message from party {from}"
                    )));
                }

                // Deserialize the R1 message.
                let (peer_pk_abc, peer_proof) = deserialize_round1(&data, &self.setup)
                    .map_err(|e| TecdsaError::Other(format!("R1 deserialize from {from}: {e}")))?;

                // Reconstruct BicyclPublicKey from abc.
                let peer_pk_qfi = abc_to_qfi(&self.setup, &peer_pk_abc)
                    .map_err(|e| TecdsaError::Other(format!("abc_to_qfi from {from}: {e}")))?;
                let peer_pk_raw = self
                    .setup
                    .pk_from_qfi(&peer_pk_qfi)
                    .map_err(|e| TecdsaError::Other(format!("pk_from_qfi from {from}: {e}")))?;

                // Verify R_key proof.
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
                        cl_pk_abc: peer_pk_abc,
                    },
                );

                // Check if all messages are collected.
                if state.received.len() == self.expected_count() {
                    // Transition to Round 2.
                    let new_state = transition_r1_to_r2(&mut self.setup, state)?;
                    self.round = KeygenRound::Round2(new_state);
                } else {
                    self.round = KeygenRound::Round1(state);
                }

                Ok(())
            }

            // -- Round 2: collect PVSS distributions + R_Sh proofs --
            (KeygenRound::Round2(mut state), Tx25KeygenMsg::Round2(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round2(state);
                    return Err(TecdsaError::Other(format!(
                        "duplicate R2 message from party {from}"
                    )));
                }

                // Deserialize R2 message.
                let (c1, c2s, proof) = deserialize_round2(&data, &self.setup)
                    .map_err(|e| TecdsaError::Other(format!("R2 deserialize from {from}: {e}")))?;

                // Build ordered public keys for PVSS verification.
                let n = state.all_parties.len();
                let party_ids: Vec<u16> = (1..=n as u16).collect();

                let mut ordered_pks: Vec<tecdsa_class_group::bicycl_glue::BicyclPublicKey> =
                    Vec::with_capacity(n);
                for pid in &state.all_parties {
                    let abc = state.cl_pk_abcs.get(pid).ok_or_else(|| {
                        TecdsaError::Other(format!("missing pk_abc for party {pid}"))
                    })?;
                    let qfi = abc_to_qfi(&self.setup, abc)
                        .map_err(|e| TecdsaError::Other(format!("abc_to_qfi for {pid}: {e}")))?;
                    let pk = self
                        .setup
                        .pk_from_qfi(&qfi)
                        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi for {pid}: {e}")))?;
                    ordered_pks.push(pk);
                }

                // Verify R_Sh proof.
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

                // Check if all messages are collected.
                if state.received.len() == self.expected_count() {
                    let new_state = transition_r2_to_r3(&mut self.setup, state)?;
                    self.round = KeygenRound::Round3(new_state);
                } else {
                    self.round = KeygenRound::Round2(state);
                }

                Ok(())
            }

            // -- Round 3: collect public shares + R_Dec_DL proofs --
            (KeygenRound::Round3(mut state), Tx25KeygenMsg::Round3(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round3(state);
                    return Err(TecdsaError::Other(format!(
                        "duplicate R3 message from party {from}"
                    )));
                }

                // Deserialize R3 message (includes pd for R_Dec_DL verification).
                let (public_share, proof, pd) = deserialize_round3(&data, &self.setup)
                    .map_err(|e| TecdsaError::Other(format!("R3 deserialize from {from}: {e}")))?;

                // Verify R_Dec_DL proof: the proof attests that the partial
                // decryption pd = c1^{sk} is correct relative to the sender's
                // CL public key.

                // Reconstruct the sender's CL public key.
                let from_pk_abc = state.cl_pk_abcs.get(&from).ok_or_else(|| {
                    TecdsaError::Other(format!("missing CL pk abc for party {from}"))
                })?;
                let from_pk_qfi = abc_to_qfi(&self.setup, from_pk_abc)
                    .map_err(|e| TecdsaError::Other(format!("abc_to_qfi pk from {from}: {e}")))?;
                let from_pk_raw = self
                    .setup
                    .pk_from_qfi(&from_pk_qfi)
                    .map_err(|e| TecdsaError::Other(format!("pk_from_qfi from {from}: {e}")))?;

                // Reconstruct the PVSS c1 from the sender's Round 2 distribution.
                let from_c1_abc = state.pvss_c1_abcs.get(&from).ok_or_else(|| {
                    TecdsaError::Other(format!("missing PVSS c1 abc for party {from}"))
                })?;
                let from_c1 = abc_to_qfi(&self.setup, from_c1_abc)
                    .map_err(|e| TecdsaError::Other(format!("abc_to_qfi c1 from {from}: {e}")))?;

                // Build the ciphertext (c1, dummy_c2) -- the verify() function
                // only extracts c1 from the ciphertext internally.
                let dummy_c2 = self
                    .setup
                    .identity()
                    .map_err(|e| TecdsaError::Other(format!("identity: {e}")))?;
                let ct_for_verify = self
                    .setup
                    .ct_from_components(&from_c1, &dummy_c2)
                    .map_err(|e| TecdsaError::Other(format!("ct_from_components: {e}")))?;

                // Verify the R_Dec_DL proof.
                let valid = proof
                    .verify(&self.setup, &from_pk_raw, &ct_for_verify, &pd)
                    .map_err(|e| TecdsaError::Other(format!("R_Dec_DL verify from {from}: {e}")))?;
                if !valid {
                    return Err(TecdsaError::Other(format!(
                        "R_Dec_DL proof verification failed for party {from}"
                    )));
                }

                state.received.insert(from, Round3Msg { public_share });

                // Check if all messages are collected.
                if state.received.len() == self.expected_count() {
                    let output = finalize_keygen(state)?;
                    self.round = KeygenRound::Done(output);
                } else {
                    self.round = KeygenRound::Round3(state);
                }

                Ok(())
            }

            // -- Wrong round / wrong message type --
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
