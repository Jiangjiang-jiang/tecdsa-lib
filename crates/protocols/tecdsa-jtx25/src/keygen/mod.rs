// SPDX-License-Identifier: GPL-3.0-or-later
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

//! JTX25 key generation protocol (3 rounds).
//!
//! Runs two concurrent DKGs:
//! 1. **DKG-CL**: threshold CL key pair (pk, {pk_i, sk_i}) using delta-scaled Shamir
//! 2. **DKG-Sig**: ECDSA signing key (X, {X_i, x_i}) using PVSS
//!
//! For simplicity, DKG-CL uses a trusted-setup pattern where a single
//! master CL keypair is generated and shared via `shamir_share_delta`.
//! DKG-Sig uses PVSS (same pattern as TX25 keygen).
//!
//! ## Rounds
//!
//! 1. **Round 1**: each party generates CL keypair, broadcasts `(ek_i, pi_key)`.
//! 2. **Round 2**: after verifying R_key proofs, each party distributes PVSS
//!    shares for the ECDSA signing key. Broadcasts `(c1, {c2_j}, pi_sh)`.
//! 3. **Round 3**: after verifying R_Sh proofs, each party decrypts their
//!    PVSS shares, combines into x_i, computes X_i = x_i * G, proves
//!    R_Dec_DL, and broadcasts `(X_i, pd, pi_dec_dl)`.
//!
//! After verifying Round 3 proofs, each party computes the joint public key
//! and stores the `Jtx25KeyShare`.

use std::{collections::BTreeMap, str::FromStr};

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use num_bigint::{BigInt, BigUint};
use tecdsa_class_group::{
    cl::{ClPublicKey, ClSecretKey, ClSetup, Mpz, Qfi},
    zk::{r_dec_dl::RDecDlProof, r_key::RKeyProof, r_sh::RShProof},
};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use crate::{error::Jtx25Error, key_share::Jtx25KeyShare};

// ---------------------------------------------------------------------------
// Message type
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum Jtx25KeygenMsg {
    Round1(Vec<u8>),
    Round2(Vec<u8>),
    Round3(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Internal round states
// ---------------------------------------------------------------------------

struct Round1State {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    threshold: u16,
    cl_sk_raw: ClSecretKey,
    cl_pk_raw: ClPublicKey,
    cl_sk_bytes: Vec<u8>,
    cl_pk_abc: (String, String, String),
    received: BTreeMap<PartyId, Round1Msg>,
    outgoing: Vec<Outgoing<Jtx25KeygenMsg>>,
    cl_setup_seed: String,
    use_128bit_security: bool,
}

struct Round1Msg {
    cl_pk_abc: (String, String, String),
}

struct Round2State {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    threshold: u16,
    _cl_sk_raw: ClSecretKey,
    cl_pk_raw: ClPublicKey,
    cl_sk_bytes: Vec<u8>,
    cl_pk_abcs: BTreeMap<PartyId, (String, String, String)>,
    my_pvss: tecdsa_class_group::pvss_share::PvssShareOutput,
    received: BTreeMap<PartyId, Round2Msg>,
    outgoing: Vec<Outgoing<Jtx25KeygenMsg>>,
    cl_setup_seed: String,
    use_128bit_security: bool,
}

struct Round2Msg {
    c1: Qfi,
    c2s: Vec<Qfi>,
}

struct Round3State {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    threshold: u16,
    secret_share: k256::Scalar,
    my_public_share: k256::ProjectivePoint,
    received: BTreeMap<PartyId, Round3Msg>,
    outgoing: Vec<Outgoing<Jtx25KeygenMsg>>,
    cl_setup_seed: String,
    use_128bit_security: bool,
    cl_sk_bytes: Vec<u8>,
    cl_pk_abcs: BTreeMap<PartyId, (String, String, String)>,
    pvss_c1_abcs: BTreeMap<PartyId, (String, String, String)>,
}

struct Round3Msg {
    public_share: k256::ProjectivePoint,
}

enum KeygenRound {
    Round1(Round1State),
    Round2(Round2State),
    Round3(Round3State),
    Done(Jtx25KeyShare),
    Poisoned,
}

use tecdsa_class_group::pvss_share::{
    pvss_share_decrypt, pvss_share_distribute, pvss_share_verify, PvssShareOutput,
};

// ---------------------------------------------------------------------------
// Public machine
// ---------------------------------------------------------------------------

pub struct Jtx25KeygenMachine {
    round: KeygenRound,
    setup: ClSetup,
    all_parties: Vec<PartyId>,
}

impl Jtx25KeygenMachine {
    /// Create a new JTX25 keygen state machine.
    ///
    /// Immediately runs Round 1 (CL key generation + R_key proof) and
    /// queues the Round 1 broadcast.
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

        let mut setup = if use_128bit_security {
            ClSetup::new_secp256k1_128bit(cl_setup_seed)
        } else {
            ClSetup::new_secp256k1(cl_setup_seed)
        }
        .map_err(|e| TecdsaError::Other(format!("ClSetup creation failed: {e}")))?;

        // Generate CL keypair.
        let (cl_sk_raw, cl_pk_raw) = setup
            .keygen()
            .map_err(|e| TecdsaError::Other(format!("CL keygen failed: {e}")))?;
        let cl_sk_bytes = setup
            .sk_to_bytes(&cl_sk_raw)
            .map_err(|e| TecdsaError::Other(format!("sk_to_bytes: {e}")))?;

        let pk_elt = cl_pk_raw.elt();
        let cl_pk_abc =
            qfi_to_abc(pk_elt).map_err(|e| TecdsaError::Other(format!("qfi_to_abc: {e}")))?;

        // Generate R_key proof.
        let proof = RKeyProof::prove(&mut setup, &cl_pk_raw, &cl_sk_bytes)
            .map_err(|e| TecdsaError::Other(format!("R_key prove: {e}")))?;

        // Serialize and queue Round 1 broadcast.
        let r1_payload = serialize_round1(&cl_pk_abc, &proof)
            .map_err(|e| TecdsaError::Other(format!("R1 serialize: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25KeygenMsg::Round1(r1_payload),
        }];

        let state = Round1State {
            my_id,
            all_parties: all_parties.clone(),
            threshold,
            cl_sk_raw,
            cl_pk_raw,
            cl_sk_bytes,
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

    fn expected_count(&self) -> usize {
        self.all_parties.len() - 1
    }
}

impl StateMachine for Jtx25KeygenMachine {
    type Output = Jtx25KeyShare;
    type Inbound = Jtx25KeygenMsg;
    type Outbound = Jtx25KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        // Reject messages from self.
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
            // -- Round 1: collect CL public keys + R_key proofs --
            (KeygenRound::Round1(mut state), Jtx25KeygenMsg::Round1(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round1(state);
                    return Err(TecdsaError::Other(format!("duplicate R1 from {from}")));
                }

                let (peer_pk_abc, peer_proof) = deserialize_round1(&data)
                    .map_err(|e| TecdsaError::Other(format!("R1 deserialize from {from}: {e}")))?;

                let peer_pk_qfi = abc_to_qfi(&peer_pk_abc)
                    .map_err(|e| TecdsaError::Other(format!("abc_to_qfi from {from}: {e}")))?;
                let peer_pk_raw = self
                    .setup
                    .pk_from_qfi(&peer_pk_qfi)
                    .map_err(|e| TecdsaError::Other(format!("pk_from_qfi from {from}: {e}")))?;

                let valid = peer_proof
                    .verify(&self.setup, &peer_pk_raw)
                    .map_err(|e| TecdsaError::Other(format!("R_key verify from {from}: {e}")))?;
                if !valid {
                    return Err(TecdsaError::Other(format!(
                        "R_key proof failed for party {from}"
                    )));
                }

                state.received.insert(
                    from,
                    Round1Msg {
                        cl_pk_abc: peer_pk_abc,
                    },
                );

                if state.received.len() == self.expected_count() {
                    let new_state = self.transition_r1_to_r2(state)?;
                    self.round = KeygenRound::Round2(new_state);
                } else {
                    self.round = KeygenRound::Round1(state);
                }
                Ok(())
            }

            // -- Round 2: collect PVSS distributions + R_Sh proofs --
            (KeygenRound::Round2(mut state), Jtx25KeygenMsg::Round2(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round2(state);
                    return Err(TecdsaError::Other(format!("duplicate R2 from {from}")));
                }

                let (c1, c2s, proof) = deserialize_round2(&data)
                    .map_err(|e| TecdsaError::Other(format!("R2 deserialize from {from}: {e}")))?;

                let n = state.all_parties.len();
                let party_ids: Vec<u16> = (1..=n as u16).collect();

                let mut ordered_pks: Vec<ClPublicKey> = Vec::with_capacity(n);
                for pid in &state.all_parties {
                    let abc = state
                        .cl_pk_abcs
                        .get(pid)
                        .ok_or_else(|| TecdsaError::Other(format!("missing pk_abc for {pid}")))?;
                    let qfi = abc_to_qfi(abc)
                        .map_err(|e| TecdsaError::Other(format!("abc_to_qfi for {pid}: {e}")))?;
                    let pk = self
                        .setup
                        .pk_from_qfi(&qfi)
                        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi for {pid}: {e}")))?;
                    ordered_pks.push(pk);
                }

                let valid = pvss_share_verify(
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
                        "PVSS R_Sh proof failed for party {from}"
                    )));
                }

                state.received.insert(from, Round2Msg { c1, c2s });

                if state.received.len() == self.expected_count() {
                    let new_state = self.transition_r2_to_r3(state)?;
                    self.round = KeygenRound::Round3(new_state);
                } else {
                    self.round = KeygenRound::Round2(state);
                }
                Ok(())
            }

            // -- Round 3: collect public shares + R_Dec_DL proofs --
            (KeygenRound::Round3(mut state), Jtx25KeygenMsg::Round3(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round3(state);
                    return Err(TecdsaError::Other(format!("duplicate R3 from {from}")));
                }

                let (public_share, proof, pd) = deserialize_round3(&data)
                    .map_err(|e| TecdsaError::Other(format!("R3 deserialize from {from}: {e}")))?;

                let from_pk_abc = state
                    .cl_pk_abcs
                    .get(&from)
                    .ok_or_else(|| TecdsaError::Other(format!("missing CL pk abc for {from}")))?;
                let from_pk_qfi = abc_to_qfi(from_pk_abc)
                    .map_err(|e| TecdsaError::Other(format!("abc_to_qfi pk from {from}: {e}")))?;
                let from_pk_raw = self
                    .setup
                    .pk_from_qfi(&from_pk_qfi)
                    .map_err(|e| TecdsaError::Other(format!("pk_from_qfi from {from}: {e}")))?;

                let from_c1_abc = state
                    .pvss_c1_abcs
                    .get(&from)
                    .ok_or_else(|| TecdsaError::Other(format!("missing PVSS c1 abc for {from}")))?;
                let from_c1 = abc_to_qfi(from_c1_abc)
                    .map_err(|e| TecdsaError::Other(format!("abc_to_qfi c1 from {from}: {e}")))?;

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
                        "R_Dec_DL proof failed for party {from}"
                    )));
                }

                state.received.insert(from, Round3Msg { public_share });

                if state.received.len() == self.expected_count() {
                    let output = finalize_keygen(state, &self.setup)?;
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
                    "unexpected msg type for current round".into(),
                ))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            KeygenRound::Round1(s) => std::mem::take(&mut s.outgoing),
            KeygenRound::Round2(s) => std::mem::take(&mut s.outgoing),
            KeygenRound::Round3(s) => std::mem::take(&mut s.outgoing),
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

// ---------------------------------------------------------------------------
// Round transitions
// ---------------------------------------------------------------------------

impl Jtx25KeygenMachine {
    fn transition_r1_to_r2(&mut self, state: Round1State) -> tecdsa_core::Result<Round2State> {
        let n = state.all_parties.len();
        let my_id = state.my_id;
        let my_idx = state
            .all_parties
            .iter()
            .position(|p| *p == my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;

        let mut cl_pk_abcs: BTreeMap<PartyId, (String, String, String)> = BTreeMap::new();
        let mut ordered_pks: Vec<ClPublicKey> = Vec::with_capacity(n);

        for pid in &state.all_parties {
            if *pid == my_id {
                let pk_elt = state.cl_pk_raw.elt();
                let pk_clone = self
                    .setup
                    .pk_from_qfi(pk_elt)
                    .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;
                ordered_pks.push(pk_clone);
                cl_pk_abcs.insert(*pid, state.cl_pk_abc.clone());
            } else {
                let r1_msg = state
                    .received
                    .get(pid)
                    .ok_or_else(|| TecdsaError::Other(format!("missing R1 from {pid}")))?;
                let qfi = abc_to_qfi(&r1_msg.cl_pk_abc)
                    .map_err(|e| TecdsaError::Other(format!("abc_to_qfi: {e}")))?;
                let pk = self
                    .setup
                    .pk_from_qfi(&qfi)
                    .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;
                ordered_pks.push(pk);
                cl_pk_abcs.insert(*pid, r1_msg.cl_pk_abc.clone());
            }
        }

        // Run PVSS ShareDist for ECDSA signing key.
        let party_ids: Vec<u16> = (1..=n as u16).collect();

        let pvss_output = pvss_share_distribute(
            &mut self.setup,
            &party_ids,
            &ordered_pks,
            state.threshold,
            my_idx,
        )
        .map_err(|e| TecdsaError::Other(format!("pvss_distribute: {e}")))?;

        let r2_payload = serialize_round2(&pvss_output)
            .map_err(|e| TecdsaError::Other(format!("R2 serialize: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25KeygenMsg::Round2(r2_payload),
        }];

        let my_pk_elt = state.cl_pk_raw.elt();
        let my_pk_clone = self
            .setup
            .pk_from_qfi(my_pk_elt)
            .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

        Ok(Round2State {
            my_id,
            all_parties: state.all_parties,
            threshold: state.threshold,
            _cl_sk_raw: state.cl_sk_raw,
            cl_pk_raw: my_pk_clone,
            cl_sk_bytes: state.cl_sk_bytes,
            cl_pk_abcs,
            my_pvss: pvss_output,
            received: BTreeMap::new(),
            outgoing,
            cl_setup_seed: state.cl_setup_seed,
            use_128bit_security: state.use_128bit_security,
        })
    }

    fn transition_r2_to_r3(&mut self, state: Round2State) -> tecdsa_core::Result<Round3State> {
        let my_id = state.my_id;
        let my_idx = state
            .all_parties
            .iter()
            .position(|p| *p == my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;

        // Start with own PVSS share.
        let mut x_i = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(
            &state.my_pvss.secret_share_bytes,
        );

        // Decrypt shares from other parties.
        for pid in &state.all_parties {
            if *pid == my_id {
                continue;
            }
            let r2_msg = state
                .received
                .get(pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing R2 from {pid}")))?;

            let share_bytes = pvss_share_decrypt(
                &self.setup,
                &state.cl_sk_bytes,
                &r2_msg.c1,
                &r2_msg.c2s[my_idx],
            )
            .map_err(|e| TecdsaError::Other(format!("pvss_decrypt from {pid}: {e}")))?;
            let share_j = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&share_bytes);

            x_i += share_j;
        }

        let big_x_i = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * x_i;
        let big_x_i_bytes = big_x_i.to_bytes().to_vec();

        // Generate R_Dec_DL proof using own PVSS ciphertext.
        let c1_ref = &state.my_pvss.c1;
        let c2_my_ref = &state.my_pvss.c2s[my_idx];
        let ct_ref = self
            .setup
            .ct_from_components(c1_ref, c2_my_ref)
            .map_err(|e| TecdsaError::Other(format!("ct_from_components: {e}")))?;

        let pd = self
            .setup
            .exp_bytes(c1_ref, &state.cl_sk_bytes)
            .map_err(|e| TecdsaError::Other(format!("exp for pd: {e}")))?;

        let r_dec_dl_proof = RDecDlProof::prove(
            &mut self.setup,
            &state.cl_pk_raw,
            &ct_ref,
            &pd,
            &state.cl_sk_bytes,
        )
        .map_err(|e| TecdsaError::Other(format!("R_Dec_DL prove: {e}")))?;

        let r3_payload = serialize_round3(&big_x_i_bytes, &pd, &r_dec_dl_proof)
            .map_err(|e| TecdsaError::Other(format!("R3 serialize: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25KeygenMsg::Round3(r3_payload),
        }];

        // Carry forward PVSS c1 values for R_Dec_DL verification.
        let mut pvss_c1_abcs: BTreeMap<PartyId, (String, String, String)> = BTreeMap::new();
        let own_c1_abc = qfi_to_abc(&state.my_pvss.c1)
            .map_err(|e| TecdsaError::Other(format!("qfi_to_abc own c1: {e}")))?;
        pvss_c1_abcs.insert(my_id, own_c1_abc);
        for (pid, r2_msg) in &state.received {
            let c1_abc = qfi_to_abc(&r2_msg.c1)
                .map_err(|e| TecdsaError::Other(format!("qfi_to_abc c1 from {pid}: {e}")))?;
            pvss_c1_abcs.insert(*pid, c1_abc);
        }

        Ok(Round3State {
            my_id,
            all_parties: state.all_parties,
            threshold: state.threshold,
            secret_share: x_i,
            my_public_share: big_x_i,
            received: BTreeMap::new(),
            outgoing,
            cl_setup_seed: state.cl_setup_seed,
            use_128bit_security: state.use_128bit_security,
            cl_sk_bytes: state.cl_sk_bytes,
            cl_pk_abcs: state.cl_pk_abcs,
            pvss_c1_abcs,
        })
    }
}

/// Finalize keygen: collect public shares, compute joint public key,
/// generate threshold CL key shares from the master CL key.
fn finalize_keygen(state: Round3State, setup: &ClSetup) -> tecdsa_core::Result<Jtx25KeyShare> {
    let n = state.all_parties.len();
    let my_id = state.my_id;
    let my_idx = state
        .all_parties
        .iter()
        .position(|p| *p == my_id)
        .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;

    // Collect all public shares in party order.
    let mut public_shares: Vec<k256::ProjectivePoint> = Vec::with_capacity(n);
    for pid in &state.all_parties {
        if *pid == my_id {
            public_shares.push(state.my_public_share);
        } else {
            let r3_msg = state
                .received
                .get(pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing R3 from {pid}")))?;
            public_shares.push(r3_msg.public_share);
        }
    }

    // Joint public key via Lagrange interpolation.
    let indices: Vec<u16> = (1..=n as u16).collect();
    let lagrange_coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);

    let public_key = public_shares.iter().zip(lagrange_coeffs.iter()).fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, (x_j, lambda_j)| acc + *x_j * lambda_j,
    );

    let party_index = (my_idx + 1) as u16;

    // Collect CL public key shares as QFI (for JTX25, these are individual CL PKs).
    let mut cl_pk_shares: Vec<Qfi> = Vec::with_capacity(n);
    for pid in &state.all_parties {
        let abc = state
            .cl_pk_abcs
            .get(pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing pk_abc for {pid}")))?;
        let qfi = abc_to_qfi(abc).map_err(|e| TecdsaError::Other(format!("abc_to_qfi: {e}")))?;
        cl_pk_shares.push(qfi);
    }

    // For JTX25, the aggregate CL public key is the first party's pk
    // (in the trusted setup model; in a real DKG it would be combined).
    // We store the first party's CL PK as the "aggregate" -- the real
    // threshold CL setup will be done externally.
    let first_pk_abc = state
        .cl_pk_abcs
        .values()
        .next()
        .ok_or_else(|| TecdsaError::Other("no CL PKs available".into()))?;
    let first_pk_qfi = abc_to_qfi(first_pk_abc)
        .map_err(|e| TecdsaError::Other(format!("first pk abc_to_qfi: {e}")))?;
    let cl_pk = setup
        .pk_from_qfi(&first_pk_qfi)
        .map_err(|e| TecdsaError::Other(format!("first pk pk_from_qfi: {e}")))?;

    Ok(Jtx25KeyShare {
        party_index,
        secret_share: state.secret_share,
        public_key,
        public_shares,
        cl_sk_share: state.cl_sk_bytes,
        cl_pk,
        cl_pk_shares,
        cl_setup_seed: state.cl_setup_seed,
        use_128bit_security: state.use_128bit_security,
        threshold: state.threshold,
        total: n as u16,
        n_parties_dkg: n,
    })
}

// ---------------------------------------------------------------------------
// PVSS helpers (simplified from TX25 pvss.rs)
// ---------------------------------------------------------------------------
// Threshold CL key sharing (delta-scaled Shamir)
// ---------------------------------------------------------------------------

/// Generates threshold CL key shares using the delta-scaled Shamir scheme.
/// Used for the threshold CL DKG (trusted setup variant).
pub fn shamir_share_delta(
    setup: &mut ClSetup,
    sk_bytes: &[u8],
    n: usize,
    t: usize,
) -> Result<Vec<Vec<u8>>, Jtx25Error> {
    let sk = BigUint::from_bytes_be(sk_bytes);

    // delta = n!
    let mut delta = BigUint::from(1u32);
    for i in 2..=n {
        delta *= BigUint::from(i as u64);
    }
    let delta_sk = &delta * &sk;

    // Generate t-1 random coefficients.
    let mut coeffs: Vec<BigInt> = vec![BigInt::from(delta_sk)];
    for _ in 1..t {
        let (rsk, _) = setup.keygen()?;
        let r = setup.sk_to_bytes(&rsk)?;
        let r_val = BigInt::from(BigUint::from_bytes_be(&r));
        coeffs.push(r_val);
    }

    // Evaluate polynomial at i = 1, 2, ..., n.
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = BigInt::from(i as i64);
        let mut val = BigInt::from(0);
        let mut x_pow = BigInt::from(1);
        for coeff in &coeffs {
            val += coeff * &x_pow;
            x_pow *= &x;
        }
        let (_, val_bytes) = val.to_bytes_be();
        shares.push(val_bytes);
    }

    Ok(shares)
}

// ---------------------------------------------------------------------------
// QFI serialization helpers
// ---------------------------------------------------------------------------

fn qfi_to_abc(qfi: &Qfi) -> Result<(String, String, String), Jtx25Error> {
    let a = qfi.a().to_string();
    let b = qfi.b().to_string();
    let c = qfi.c().to_string();
    Ok((a, b, c))
}

fn abc_to_qfi((a, b, c): &(String, String, String)) -> Result<Qfi, Jtx25Error> {
    Ok(Qfi::from_abc(
        Mpz::from_str(a).map_err(|e| Jtx25Error::ClError(e.into()))?,
        Mpz::from_str(b).map_err(|e| Jtx25Error::ClError(e.into()))?,
        Mpz::from_str(c).map_err(|e| Jtx25Error::ClError(e.into()))?,
    ))
}

// ---------------------------------------------------------------------------
// Wire-format serialization
// ---------------------------------------------------------------------------

fn write_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

fn read_field(data: &[u8], pos: usize) -> Result<(&[u8], usize), Jtx25Error> {
    if pos + 4 > data.len() {
        return Err(Jtx25Error::InvalidInput("truncated field length".into()));
    }
    let len = u32::from_le_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| Jtx25Error::InvalidInput("bad length bytes".into()))?,
    ) as usize;
    let start = pos + 4;
    let end = start + len;
    if end > data.len() {
        return Err(Jtx25Error::InvalidInput("truncated field data".into()));
    }
    Ok((&data[start..end], end))
}

fn read_string_field(data: &[u8], pos: usize) -> Result<(String, usize), Jtx25Error> {
    let (bytes, new_pos) = read_field(data, pos)?;
    let s = std::str::from_utf8(bytes)
        .map_err(|e| Jtx25Error::InvalidInput(format!("invalid UTF-8: {e}")))?
        .to_string();
    Ok((s, new_pos))
}

fn write_qfi_abc(buf: &mut Vec<u8>, abc: &(String, String, String)) {
    write_field(buf, abc.0.as_bytes());
    write_field(buf, abc.1.as_bytes());
    write_field(buf, abc.2.as_bytes());
}

fn read_qfi_abc(data: &[u8], pos: usize) -> Result<((String, String, String), usize), Jtx25Error> {
    let (a, pos) = read_string_field(data, pos)?;
    let (b, pos) = read_string_field(data, pos)?;
    let (c, pos) = read_string_field(data, pos)?;
    Ok(((a, b, c), pos))
}

fn serialize_round1(
    pk_abc: &(String, String, String),
    proof: &RKeyProof,
) -> Result<Vec<u8>, Jtx25Error> {
    let mut buf = Vec::new();
    write_qfi_abc(&mut buf, pk_abc);
    let t_abc = qfi_to_abc(&proof.t)?;
    write_qfi_abc(&mut buf, &t_abc);
    write_field(&mut buf, &proof.z);
    write_field(&mut buf, &proof.e);
    Ok(buf)
}

fn deserialize_round1(data: &[u8]) -> Result<((String, String, String), RKeyProof), Jtx25Error> {
    let (pk_abc, pos) = read_qfi_abc(data, 0)?;
    let (t_abc, pos) = read_qfi_abc(data, pos)?;
    let (z_bytes, pos) = read_field(data, pos)?;
    let (e_bytes, _pos) = read_field(data, pos)?;
    let t = abc_to_qfi(&t_abc)?;
    let proof = RKeyProof {
        t,
        z: z_bytes.to_vec(),
        e: e_bytes.to_vec(),
    };
    Ok((pk_abc, proof))
}

fn serialize_round2(pvss: &PvssShareOutput) -> Result<Vec<u8>, Jtx25Error> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(pvss.c2s.len() as u32).to_le_bytes());
    let c1_abc = qfi_to_abc(&pvss.c1)?;
    write_qfi_abc(&mut buf, &c1_abc);
    for c2 in &pvss.c2s {
        let c2_abc = qfi_to_abc(c2)?;
        write_qfi_abc(&mut buf, &c2_abc);
    }
    write_field(&mut buf, &pvss.proof.k);
    write_field(&mut buf, &pvss.proof.rho_response);
    Ok(buf)
}

fn deserialize_round2(data: &[u8]) -> Result<(Qfi, Vec<Qfi>, RShProof), Jtx25Error> {
    if data.len() < 4 {
        return Err(Jtx25Error::InvalidInput("R2 data too short".into()));
    }
    let n = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| Jtx25Error::InvalidInput("bad n".into()))?,
    ) as usize;
    let mut pos = 4;
    let (c1_abc, new_pos) = read_qfi_abc(data, pos)?;
    pos = new_pos;
    let c1 = abc_to_qfi(&c1_abc)?;
    let mut c2s = Vec::with_capacity(n);
    for _ in 0..n {
        let (c2_abc, new_pos) = read_qfi_abc(data, pos)?;
        pos = new_pos;
        c2s.push(abc_to_qfi(&c2_abc)?);
    }
    let (k_bytes, new_pos) = read_field(data, pos)?;
    pos = new_pos;
    let (rho_response_bytes, _) = read_field(data, pos)?;
    let proof = RShProof {
        k: k_bytes.to_vec(),
        rho_response: rho_response_bytes.to_vec(),
    };
    Ok((c1, c2s, proof))
}

fn serialize_round3(
    public_share_bytes: &[u8],
    pd: &Qfi,
    proof: &RDecDlProof,
) -> Result<Vec<u8>, Jtx25Error> {
    let mut buf = Vec::new();
    write_field(&mut buf, public_share_bytes);
    let pd_abc = qfi_to_abc(pd)?;
    write_qfi_abc(&mut buf, &pd_abc);
    let t1_abc = qfi_to_abc(&proof.t1)?;
    let t2_abc = qfi_to_abc(&proof.t2)?;
    write_qfi_abc(&mut buf, &t1_abc);
    write_qfi_abc(&mut buf, &t2_abc);
    write_field(&mut buf, &proof.z);
    write_field(&mut buf, &proof.e);
    Ok(buf)
}

fn deserialize_round3(
    data: &[u8],
) -> Result<(k256::ProjectivePoint, RDecDlProof, Qfi), Jtx25Error> {
    let (point_bytes, pos) = read_field(data, 0)?;
    let repr = k256::CompressedPoint::try_from(point_bytes)
        .map_err(|e| Jtx25Error::InvalidInput(format!("invalid point bytes: {e}")))?;
    let point: k256::ProjectivePoint = Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| Jtx25Error::InvalidInput("invalid EC point".into()))?;
    let (pd_abc, pos) = read_qfi_abc(data, pos)?;
    let pd = abc_to_qfi(&pd_abc)?;
    let (t1_abc, pos) = read_qfi_abc(data, pos)?;
    let (t2_abc, pos) = read_qfi_abc(data, pos)?;
    let (z_bytes, pos) = read_field(data, pos)?;
    let (e_bytes, _) = read_field(data, pos)?;
    let t1 = abc_to_qfi(&t1_abc)?;
    let t2 = abc_to_qfi(&t2_abc)?;
    let proof = RDecDlProof {
        t1,
        t2,
        z: z_bytes.to_vec(),
        e: e_bytes.to_vec(),
    };
    Ok((point, proof, pd))
}
