// SPDX-License-Identifier: MIT OR Apache-2.0
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
//! 1. **DKG-CL**: distributed threshold CL key pair via the paper-compliant
//!    `dkg_cl` module (Gen/GenVf/Reveal/RevealVf/Aggregate) using chunk
//!    encryption, Pedersen commitments, and Z_Blnt / Z_GDec-CL proofs.
//! 2. **DKG-Sig**: ECDSA signing key (X, {X_i, x_i}) using PVSS.
//!
//! ## Rounds
//!
//! 1. **Round 1**: each party generates CL keypair (sk_i, pk_i), broadcasts
//!    `(pk_i, pi_key)`.
//! 2. **Round 2**: after verifying R_key proofs, each party:
//!    - DKG-Sig: distributes PVSS shares for the ECDSA signing key (broadcast).
//!    - DKG-CL Gen: calls `dkg_cl_gen()`, broadcasts PCs + chunk_cts + agg_cts
//!      + Z_Blnt proofs, and sends per-recipient encrypted chunks via P2P.
//! 3. **Round 3**: after verifying R_Sh and Z_Blnt proofs, each party:
//!    - DKG-Sig: decrypts PVSS shares, combines into x_i, proves R_Dec_DL.
//!    - DKG-CL Reveal: calls `dkg_cl_reveal()`, broadcasts CL pk share +
//!      Z_GDec-CL proof.
//!    - DKG-CL RevealVf + Aggregate: verifies proofs, computes aggregate pk.
//!
//! After verifying Round 3 proofs, each party:
//! - Computes joint ECDSA PK via Lagrange interpolation.
//! - Aggregates CL pk via `dkg_cl_aggregate()`.
//! - Stores the `Jtx25KeyShare` with DKG-CL combined shares.

use std::{collections::BTreeMap, str::FromStr};

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use tecdsa_class_group::{
    cl::{ClPublicKey, ClSecretKey, ClSetup, Mpz, Qfi},
    dkg_cl::{self, DkgClGenOutput, DkgClGenPerRecipient, DkgClRevealOutput},
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
    /// P2P message carrying DKG-CL per-recipient chunk ciphertexts.
    Round2P2p(Vec<u8>),
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
    /// DKG-CL Gen output (kept for Reveal phase).
    dkg_cl_gen_output: DkgClGenOutput,
    /// Received DKG-CL Gen per-recipient data from peers (for GenVf + Reveal).
    dkg_cl_received: BTreeMap<PartyId, DkgClGenPerRecipient>,
    /// Count of P2P messages received (for round gate synchronization).
    p2p_received: std::collections::BTreeSet<PartyId>,
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
    /// DKG-CL combined secret share (from `dkg_cl_reveal`).
    dkg_cl_combined_share: Vec<u8>,
    /// Own DKG-CL public key share `h^{combined_share}`.
    my_dkg_cl_lifted_share: Qfi,
    /// Own DKG-CL combined ciphertext (for RevealVf).
    _my_dkg_cl_combined_ct: tecdsa_class_group::cl::ClCiphertext,
    /// Received DKG-CL per-recipient chunk ciphertexts from all dealers
    /// (indexed by dealer party ID). Stored for RevealVf reconstruction
    /// of each party's combined ciphertext.
    _all_dkg_cl_chunk_cts: BTreeMap<PartyId, Vec<(Qfi, Qfi)>>,
    cl_pk_abcs: BTreeMap<PartyId, (String, String, String)>,
    pvss_c1_abcs: BTreeMap<PartyId, (String, String, String)>,
}

struct Round3Msg {
    public_share: k256::ProjectivePoint,
    /// DKG-CL public key share from Reveal phase.
    dkg_cl_lifted_share: Qfi,
    /// DKG-CL R_GDec-CL proof (kept for diagnostics).
    _dkg_cl_proof: DkgClRevealWire,
}

/// Wire-friendly representation of DKG-CL Reveal data.
struct DkgClRevealWire {
    /// The CL public key share `h^{x_i}`.
    lifted_share: Qfi,
    /// R_GDec-CL proof fields.
    proof_t1: Qfi,
    proof_t2: Qfi,
    proof_z: Vec<u8>,
    proof_e: Vec<u8>,
    /// combined_share bytes (needed for RevealVf to reconstruct D).
    combined_share: Vec<u8>,
    /// combined_ct components (c1, c2) for proof verification.
    combined_ct_c1: Qfi,
    combined_ct_c2: Qfi,
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
    /// Create a new JTX25 keygen state machine from a pre-built `ClSetup`.
    ///
    /// This avoids recreating the expensive CL setup per party,
    /// which is useful in benchmarks where all parties share the same
    /// discriminant parameters.
    ///
    /// See [`Self::new`] for the full documentation.
    pub fn new_with_setup(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit_security: bool,
        mut setup: ClSetup,
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

            // -- Round 2 broadcast: collect PVSS distributions + DKG-CL Gen data --
            (KeygenRound::Round2(mut state), Jtx25KeygenMsg::Round2(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round2(state);
                    return Err(TecdsaError::Other(format!("duplicate R2 from {from}")));
                }

                let my_id = state.my_id;
                let my_idx = state
                    .all_parties
                    .iter()
                    .position(|p| *p == my_id)
                    .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;

                let (c1, c2s, proof, dkg_cl_gen_per_recipient) =
                    deserialize_round2_full(&data, my_idx).map_err(|e| {
                        TecdsaError::Other(format!("R2 deserialize from {from}: {e}"))
                    })?;

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

                // Verify PVSS R_Sh proof.
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

                // Verify DKG-CL GenVf (R_Blnt proof).
                let from_idx = state
                    .all_parties
                    .iter()
                    .position(|p| *p == from)
                    .ok_or_else(|| TecdsaError::Other(format!("from {from} not in all_parties")))?;
                let my_id = state.my_id;
                let my_idx = state
                    .all_parties
                    .iter()
                    .position(|p| *p == my_id)
                    .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;

                let dealer_pk = &ordered_pks[from_idx];
                let my_pk = &ordered_pks[my_idx];

                let gen_vf_ok = dkg_cl::dkg_cl_gen_verify(
                    &self.setup,
                    &dkg_cl_gen_per_recipient,
                    dealer_pk,
                    my_pk,
                )
                .map_err(|e| TecdsaError::Other(format!("DKG-CL GenVf from {from}: {e}")))?;

                if !gen_vf_ok {
                    return Err(TecdsaError::Other(format!(
                        "DKG-CL R_Blnt proof failed for party {from}"
                    )));
                }

                state.received.insert(from, Round2Msg { c1, c2s });
                state.dkg_cl_received.insert(from, dkg_cl_gen_per_recipient);

                // Transition when broadcast and P2P received from all peers.
                let expected = self.expected_count();
                if state.received.len() == expected
                    && state.dkg_cl_received.len() == expected
                    && state.p2p_received.len() == expected
                {
                    let new_state = self.transition_r2_to_r3(state)?;
                    self.round = KeygenRound::Round3(new_state);
                } else {
                    self.round = KeygenRound::Round2(state);
                }
                Ok(())
            }

            // -- Round 2 P2P: synchronization messages --
            // In the paper-compliant DKG-CL, all per-recipient data is
            // broadcast (proofs are publicly verifiable). P2P messages are
            // retained for round synchronization only.
            (KeygenRound::Round2(mut state), Jtx25KeygenMsg::Round2P2p(_data)) => {
                if !state.all_parties.contains(&from) {
                    self.round = KeygenRound::Round2(state);
                    return Err(TecdsaError::Other(format!("unknown party: {from}")));
                }
                if state.p2p_received.contains(&from) {
                    self.round = KeygenRound::Round2(state);
                    return Err(TecdsaError::Other(format!("duplicate R2 P2P from {from}")));
                }
                state.p2p_received.insert(from);

                // Transition when broadcast and P2P received from all peers.
                let expected = self.expected_count();
                if state.received.len() == expected
                    && state.dkg_cl_received.len() == expected
                    && state.p2p_received.len() == expected
                {
                    let new_state = self.transition_r2_to_r3(state)?;
                    self.round = KeygenRound::Round3(new_state);
                } else {
                    self.round = KeygenRound::Round2(state);
                }
                Ok(())
            }

            // -- Round 3: collect public shares + DKG-CL Reveal data --
            (KeygenRound::Round3(mut state), Jtx25KeygenMsg::Round3(data)) => {
                if state.received.contains_key(&from) {
                    self.round = KeygenRound::Round3(state);
                    return Err(TecdsaError::Other(format!("duplicate R3 from {from}")));
                }

                let (public_share, proof, pd, dkg_cl_reveal_wire) = deserialize_round3(&data)
                    .map_err(|e| TecdsaError::Other(format!("R3 deserialize from {from}: {e}")))?;

                // Verify R_Dec_DL for PVSS.
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

                // Verify DKG-CL RevealVf (R_GDec-CL proof).
                let from_reveal_ct = self
                    .setup
                    .ct_from_components(
                        &dkg_cl_reveal_wire.combined_ct_c1,
                        &dkg_cl_reveal_wire.combined_ct_c2,
                    )
                    .map_err(|e| {
                        TecdsaError::Other(format!("ct_from_components for reveal: {e}"))
                    })?;

                let from_reveal_output = DkgClRevealOutput {
                    combined_share: dkg_cl_reveal_wire.combined_share.clone(),
                    pk_share: dkg_cl_reveal_wire.lifted_share.clone(),
                    proof: tecdsa_class_group::zk::r_gdec_cl::RGdecClProof::from_parts(
                        dkg_cl_reveal_wire.proof_t1.clone(),
                        dkg_cl_reveal_wire.proof_t2.clone(),
                        dkg_cl_reveal_wire.proof_z.clone(),
                        dkg_cl_reveal_wire.proof_e.clone(),
                    ),
                    combined_ct: from_reveal_ct,
                };

                let reveal_vf_ok =
                    dkg_cl::dkg_cl_reveal_verify(&self.setup, &from_reveal_output, &from_pk_raw)
                        .map_err(|e| {
                            TecdsaError::Other(format!("DKG-CL RevealVf from {from}: {e}"))
                        })?;

                if !reveal_vf_ok {
                    return Err(TecdsaError::Other(format!(
                        "DKG-CL R_GDec-CL proof failed for party {from}"
                    )));
                }

                let lifted_share = dkg_cl_reveal_wire.lifted_share.clone();
                state.received.insert(
                    from,
                    Round3Msg {
                        public_share,
                        dkg_cl_lifted_share: lifted_share,
                        _dkg_cl_proof: dkg_cl_reveal_wire,
                    },
                );

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

        // --- DKG-CL Gen: paper-compliant chunk encryption + R_Blnt ---
        // threshold parameter for DKG-CL: corruption threshold t where
        // reconstruction needs t+1 shares. Our `state.threshold` is the
        // reconstruction threshold, so corruption threshold = threshold - 1.
        let dkg_cl_t = (state.threshold - 1) as usize;

        let dkg_cl_gen_output = dkg_cl::dkg_cl_gen_with_secret(
            &mut self.setup,
            &ordered_pks,
            n,
            dkg_cl_t,
            my_idx,
            &state.cl_sk_bytes,
        )
        .map_err(|e| TecdsaError::Other(format!("DKG-CL Gen failed: {e}")))?;

        // Serialize Round 2 broadcast: PVSS data + DKG-CL Gen per-recipient
        // data for the recipient (we send our own per-recipient[my_idx] as
        // a self-reference; each peer gets per_recipient[peer_idx]).
        //
        // The broadcast carries: PVSS + DKG-CL Gen data for the RECEIVER.
        // Since each peer needs different per-recipient data, we need to
        // send per-peer messages.
        //
        // Design choice: We send a single broadcast with PVSS data + our
        // OWN DKG-CL per-recipient[receiver_idx] in per-party messages.
        // But since the Orchestrator/transport layer supports broadcast +
        // P2P, we use broadcast for PVSS and P2P for DKG-CL per-recipient.
        //
        // Actually, looking at the existing pattern: Round2 broadcast carries
        // PVSS and Round2P2p carries per-recipient data. We'll reuse this
        // pattern: broadcast carries PVSS + our DKG-CL per_recipient[my_idx]
        // (self data, needed by all for round completion), and P2P carries
        // per_recipient[peer_idx] for each peer.
        //
        // REVISED: To simplify verification, we send per-recipient-specific
        // Round2 broadcast messages. Since the transport layer broadcasts
        // to all, and each receiver extracts their data from the broadcast,
        // we encode the DKG-CL per-recipient data for ALL recipients in the
        // broadcast. This is simpler and matches the paper (all Gen data is
        // public).

        let r2_payload = serialize_round2_with_dkg_cl(&pvss_output, &dkg_cl_gen_output, n)
            .map_err(|e| TecdsaError::Other(format!("R2 serialize: {e}")))?;

        // Build outgoing: broadcast PVSS + DKG-CL Gen data.
        let mut outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25KeygenMsg::Round2(r2_payload),
        }];

        // Send P2P messages (kept for round synchronization).
        // Each peer gets a dummy P2P message to satisfy the round gate.
        for pid in &state.all_parties {
            if *pid == my_id {
                continue;
            }
            outgoing.push(Outgoing {
                to: Recipient::Party(*pid),
                msg: Jtx25KeygenMsg::Round2P2p(vec![]),
            });
        }

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
            dkg_cl_gen_output,
            dkg_cl_received: BTreeMap::new(),
            p2p_received: std::collections::BTreeSet::new(),
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
        let n = state.all_parties.len();

        // ---- DKG-Sig: PVSS decrypt and combine ----

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

        // ---- DKG-CL Reveal (JTX25 variant: integer shares, no mod-q) ----
        // Collect chunk ciphertexts addressed to this party from all dealers.
        // Decrypt chunks, recompose to integer Shamir shares, sum WITHOUT
        // mod-q reduction to produce shares compatible with t_cl::partial_decrypt.
        let mut received_chunks: Vec<Vec<(Qfi, Qfi)>> = Vec::with_capacity(n);
        let mut all_dkg_cl_chunk_cts: BTreeMap<PartyId, Vec<(Qfi, Qfi)>> = BTreeMap::new();

        for pid in &state.all_parties {
            if *pid == my_id {
                let my_gen_per_recipient = &state.dkg_cl_gen_output.per_recipient[my_idx];
                received_chunks.push(my_gen_per_recipient.chunk_cts.clone());
                all_dkg_cl_chunk_cts.insert(*pid, my_gen_per_recipient.chunk_cts.clone());
            } else {
                let gen_per_recipient = state
                    .dkg_cl_received
                    .get(pid)
                    .ok_or_else(|| TecdsaError::Other(format!("missing DKG-CL Gen from {pid}")))?;
                received_chunks.push(gen_per_recipient.chunk_cts.clone());
                all_dkg_cl_chunk_cts.insert(*pid, gen_per_recipient.chunk_cts.clone());
            }
        }

        let my_pk_for_reveal = self
            .setup
            .pk_from_qfi(state.cl_pk_raw.elt())
            .map_err(|e| TecdsaError::Other(format!("pk_from_qfi for reveal: {e}")))?;

        let dkg_cl_reveal = dkg_cl::dkg_cl_reveal(
            &mut self.setup,
            &state.cl_sk_bytes,
            &my_pk_for_reveal,
            &received_chunks,
            n,
        )
        .map_err(|e| TecdsaError::Other(format!("DKG-CL Reveal failed: {e}")))?;

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

        // Extract R_GDec-CL proof parts for serialization.
        let (proof_t1, proof_t2, proof_z, proof_e) = dkg_cl_reveal.proof.to_parts();
        let (combined_ct_c1, combined_ct_c2) = self
            .setup
            .ct_components(&dkg_cl_reveal.combined_ct)
            .map_err(|e| TecdsaError::Other(format!("ct_components for reveal ct: {e}")))?;

        let r3_payload = serialize_round3(
            &big_x_i_bytes,
            &pd,
            &r_dec_dl_proof,
            &dkg_cl_reveal.pk_share,
            &proof_t1,
            &proof_t2,
            &proof_z,
            &proof_e,
            &dkg_cl_reveal.combined_share,
            &combined_ct_c1,
            &combined_ct_c2,
        )
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
            dkg_cl_combined_share: dkg_cl_reveal.combined_share,
            my_dkg_cl_lifted_share: dkg_cl_reveal.pk_share,
            _my_dkg_cl_combined_ct: dkg_cl_reveal.combined_ct,
            _all_dkg_cl_chunk_cts: all_dkg_cl_chunk_cts,
            cl_pk_abcs: state.cl_pk_abcs,
            pvss_c1_abcs,
        })
    }
}

/// Finalize keygen: collect public shares, compute joint ECDSA public key,
/// aggregate CL public keys via DKG-CL, and store combined CL threshold shares.
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

    // --- Aggregate CL public key: pk = compose(pk_1, ..., pk_n) = h^{sum(sk_i)} ---
    let mut agg_pk_qfi = setup
        .identity()
        .map_err(|e| TecdsaError::Other(format!("CL identity: {e}")))?;
    for pid in &state.all_parties {
        let abc = state
            .cl_pk_abcs
            .get(pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing pk_abc for {pid}")))?;
        let qfi = abc_to_qfi(abc).map_err(|e| TecdsaError::Other(format!("abc_to_qfi: {e}")))?;
        agg_pk_qfi = setup
            .compose(&agg_pk_qfi, &qfi)
            .map_err(|e| TecdsaError::Other(format!("compose CL pk: {e}")))?;
    }
    let cl_pk = setup
        .pk_from_qfi(&agg_pk_qfi)
        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi agg: {e}")))?;

    // Collect per-party CL public key shares: h^{combined_integer_share_j}.
    // These are broadcast in Round 3 using the historical "lifted share" field.
    let mut cl_pk_shares: Vec<Qfi> = Vec::with_capacity(n);
    for pid in &state.all_parties {
        if *pid == my_id {
            cl_pk_shares.push(state.my_dkg_cl_lifted_share.clone());
        } else {
            let r3_msg = state
                .received
                .get(pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing R3 from {pid}")))?;
            cl_pk_shares.push(r3_msg.dkg_cl_lifted_share.clone());
        }
    }

    Ok(Jtx25KeyShare {
        party_index,
        secret_share: state.secret_share,
        public_key,
        public_shares,
        cl_sk_share: state.dkg_cl_combined_share,
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
// Threshold CL key sharing (delta-scaled Shamir) -- utility for tests
// ---------------------------------------------------------------------------

/// Generates threshold CL key shares using the delta-scaled Shamir scheme.
/// Used by the threshold CL partial/final decrypt tests (not by the paper-
/// compliant DKG-CL protocol flow which uses `dkg_cl` module instead).
pub fn shamir_share_delta(
    setup: &mut ClSetup,
    sk_bytes: &[u8],
    n: usize,
    t: usize,
) -> Result<Vec<Vec<u8>>, Jtx25Error> {
    use num_bigint::{BigInt, BigUint};

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

/// Write a Qfi as binary (length-prefixed to_bytes()).
fn write_qfi_bin(buf: &mut Vec<u8>, qfi: &Qfi) {
    let bytes = qfi.to_bytes();
    write_field(buf, &bytes);
}

/// Read a Qfi from binary (length-prefixed from_bytes()).
fn read_qfi_bin(data: &[u8], pos: usize) -> Result<(Qfi, usize), Jtx25Error> {
    let (bytes, new_pos) = read_field(data, pos)?;
    Ok((Qfi::from_bytes(bytes), new_pos))
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

/// Serialize Round 2 broadcast: PVSS data + DKG-CL Gen per-recipient data for
/// all n recipients.
fn serialize_round2_with_dkg_cl(
    pvss: &PvssShareOutput,
    dkg_cl_gen: &DkgClGenOutput,
    n: usize,
) -> Result<Vec<u8>, Jtx25Error> {
    let mut buf = Vec::new();

    // ---- PVSS section ----
    buf.extend_from_slice(&(pvss.c2s.len() as u32).to_le_bytes());
    let c1_abc = qfi_to_abc(&pvss.c1)?;
    write_qfi_abc(&mut buf, &c1_abc);
    for c2 in &pvss.c2s {
        let c2_abc = qfi_to_abc(c2)?;
        write_qfi_abc(&mut buf, &c2_abc);
    }
    write_field(&mut buf, &pvss.proof.k);
    write_field(&mut buf, &pvss.proof.rho_response);

    // ---- DKG-CL Gen section ----
    // Number of recipients.
    buf.extend_from_slice(&(n as u32).to_le_bytes());

    for recipient_idx in 0..n {
        let per = &dkg_cl_gen.per_recipient[recipient_idx];

        // PC (Pedersen commitment)
        write_qfi_bin(&mut buf, &per.pc);

        // Number of chunk ciphertexts
        buf.extend_from_slice(&(per.chunk_cts.len() as u32).to_le_bytes());
        for (c0, c1) in &per.chunk_cts {
            write_qfi_bin(&mut buf, c0);
            write_qfi_bin(&mut buf, c1);
        }

        // Aggregated ciphertext (c0, c1)
        write_qfi_bin(&mut buf, &per.agg_ct.0);
        write_qfi_bin(&mut buf, &per.agg_ct.1);

        // R_Blnt proof
        serialize_r_blnt_proof(&mut buf, &per.proof);
    }

    Ok(buf)
}

fn serialize_r_blnt_proof(buf: &mut Vec<u8>, proof: &tecdsa_class_group::zk::r_blnt::RBlntProof) {
    // c_commit
    write_qfi_bin(buf, &proof.c_commit);
    // r_chunks count + elements
    buf.extend_from_slice(&(proof.r_chunks.len() as u32).to_le_bytes());
    for r in &proof.r_chunks {
        write_qfi_bin(buf, r);
    }
    // s_chunks count + elements
    buf.extend_from_slice(&(proof.s_chunks.len() as u32).to_le_bytes());
    for s in &proof.s_chunks {
        write_qfi_bin(buf, s);
    }
    // r_0, s_0
    write_qfi_bin(buf, &proof.r_0);
    write_qfi_bin(buf, &proof.s_0);
    // z1_chunks
    buf.extend_from_slice(&(proof.z1_chunks.len() as u32).to_le_bytes());
    for z in &proof.z1_chunks {
        write_field(buf, z);
    }
    // z3_chunks
    buf.extend_from_slice(&(proof.z3_chunks.len() as u32).to_le_bytes());
    for z in &proof.z3_chunks {
        write_field(buf, z);
    }
    // z2, z4, e
    write_field(buf, &proof.z2);
    write_field(buf, &proof.z4);
    write_field(buf, &proof.e);
}

fn deserialize_r_blnt_proof(
    data: &[u8],
    pos: usize,
) -> Result<(tecdsa_class_group::zk::r_blnt::RBlntProof, usize), Jtx25Error> {
    let (c_commit, mut pos) = read_qfi_bin(data, pos)?;

    // r_chunks
    if pos + 4 > data.len() {
        return Err(Jtx25Error::InvalidInput("truncated r_chunks count".into()));
    }
    let r_chunks_len = u32::from_le_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| Jtx25Error::InvalidInput("bad r_chunks count".into()))?,
    ) as usize;
    pos += 4;
    let mut r_chunks = Vec::with_capacity(r_chunks_len);
    for _ in 0..r_chunks_len {
        let (qfi, new_pos) = read_qfi_bin(data, pos)?;
        r_chunks.push(qfi);
        pos = new_pos;
    }

    // s_chunks
    if pos + 4 > data.len() {
        return Err(Jtx25Error::InvalidInput("truncated s_chunks count".into()));
    }
    let s_chunks_len = u32::from_le_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| Jtx25Error::InvalidInput("bad s_chunks count".into()))?,
    ) as usize;
    pos += 4;
    let mut s_chunks = Vec::with_capacity(s_chunks_len);
    for _ in 0..s_chunks_len {
        let (qfi, new_pos) = read_qfi_bin(data, pos)?;
        s_chunks.push(qfi);
        pos = new_pos;
    }

    // r_0, s_0
    let (r_0, pos) = read_qfi_bin(data, pos)?;
    let (s_0, mut pos) = read_qfi_bin(data, pos)?;

    // z1_chunks
    if pos + 4 > data.len() {
        return Err(Jtx25Error::InvalidInput("truncated z1_chunks count".into()));
    }
    let z1_len = u32::from_le_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| Jtx25Error::InvalidInput("bad z1 count".into()))?,
    ) as usize;
    pos += 4;
    let mut z1_chunks = Vec::with_capacity(z1_len);
    for _ in 0..z1_len {
        let (bytes, new_pos) = read_field(data, pos)?;
        z1_chunks.push(bytes.to_vec());
        pos = new_pos;
    }

    // z3_chunks
    if pos + 4 > data.len() {
        return Err(Jtx25Error::InvalidInput("truncated z3_chunks count".into()));
    }
    let z3_len = u32::from_le_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| Jtx25Error::InvalidInput("bad z3 count".into()))?,
    ) as usize;
    pos += 4;
    let mut z3_chunks = Vec::with_capacity(z3_len);
    for _ in 0..z3_len {
        let (bytes, new_pos) = read_field(data, pos)?;
        z3_chunks.push(bytes.to_vec());
        pos = new_pos;
    }

    // z2, z4, e
    let (z2, pos) = read_field(data, pos)?;
    let (z4, pos) = read_field(data, pos)?;
    let (e, pos) = read_field(data, pos)?;

    Ok((
        tecdsa_class_group::zk::r_blnt::RBlntProof {
            c_commit,
            r_chunks,
            s_chunks,
            r_0,
            s_0,
            z1_chunks,
            z3_chunks,
            z2: z2.to_vec(),
            z4: z4.to_vec(),
            e: e.to_vec(),
        },
        pos,
    ))
}

/// Deserialize Round 2 broadcast: PVSS data + DKG-CL Gen per-recipient data.
/// The receiver extracts their DKG-CL per-recipient bundle using `my_idx`.
#[allow(clippy::type_complexity)]
fn deserialize_round2_full(
    data: &[u8],
    my_idx: usize,
) -> Result<(Qfi, Vec<Qfi>, RShProof, DkgClGenPerRecipient), Jtx25Error> {
    if data.len() < 4 {
        return Err(Jtx25Error::InvalidInput("R2 data too short".into()));
    }

    // ---- PVSS section ----
    let n_pvss = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| Jtx25Error::InvalidInput("bad n".into()))?,
    ) as usize;
    let mut pos = 4;
    let (c1_abc, new_pos) = read_qfi_abc(data, pos)?;
    pos = new_pos;
    let c1 = abc_to_qfi(&c1_abc)?;
    let mut c2s = Vec::with_capacity(n_pvss);
    for _ in 0..n_pvss {
        let (c2_abc, new_pos) = read_qfi_abc(data, pos)?;
        pos = new_pos;
        c2s.push(abc_to_qfi(&c2_abc)?);
    }
    let (k_bytes, new_pos) = read_field(data, pos)?;
    pos = new_pos;
    let (rho_response_bytes, new_pos) = read_field(data, pos)?;
    pos = new_pos;
    let proof = RShProof {
        k: k_bytes.to_vec(),
        rho_response: rho_response_bytes.to_vec(),
    };

    // ---- DKG-CL Gen section ----
    if pos + 4 > data.len() {
        return Err(Jtx25Error::InvalidInput("truncated DKG-CL count".into()));
    }
    let n_dkg = u32::from_le_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| Jtx25Error::InvalidInput("bad DKG-CL count".into()))?,
    ) as usize;
    pos += 4;

    let mut my_per_recipient: Option<DkgClGenPerRecipient> = None;

    for recipient_idx in 0..n_dkg {
        // PC
        let (pc, new_pos) = read_qfi_bin(data, pos)?;
        pos = new_pos;

        // chunk_cts count
        if pos + 4 > data.len() {
            return Err(Jtx25Error::InvalidInput("truncated chunk_cts count".into()));
        }
        let num_chunks = u32::from_le_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| Jtx25Error::InvalidInput("bad chunk count".into()))?,
        ) as usize;
        pos += 4;

        let mut chunk_cts = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            let (c0, new_pos) = read_qfi_bin(data, pos)?;
            pos = new_pos;
            let (c1_chunk, new_pos) = read_qfi_bin(data, pos)?;
            pos = new_pos;
            chunk_cts.push((c0, c1_chunk));
        }

        // agg_ct
        let (agg_c0, new_pos) = read_qfi_bin(data, pos)?;
        pos = new_pos;
        let (agg_c1, new_pos) = read_qfi_bin(data, pos)?;
        pos = new_pos;

        // R_Blnt proof
        let (proof_blnt, new_pos) = deserialize_r_blnt_proof(data, pos)?;
        pos = new_pos;

        if recipient_idx == my_idx {
            my_per_recipient = Some(DkgClGenPerRecipient {
                pc,
                chunk_cts,
                agg_ct: (agg_c0, agg_c1),
                proof: proof_blnt,
            });
        }
    }

    let per_recipient = my_per_recipient.ok_or_else(|| {
        Jtx25Error::InvalidInput(format!(
            "my_idx {my_idx} out of range for {n_dkg} recipients"
        ))
    })?;

    Ok((c1, c2s, proof, per_recipient))
}

fn serialize_round3(
    public_share_bytes: &[u8],
    pd: &Qfi,
    proof: &RDecDlProof,
    dkg_cl_lifted_share: &Qfi,
    dkg_cl_proof_t1: &Qfi,
    dkg_cl_proof_t2: &Qfi,
    dkg_cl_proof_z: &[u8],
    dkg_cl_proof_e: &[u8],
    dkg_cl_combined_share: &[u8],
    dkg_cl_combined_ct_c1: &Qfi,
    dkg_cl_combined_ct_c2: &Qfi,
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

    // DKG-CL Reveal data
    write_qfi_bin(&mut buf, dkg_cl_lifted_share);
    write_qfi_bin(&mut buf, dkg_cl_proof_t1);
    write_qfi_bin(&mut buf, dkg_cl_proof_t2);
    write_field(&mut buf, dkg_cl_proof_z);
    write_field(&mut buf, dkg_cl_proof_e);
    write_field(&mut buf, dkg_cl_combined_share);
    write_qfi_bin(&mut buf, dkg_cl_combined_ct_c1);
    write_qfi_bin(&mut buf, dkg_cl_combined_ct_c2);

    Ok(buf)
}

#[allow(clippy::type_complexity)]
fn deserialize_round3(
    data: &[u8],
) -> Result<(k256::ProjectivePoint, RDecDlProof, Qfi, DkgClRevealWire), Jtx25Error> {
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
    let (e_bytes, pos) = read_field(data, pos)?;
    let t1 = abc_to_qfi(&t1_abc)?;
    let t2 = abc_to_qfi(&t2_abc)?;
    let dec_dl_proof = RDecDlProof {
        t1,
        t2,
        z: z_bytes.to_vec(),
        e: e_bytes.to_vec(),
    };

    // DKG-CL Reveal data
    let (dkg_cl_lifted_share, pos) = read_qfi_bin(data, pos)?;
    let (dkg_cl_proof_t1, pos) = read_qfi_bin(data, pos)?;
    let (dkg_cl_proof_t2, pos) = read_qfi_bin(data, pos)?;
    let (dkg_cl_proof_z, pos) = read_field(data, pos)?;
    let (dkg_cl_proof_e, pos) = read_field(data, pos)?;
    let (dkg_cl_combined_share, pos) = read_field(data, pos)?;
    let (dkg_cl_combined_ct_c1, pos) = read_qfi_bin(data, pos)?;
    let (dkg_cl_combined_ct_c2, _pos) = read_qfi_bin(data, pos)?;

    let dkg_cl_reveal_wire = DkgClRevealWire {
        lifted_share: dkg_cl_lifted_share,
        proof_t1: dkg_cl_proof_t1,
        proof_t2: dkg_cl_proof_t2,
        proof_z: dkg_cl_proof_z.to_vec(),
        proof_e: dkg_cl_proof_e.to_vec(),
        combined_share: dkg_cl_combined_share.to_vec(),
        combined_ct_c1: dkg_cl_combined_ct_c1,
        combined_ct_c2: dkg_cl_combined_ct_c2,
    };

    Ok((point, dec_dl_proof, pd, dkg_cl_reveal_wire))
}
