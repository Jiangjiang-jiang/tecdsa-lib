// SPDX-License-Identifier: MIT OR Apache-2.0
//! Presign `StateMachine` for XAL23 (4-round interactive protocol).
//!
//! ## Protocol overview
//!
//! Round 1: commit to Gamma_i + MtA sender_encrypt for gamma and w.
//! Round 2: decommit Gamma_i + MtA receiver_compute.
//! Round 3: MtA sender_decrypt + compute/broadcast delta_i.
//! Round 4: collect deltas, reconstruct R, output presignature.
//!
//! ## Backward compatibility
//!
//! The `new_simulation` constructor provides the old simulation-mode behavior:
//! it runs `presign_all_with_sec` internally and wraps the result.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    non_snake_case
)]

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};

use super::msg::{
    R1BroadcastPayload, R1P2pPayload, R2BroadcastPayload, R2P2pPayload, R3BroadcastPayload,
    Xal23PresignMsg,
};
use super::rounds::{
    build_round1, finalize_r3, transition_r1_to_r2, transition_r2_to_r3, PresignRound, Round1State,
    Round2State, Round3State,
};
use super::Xal23Presignature;
use crate::key_share::Xal23KeyShare;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Number of expected messages from peers (all parties minus self).
fn n_peers(all_parties: &[PartyId]) -> usize {
    all_parties.len() - 1
}

/// Get my_id from the current round state.
fn my_id_of<C: TecdsaCurve>(round: &PresignRound<C>) -> PartyId
where
    FieldBytesSize<C>: ModulusSize,
{
    match round {
        PresignRound::Round1(s) => s.my_id,
        PresignRound::Round2(s) => s.my_id,
        PresignRound::Round3(s) => s.my_id,
        PresignRound::Done(_) | PresignRound::Poisoned => PartyId(u16::MAX),
    }
}

// ---------------------------------------------------------------------------
// Xal23PresignMachine
// ---------------------------------------------------------------------------

/// 4-round presigning `StateMachine` for XAL23.
///
/// Implements the full interactive presign protocol using JL-based MtA.
/// Driven by the Orchestrator/Session layer via the `StateMachine` trait.
///
/// ## Construction
///
/// Use `Xal23PresignMachine::new()` to create the machine. Round 1 messages
/// are immediately queued (drain with `drain_outgoing()`).
///
/// ## Simulation mode
///
/// Use `Xal23PresignMachine::new_simulation()` for backward-compatible
/// simulation that runs all rounds internally on construction.
pub struct Xal23PresignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: PresignRound<C>,
}

impl<C: TecdsaCurve> Xal23PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new interactive presign state machine.
    ///
    /// Immediately runs Round 1 (sample k_i, gamma_i, commit,
    /// sender_encrypt) and queues R1 messages for all peers.
    ///
    /// # Arguments
    ///
    /// * `my_id` - This party's identifier
    /// * `all_parties` - All signing party identifiers in consistent order
    /// * `key_share` - This party's key share from keygen
    /// * `rng` - Cryptographic RNG
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        key_share: &Xal23KeyShare<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> tecdsa_core::Result<Self> {
        Self::with_sec(my_id, all_parties, key_share, 40, 40, rng)
    }

    pub fn with_sec(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        key_share: &Xal23KeyShare<C>,
        s: u32,
        t: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> tecdsa_core::Result<Self> {
        let r1 = build_round1(my_id, all_parties, key_share, s, t, rng)?;
        Ok(Self {
            round: PresignRound::Round1(r1),
        })
    }

    /// Create a simulation-mode presign machine (backward compatibility).
    ///
    /// Runs `presign_all_with_sec` internally and wraps the local party's
    /// presignature. The machine starts in "done" state.
    pub fn new_simulation(
        key_shares: &[Xal23KeyShare<C>],
        signer_indices: &[usize],
        local_signer_pos: usize,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let presignatures = super::presign_all_with_sec(key_shares, signer_indices, 40, 40, rng);
        let presig = presignatures
            .into_iter()
            .nth(local_signer_pos)
            .expect("local_signer_pos out of bounds");
        Self {
            round: PresignRound::Done(presig),
        }
    }

    /// Handle a Round 1 broadcast message.
    fn handle_r1_broadcast(
        state: &mut Round1State<C>,
        from: PartyId,
        payload: R1BroadcastPayload,
    ) -> tecdsa_core::Result<()> {
        if !state.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }
        if state.commitments.contains_key(&from) {
            return Err(TecdsaError::Other(format!(
                "duplicate R1 broadcast from {from}"
            )));
        }
        state.commitments.insert(from, payload.commitment);
        Ok(())
    }

    /// Handle a Round 1 P2P message.
    fn handle_r1_p2p(
        state: &mut Round1State<C>,
        from: PartyId,
        payload: R1P2pPayload,
    ) -> tecdsa_core::Result<()> {
        if !state.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }
        if state.r1_p2p.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate R1 P2P from {from}")));
        }
        state.r1_p2p.insert(from, payload);
        Ok(())
    }

    /// Check if Round 1 has collected all messages and should transition.
    fn r1_complete(state: &Round1State<C>) -> bool {
        let np = n_peers(&state.all_parties);
        // We need commitment from all peers + own = all_parties.len()
        state.commitments.len() == state.all_parties.len() && state.r1_p2p.len() == np
    }

    /// Handle a Round 2 broadcast message.
    fn handle_r2_broadcast(
        state: &mut Round2State<C>,
        from: PartyId,
        payload: R2BroadcastPayload,
    ) -> tecdsa_core::Result<()> {
        if !state.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }
        if state.r2_bcast.contains_key(&from) {
            return Err(TecdsaError::Other(format!(
                "duplicate R2 broadcast from {from}"
            )));
        }
        state.r2_bcast.insert(from, payload);
        Ok(())
    }

    /// Handle a Round 2 P2P message.
    fn handle_r2_p2p(
        state: &mut Round2State<C>,
        from: PartyId,
        payload: R2P2pPayload,
    ) -> tecdsa_core::Result<()> {
        if !state.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }
        if state.r2_p2p.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate R2 P2P from {from}")));
        }
        state.r2_p2p.insert(from, payload);
        Ok(())
    }

    /// Check if Round 2 has collected all messages and should transition.
    fn r2_complete(state: &Round2State<C>) -> bool {
        let np = n_peers(&state.all_parties);
        state.r2_bcast.len() == np && state.r2_p2p.len() == np
    }

    /// Handle a Round 3 broadcast (delta_j).
    fn handle_r3_broadcast(
        state: &mut Round3State<C>,
        from: PartyId,
        payload: R3BroadcastPayload,
    ) -> tecdsa_core::Result<()> {
        if !state.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }
        if state.deltas.contains_key(&from) {
            return Err(TecdsaError::Other(format!(
                "duplicate R3 broadcast from {from}"
            )));
        }
        let delta_j = super::rounds::scalar_from_bytes::<C>(&payload.delta_i_bytes)?;
        state.deltas.insert(from, delta_j);
        Ok(())
    }

    /// Check if Round 3 has collected all deltas and should finalize.
    fn r3_complete(state: &Round3State<C>) -> bool {
        state.deltas.len() == state.all_parties.len()
    }
}

// ---------------------------------------------------------------------------
// StateMachine implementation
// ---------------------------------------------------------------------------

impl<C: TecdsaCurve> StateMachine for Xal23PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Xal23Presignature<C>;
    type Inbound = Xal23PresignMsg;
    type Outbound = Xal23PresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        let my_id = my_id_of(&self.round);
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        // Take the current round state (replace with Poisoned temporarily).
        let round = std::mem::replace(&mut self.round, PresignRound::Poisoned);

        match round {
            PresignRound::Round1(mut state) => {
                match msg {
                    Xal23PresignMsg::R1Broadcast(payload) => {
                        if let Err(e) = Self::handle_r1_broadcast(&mut state, from, payload) {
                            self.round = PresignRound::Round1(state);
                            return Err(e);
                        }
                    }
                    Xal23PresignMsg::R1P2p(payload) => {
                        if let Err(e) = Self::handle_r1_p2p(&mut state, from, payload) {
                            self.round = PresignRound::Round1(state);
                            return Err(e);
                        }
                    }
                    _ => {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(
                            "unexpected message type in round 1".into(),
                        ));
                    }
                }

                if Self::r1_complete(&state) {
                    let mut rng = rand::thread_rng();
                    match transition_r1_to_r2(state, &mut rng) {
                        Ok(r2) => self.round = PresignRound::Round2(r2),
                        Err(e) => {
                            // Cannot restore Round1 state as it was consumed.
                            // Machine is poisoned.
                            return Err(e);
                        }
                    }
                } else {
                    self.round = PresignRound::Round1(state);
                }
            }

            PresignRound::Round2(mut state) => {
                match msg {
                    Xal23PresignMsg::R2Broadcast(payload) => {
                        if let Err(e) = Self::handle_r2_broadcast(&mut state, from, payload) {
                            self.round = PresignRound::Round2(state);
                            return Err(e);
                        }
                    }
                    Xal23PresignMsg::R2P2p(payload) => {
                        if let Err(e) = Self::handle_r2_p2p(&mut state, from, payload) {
                            self.round = PresignRound::Round2(state);
                            return Err(e);
                        }
                    }
                    _ => {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(
                            "unexpected message type in round 2".into(),
                        ));
                    }
                }

                if Self::r2_complete(&state) {
                    match transition_r2_to_r3(state) {
                        Ok(r3) => self.round = PresignRound::Round3(r3),
                        Err(e) => {
                            return Err(e);
                        }
                    }
                } else {
                    self.round = PresignRound::Round2(state);
                }
            }

            PresignRound::Round3(mut state) => {
                match msg {
                    Xal23PresignMsg::R3Broadcast(payload) => {
                        if let Err(e) = Self::handle_r3_broadcast(&mut state, from, payload) {
                            self.round = PresignRound::Round3(state);
                            return Err(e);
                        }
                    }
                    _ => {
                        self.round = PresignRound::Round3(state);
                        return Err(TecdsaError::Other(
                            "unexpected message type in round 3".into(),
                        ));
                    }
                }

                if Self::r3_complete(&state) {
                    match finalize_r3(&state) {
                        Ok(presig) => self.round = PresignRound::Done(presig),
                        Err(e) => {
                            self.round = PresignRound::Round3(state);
                            return Err(e);
                        }
                    }
                } else {
                    self.round = PresignRound::Round3(state);
                }
            }

            PresignRound::Done(presig) => {
                self.round = PresignRound::Done(presig);
                return Err(TecdsaError::Other(
                    "presign already complete, no more messages expected".into(),
                ));
            }

            PresignRound::Poisoned => {
                return Err(TecdsaError::Other(
                    "presign machine is in poisoned state".into(),
                ));
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRound::Round1(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Round2(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Round3(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Done(_) | PresignRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, PresignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            PresignRound::Done(presig) => Ok(presig),
            _ => Err(TecdsaError::Other("presign not complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            PresignRound::Round1(_) => 1,
            PresignRound::Round2(_) => 2,
            PresignRound::Round3(_) => 3,
            PresignRound::Done(_) => 4,
            PresignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
