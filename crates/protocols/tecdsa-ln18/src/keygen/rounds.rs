// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state structs and transition logic for LN18 KeyGen (Protocol 5.1).
//!
//! KeyGen sequences three F_mult sub-operations:
//! 1. **init** (2 rounds): distributed ElGamal keypair generation
//! 2. **input** (2 rounds): each party inputs its ECDSA secret share x_i
//!    via commit-then-prove (F_{com-zk} hybrid model)
//! 3. **element-out** (1 round): reveal Q = x*G as the joint ECDSA public key
//!
//! Total: 5 interaction rounds.

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{Outgoing, PartyId, Recipient, SessionConfig};
use zeroize::Zeroize;

use super::msg::{
    Ln18KeygenMsg, SerElementOut, SerInitRound1, SerInitRound2, SerInputRound1, SerInputRound2,
};
use crate::{
    f_mult::{
        element_out::{ElementOutMsg, ElementOutState},
        init::{InitOutput, InitRound1Msg, InitRound2Msg, InitState},
        input::{InputOutput, InputRound1Msg, InputRound2Msg, InputState},
    },
    key_share::Ln18KeyShare,
};

// ---------------------------------------------------------------------------
// Round enum
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) enum KeygenRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Round 1: init sub-protocol, waiting for Round-1 commitments.
    InitRound1(InitRound1State<C>),
    /// Round 2: init sub-protocol, waiting for Round-2 decommitments.
    InitRound2(InitRound2State<C>),
    /// Round 3: input sub-protocol, waiting for Round-1 commitments.
    InputRound1(InputRound1State<C>),
    /// Round 4: input sub-protocol, waiting for Round-2 decommitments + proofs.
    InputRound2(InputRound2State<C>),
    /// Round 5: element-out sub-protocol, waiting for revealed points + DDH proofs.
    ElementOut(ElementOutState_<C>),
    /// Protocol complete; key share is available.
    Done(Ln18KeyShare<C>),
    /// Sentinel for `std::mem::take`.
    #[default]
    Gone,
}

// ---------------------------------------------------------------------------
// Round 1 state — Init commitment
// ---------------------------------------------------------------------------

pub(crate) struct InitRound1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,
    /// Secret ECDSA share x_i sampled during construction.
    pub x_i: C::Scalar,
    /// The underlying init sub-protocol state.
    pub init_state: InitState<C>,
    /// Outgoing messages queued at construction or after transition.
    pub outgoing: Vec<Outgoing<Ln18KeygenMsg<C>>>,
    /// Received Round-1 messages from other parties.
    pub received: BTreeMap<PartyId, InitRound1Msg>,
}

impl<C: TecdsaCurve> InitRound1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: &SessionConfig, rng: &mut impl CryptoRngCore) -> Self {
        let my_id = config.local_party.id;
        let parties = config.parties.clone();
        let threshold = config.reconstruct_threshold(); // VSS reconstruction threshold
        let total = config.local_party.total;

        // Sample ECDSA secret share x_i
        let x_i = C::random_scalar(rng);

        // Create init sub-protocol state
        let (init_state, init_r1_msg) = InitState::<C>::new(my_id, parties.clone(), rng);

        // Queue the Round-1 broadcast
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18KeygenMsg::InitRound1(SerInitRound1::from_msg(&init_r1_msg)),
        }];

        Self {
            my_id,
            parties,
            threshold,
            total,
            x_i,
            init_state,
            outgoing,
            received: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SerInitRound1) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.received.insert(from, msg.to_msg());
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.expected_count()
    }

    /// Transition to InitRound2: process commitments and produce decommitment.
    pub fn advance(mut self) -> tecdsa_core::Result<InitRound2State<C>> {
        let msgs: Vec<InitRound1Msg> = self.received.values().cloned().collect();
        let r2_msg = self
            .init_state
            .handle_round1(&msgs)
            .map_err(|e| TecdsaError::Other(format!("init Round-1 processing failed: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18KeygenMsg::InitRound2(SerInitRound2::from_msg(&r2_msg)),
        }];

        Ok(InitRound2State {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            x_i: self.x_i,
            init_state: self.init_state,
            outgoing,
            received: BTreeMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Round 2 state — Init decommitment
// ---------------------------------------------------------------------------

pub(crate) struct InitRound2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,
    pub x_i: C::Scalar,
    pub init_state: InitState<C>,
    pub outgoing: Vec<Outgoing<Ln18KeygenMsg<C>>>,
    pub received: BTreeMap<PartyId, InitRound2Msg<C>>,
}

impl<C: TecdsaCurve> InitRound2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SerInitRound2<C>) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.received.insert(from, msg.to_msg());
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.expected_count()
    }

    /// Finalize init and transition to InputRound1 (commit phase).
    pub fn advance(
        mut self,
        rng: &mut impl CryptoRngCore,
    ) -> tecdsa_core::Result<InputRound1State<C>> {
        let msgs: Vec<InitRound2Msg<C>> = self.received.values().cloned().collect();
        let init_output = self
            .init_state
            .finish_round2(&msgs)
            .map_err(|e| TecdsaError::Other(format!("init Round-2 processing failed: {e}")))?;

        // Start input sub-protocol: each party inputs x_i (Round 1 = commitment)
        let (input_state, input_r1_msg) = InputState::<C>::new(
            self.my_id,
            self.parties.clone(),
            init_output.elgamal_pk,
            self.x_i,
            rng,
        );

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18KeygenMsg::InputRound1(SerInputRound1::from_msg(&input_r1_msg)),
        }];

        // Zeroize ECDSA secret share (now consumed by InputState)
        self.x_i.zeroize();

        Ok(InputRound1State {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            init_output,
            input_state,
            outgoing,
            received: BTreeMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Round 3 state — Input commitment
// ---------------------------------------------------------------------------

pub(crate) struct InputRound1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,
    pub init_output: InitOutput<C>,
    pub input_state: InputState<C>,
    pub outgoing: Vec<Outgoing<Ln18KeygenMsg<C>>>,
    pub received: BTreeMap<PartyId, InputRound1Msg>,
}

impl<C: TecdsaCurve> InputRound1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SerInputRound1) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.received.insert(from, msg.to_msg());
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.expected_count()
    }

    /// Transition to InputRound2: process commitments and produce decommitment.
    pub fn advance(mut self) -> tecdsa_core::Result<InputRound2State<C>> {
        let msgs: Vec<InputRound1Msg> = self.received.values().cloned().collect();
        let r2_msg = self
            .input_state
            .handle_round1(&msgs)
            .map_err(|e| TecdsaError::Other(format!("input Round-1 processing failed: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18KeygenMsg::InputRound2(SerInputRound2::from_msg(&r2_msg)),
        }];

        Ok(InputRound2State {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            init_output: self.init_output,
            input_state: self.input_state,
            outgoing,
            received: BTreeMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Round 4 state — Input decommitment + verify
// ---------------------------------------------------------------------------

pub(crate) struct InputRound2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,
    pub init_output: InitOutput<C>,
    pub input_state: InputState<C>,
    pub outgoing: Vec<Outgoing<Ln18KeygenMsg<C>>>,
    pub received: BTreeMap<PartyId, InputRound2Msg<C>>,
}

impl<C: TecdsaCurve> InputRound2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SerInputRound2<C>) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.received.insert(from, msg.to_msg());
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.expected_count()
    }

    /// Finalize input and transition to ElementOut.
    pub fn advance(self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<ElementOutState_<C>> {
        let msgs: Vec<InputRound2Msg<C>> = self.received.values().cloned().collect();
        let input_output = self
            .input_state
            .finish_round2(&msgs)
            .map_err(|e| TecdsaError::Other(format!("input Round-2 processing failed: {e}")))?;

        // Start element-out sub-protocol
        let (eo_state, eo_msg) = ElementOutState::<C>::new(
            self.my_id,
            self.parties.clone(),
            input_output.a_i,
            input_output.s_i,
            input_output.per_party_cts.clone(),
            self.init_output.elgamal_pk,
            rng,
        );

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18KeygenMsg::ElementOut(SerElementOut::from_msg(&eo_msg)),
        }];

        Ok(ElementOutState_ {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            init_output: self.init_output,
            input_output,
            eo_state,
            outgoing,
            received: BTreeMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Round 5 state — Element-out
// ---------------------------------------------------------------------------

/// Wrapper around the element-out sub-protocol state at the keygen level.
///
/// Named with trailing underscore to avoid collision with the sub-op's
/// `ElementOutState`.
pub(crate) struct ElementOutState_<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,
    pub init_output: InitOutput<C>,
    pub input_output: InputOutput<C>,
    pub eo_state: ElementOutState<C>,
    pub outgoing: Vec<Outgoing<Ln18KeygenMsg<C>>>,
    pub received: BTreeMap<PartyId, ElementOutMsg<C>>,
}

impl<C: TecdsaCurve> ElementOutState_<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SerElementOut<C>) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.received.insert(from, msg.to_msg());
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.expected_count()
    }

    /// Finalize element-out and produce the key share.
    pub fn finish(self) -> tecdsa_core::Result<Ln18KeyShare<C>> {
        let msgs: Vec<ElementOutMsg<C>> = self.received.values().cloned().collect();
        let eo_output = self
            .eo_state
            .finish(&msgs)
            .map_err(|e| TecdsaError::Other(format!("element-out processing failed: {e}")))?;

        // Q = x * G is the joint ECDSA public key
        let public_key = eo_output.element;

        // Find party index (0-based position in the sorted party list)
        let party_index = self
            .parties
            .iter()
            .position(|p| *p == self.my_id)
            .expect("my_id must be in parties") as u16;

        Ok(Ln18KeyShare {
            party_index,
            secret_share: self.input_output.a_i,
            public_key,
            elgamal_dk: self.init_output.d_i,
            elgamal_pk: self.init_output.elgamal_pk,
            elgamal_pk_shares: self.init_output.elgamal_pk_shares,
            n: self.total,
            t: self.threshold,
        })
    }
}
