// SPDX-License-Identifier: MIT OR Apache-2.0
//! LN18 real StateMachine implementations for offline sign (2 rounds) and online sign (6 rounds).

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{ecdsa::Signature, state_machine::Outgoing, IaReport, PartyId, StateMachine};

use super::msg::{
    offline_msg_round, online_msg_round, Ln18FullSignMsg, Ln18OfflineSignMsg, Ln18OnlineSignMsg,
    Ln18PresignMsg, Ln18SignMsg,
};
use super::state_rounds::{
    Ln18OfflineSignParams, Ln18OnlineSignParams, OfflineRound, OnlineRound, PendingOnlineStart,
};
use crate::key_share::{Ln18OfflineSignState, Ln18Presignature};

// ===========================================================================
// Ln18OfflineSignMachine -- real 2-round StateMachine
// ===========================================================================

/// Real `StateMachine` for the LN18 offline signing phase (2 rounds).
///
/// Runs parallel `input(k)` and `input(rho)` sub-protocols. Output is
/// `Ln18OfflineSignState<C>` carrying all state needed for the online phase.
pub struct Ln18OfflineSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: OfflineRound<C>,
    #[allow(dead_code)]
    rng: tecdsa_core::Csprng,
}

impl<C: TecdsaCurve> Ln18OfflineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new offline sign machine.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        params: Ln18OfflineSignParams<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let round =
            match super::state_rounds::OfflineInputRound1::new(my_id, all_parties, params, rng) {
                Ok(state) => OfflineRound::InputRound1(state),
                Err(_) => OfflineRound::Gone,
            };
        Self {
            round,
            rng: tecdsa_core::Csprng::new(),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Ln18OfflineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Ln18OfflineSignState<C>;
    type Inbound = Ln18OfflineSignMsg<C>;
    type Outbound = Ln18OfflineSignMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            OfflineRound::InputRound1(state) => match msg {
                Ln18OfflineSignMsg::Round1Input { k, rho } => {
                    state.handle(from, k.to_msg(), rho.to_msg())?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OfflineRound::InputRound1(s) = old {
                            self.round = OfflineRound::InputRound2(s.advance()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 1,
                    got: offline_msg_round(&msg),
                }),
            },
            OfflineRound::InputRound2(state) => match msg {
                Ln18OfflineSignMsg::Round2Input { k, rho } => {
                    state.handle(from, k.to_msg(), rho.to_msg())?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OfflineRound::InputRound2(s) = old {
                            self.round = OfflineRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 2,
                    got: offline_msg_round(&msg),
                }),
            },
            OfflineRound::Done(_) | OfflineRound::Gone => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            OfflineRound::InputRound1(state) => std::mem::take(&mut state.outgoing),
            OfflineRound::InputRound2(state) => std::mem::take(&mut state.outgoing),
            OfflineRound::Done(_) | OfflineRound::Gone => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, OfflineRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            OfflineRound::Done(state) => Ok(state),
            _ => Err(TecdsaError::Other("offline sign not yet complete".into())),
        }
    }

    /// Returns 1 for Round 1, 2 for Round 2, 3 when done.
    fn current_round(&self) -> u16 {
        match &self.round {
            OfflineRound::InputRound1(_) => 1,
            OfflineRound::InputRound2(_) => 2,
            OfflineRound::Done(_) => 3,
            OfflineRound::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

// ===========================================================================
// Ln18OnlineSignMachine -- real 6-round StateMachine
// ===========================================================================

/// Real `StateMachine` for the LN18 online signing phase (6 rounds).
///
/// Receives the message digest at construction. Runs element-out + interleaved
/// mult1(k,rho) and mult2(rho,alpha). Output is an ECDSA `Signature<C>`.
pub struct Ln18OnlineSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: OnlineRound<C>,
    rng: tecdsa_core::Csprng,
}

impl<C: TecdsaCurve> Ln18OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    /// Create a new online sign machine.
    ///
    /// The message digest is provided here (not via a separate `set_message` API).
    /// It is not used until paper round 3 after R and r are known.
    pub fn new(params: Ln18OnlineSignParams<C>, rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let round3 = super::state_rounds::OnlineRound3::new(params, rng);
        Self {
            round: OnlineRound::Round3(round3),
            rng: tecdsa_core::Csprng::new(),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Ln18OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    type Output = Signature<C>;
    type Inbound = Ln18OnlineSignMsg<C>;
    type Outbound = Ln18OnlineSignMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            OnlineRound::Round3(r3) => match msg {
                Ln18OnlineSignMsg::Round3 {
                    element_out,
                    mult1_r1,
                } => {
                    match &mut r3.state {
                        PendingOnlineStart::Active(active) => {
                            active.handle(from, element_out.to_msg(), mult1_r1.to_msg())?;
                            if active.is_ready() {
                                let old = std::mem::take(&mut self.round);
                                if let OnlineRound::Round3(r3) = old {
                                    if let PendingOnlineStart::Active(a) = r3.state {
                                        match a.advance(&mut self.rng)? {
                                            Ok(round4) => {
                                                self.round = OnlineRound::Round4(round4);
                                            }
                                            Err(pending) => {
                                                self.round = OnlineRound::PendingBeta(pending);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        PendingOnlineStart::WaitingForTau {
                            ref mut buffered, ..
                        } => {
                            // MtA tau not yet resolved. Buffer the incoming
                            // Round 3 message; it will be replayed once tau
                            // completes during try_resolve_pending().
                            buffered.push((from, element_out.to_msg(), mult1_r1.to_msg()));
                        }
                        PendingOnlineStart::Taken => {
                            return Err(TecdsaError::Other(
                                "PendingOnlineStart in Taken state".into(),
                            ));
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 1,
                    got: online_msg_round(&msg),
                }),
            },
            OnlineRound::PendingBeta(pending) => {
                // Beta MtA not yet resolved. Buffer Round 4 messages so
                // they can be replayed once beta completes.
                match msg {
                    Ln18OnlineSignMsg::Round4 { mult1_r2, mult2_r1 } => {
                        pending
                            .buffered_r4
                            .push((from, mult1_r2.to_msg(), mult2_r1.to_msg()));
                        Ok(())
                    }
                    _ => Err(TecdsaError::Other(
                        "beta MtA pending; expected Round4 message".into(),
                    )),
                }
            }
            OnlineRound::Round4(state) => match msg {
                Ln18OnlineSignMsg::Round4 { mult1_r2, mult2_r1 } => {
                    state.handle(from, mult1_r2.to_msg(), mult2_r1.to_msg())?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineRound::Round4(s) = old {
                            self.round = OnlineRound::Round5(s.advance(&mut self.rng)?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 2,
                    got: online_msg_round(&msg),
                }),
            },
            OnlineRound::Round5(state) => match msg {
                Ln18OnlineSignMsg::Round5 { mult1_r3, mult2_r2 } => {
                    state.handle(from, mult1_r3.to_msg(), mult2_r2.to_msg())?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineRound::Round5(s) = old {
                            self.round = OnlineRound::Round6(s.advance(&mut self.rng)?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 3,
                    got: online_msg_round(&msg),
                }),
            },
            OnlineRound::Round6(state) => match msg {
                Ln18OnlineSignMsg::Round6 { mult1_r4, mult2_r3 } => {
                    state.handle(from, mult1_r4.to_msg(), mult2_r3.to_msg())?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineRound::Round6(s) = old {
                            self.round = OnlineRound::Round7(s.advance(&mut self.rng)?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 4,
                    got: online_msg_round(&msg),
                }),
            },
            OnlineRound::Round7(state) => match msg {
                Ln18OnlineSignMsg::Round7 { mult1_r5, mult2_r4 } => {
                    state.handle(from, mult1_r5.to_msg(), mult2_r4.to_msg())?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineRound::Round7(s) = old {
                            self.round = OnlineRound::Round8(s.advance(&mut self.rng)?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 5,
                    got: online_msg_round(&msg),
                }),
            },
            OnlineRound::Round8(state) => match msg {
                Ln18OnlineSignMsg::Round8 { mult2_r5 } => {
                    state.handle(from, mult2_r5.to_msg())?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineRound::Round8(s) = old {
                            self.round = OnlineRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 6,
                    got: online_msg_round(&msg),
                }),
            },
            OnlineRound::Done(_) | OnlineRound::Gone => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        // Try to resolve PendingBeta -> Round4 before draining.
        if matches!(self.round, OnlineRound::PendingBeta(_)) {
            let old = std::mem::take(&mut self.round);
            if let OnlineRound::PendingBeta(pending) = old {
                match pending.try_resolve(&mut self.rng) {
                    Ok(Ok(round4)) => {
                        self.round = OnlineRound::Round4(round4);
                    }
                    Ok(Err(still_pending)) => {
                        self.round = OnlineRound::PendingBeta(still_pending);
                    }
                    Err(_) => {
                        self.round = OnlineRound::Gone;
                    }
                }
            }
        }

        // If Round4 is ready (from buffered Round4 messages replayed
        // during PendingBeta resolution) and its outgoing has already
        // been drained, advance to Round5. This handles the case where
        // all Round4 messages arrived while in PendingBeta.
        if let OnlineRound::Round4(ref state) = self.round {
            if state.is_ready() && state.outgoing.is_empty() {
                let old = std::mem::take(&mut self.round);
                if let OnlineRound::Round4(s) = old {
                    match s.advance(&mut self.rng) {
                        Ok(round5) => self.round = OnlineRound::Round5(round5),
                        Err(_) => self.round = OnlineRound::Gone,
                    }
                }
            }
        }

        // For Round3: try to resolve WaitingForTau -> Active so that
        // Round3 outgoing messages are emitted. If all buffered messages
        // made Active ready, advance to Round4/PendingBeta but only
        // return the Round3 outgoing this iteration; the Round4 outgoing
        // will be returned on the next drain_outgoing call.
        if matches!(self.round, OnlineRound::Round3(_)) {
            if let OnlineRound::Round3(r3) = &mut self.round {
                r3.try_resolve_pending(&mut self.rng);
            }
            // After resolve, check if Active is ready due to replayed
            // buffered messages. If so, advance but defer emitting the
            // new round's outgoing.
            let should_advance = matches!(
                self.round,
                OnlineRound::Round3(ref r3)
                    if matches!(r3.state, PendingOnlineStart::Active(ref a) if a.is_ready())
            );
            if should_advance {
                let old = std::mem::take(&mut self.round);
                if let OnlineRound::Round3(r3) = old {
                    let round3_outgoing = r3.outgoing;
                    if let PendingOnlineStart::Active(a) = r3.state {
                        match a.advance(&mut self.rng) {
                            Ok(Ok(round4)) => {
                                self.round = OnlineRound::Round4(round4);
                            }
                            Ok(Err(pending)) => {
                                self.round = OnlineRound::PendingBeta(pending);
                            }
                            Err(_) => {
                                self.round = OnlineRound::Gone;
                            }
                        }
                    }
                    // Return only the Round3 outgoing; the new round's
                    // outgoing will be returned on the next drain call.
                    return round3_outgoing;
                }
            }
        }

        match &mut self.round {
            OnlineRound::Round3(r3) => std::mem::take(&mut r3.outgoing),
            OnlineRound::PendingBeta(pending) => std::mem::take(&mut pending.outgoing),
            OnlineRound::Round4(state) => std::mem::take(&mut state.outgoing),
            OnlineRound::Round5(state) => std::mem::take(&mut state.outgoing),
            OnlineRound::Round6(state) => std::mem::take(&mut state.outgoing),
            OnlineRound::Round7(state) => std::mem::take(&mut state.outgoing),
            OnlineRound::Round8(state) => std::mem::take(&mut state.outgoing),
            OnlineRound::Done(_) | OnlineRound::Gone => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, OnlineRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            OnlineRound::Done(sig) => Ok(sig),
            _ => Err(TecdsaError::Other("online sign not yet complete".into())),
        }
    }

    /// Returns local phase index: 1-6 for rounds, 7 when done.
    fn current_round(&self) -> u16 {
        match &self.round {
            OnlineRound::Round3(_) => 1,
            OnlineRound::PendingBeta(_) => 1,
            OnlineRound::Round4(_) => 2,
            OnlineRound::Round5(_) => 3,
            OnlineRound::Round6(_) => 4,
            OnlineRound::Round7(_) => 5,
            OnlineRound::Round8(_) => 6,
            OnlineRound::Done(_) => 7,
            OnlineRound::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

// ===========================================================================
// Legacy result-wrapper machines (kept for backward compatibility)
// ===========================================================================

/// Legacy `StateMachine` wrapper for the LN18 presign protocol.
///
/// This wraps a pre-computed presignature. Use `Ln18OfflineSignMachine` for the
/// real message-driven StateMachine path.
pub struct Ln18PresignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    result: Option<Ln18Presignature<C>>,
}

impl<C: TecdsaCurve> Ln18PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[must_use]
    pub fn from_result(presig: Ln18Presignature<C>) -> Self {
        Self {
            result: Some(presig),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Ln18PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Ln18Presignature<C>;
    type Inbound = Ln18PresignMsg;
    type Outbound = Ln18PresignMsg;

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(TecdsaError::Other(
            "Ln18PresignMachine: use Ln18OfflineSignMachine for real signing".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.result.is_some()
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.result
            .ok_or_else(|| TecdsaError::Other("presign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.result.is_some() {
            9
        } else {
            0
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

/// Legacy `StateMachine` wrapper for the combined LN18 sign protocol.
pub struct Ln18SignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    result: Option<Signature<C>>,
}

impl<C: TecdsaCurve> Ln18SignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[must_use]
    pub fn from_result(sig: Signature<C>) -> Self {
        Self { result: Some(sig) }
    }
}

impl<C: TecdsaCurve> StateMachine for Ln18SignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Signature<C>;
    type Inbound = Ln18SignMsg;
    type Outbound = Ln18SignMsg;

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(TecdsaError::Other(
            "Ln18SignMachine: use Ln18OnlineSignMachine for real signing".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.result.is_some()
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.result
            .ok_or_else(|| TecdsaError::Other("sign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.result.is_some() {
            15
        } else {
            0
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

/// Legacy `StateMachine` wrapper for the LN18 8-round full-sign protocol.
pub struct Ln18FullSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    result: Option<Signature<C>>,
}

impl<C: TecdsaCurve> Ln18FullSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[must_use]
    pub fn from_result(sig: Signature<C>) -> Self {
        Self { result: Some(sig) }
    }
}

impl<C: TecdsaCurve> StateMachine for Ln18FullSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Signature<C>;
    type Inbound = Ln18FullSignMsg;
    type Outbound = Ln18FullSignMsg;

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(TecdsaError::Other(
            "Ln18FullSignMachine: use Ln18OnlineSignMachine for real signing".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.result.is_some()
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.result
            .ok_or_else(|| TecdsaError::Other("full sign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.result.is_some() {
            9
        } else {
            0
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
