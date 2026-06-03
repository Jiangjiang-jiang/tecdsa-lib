// SPDX-License-Identifier: MIT OR Apache-2.0
//! GG18 online signing protocol (Phase 5, message-dependent).
//!
//! Takes a `Gg18Presignature` from the presign phase plus a message hash,
//! and runs Phase 5 (HomoElGamal verification + signature assembly) in
//! 5 message rounds:
//!
//! 1. **Round 4 (Phase 5a):** Broadcast commitment to (V_i, A_i, B_i).
//! 2. **Round 5 (Phase 5b):** Broadcast decommitment + proofs.
//! 3. **Round 6 (Phase 5c):** Broadcast commitment to (U_i, T_i).
//! 4. **Round 7 (Phase 5d):** Broadcast decommitment (U_i, T_i) — NO s_i.
//! 5. **Round 8 (Phase 5e):** Broadcast s_i only after zero-check passes.

pub mod msg;
mod rounds;
pub mod sign_keys;

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use msg::Gg18SignMsg;
pub use rounds::OnlineSignConfig;
use rounds::{OnlineSignRound, Round4State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Signature, StateMachine};

/// GG18 online signing state machine (Phase 5, 5 message rounds).
pub struct Gg18OnlineSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: OnlineSignRound<C>,
    /// RNG carried through the protocol for rounds that need randomness.
    rng: tecdsa_core::Csprng,
}

impl<C: TecdsaCurve> Gg18OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new GG18 online signing state machine.
    pub fn new(config: OnlineSignConfig<C>, rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let state = Round4State::new(config, rng);
        Self {
            round: OnlineSignRound::Round4(state),
            rng: tecdsa_core::Csprng::new(),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Gg18OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar:
        PrimeField<Repr = FieldBytes<C>> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Output = Signature<C>;
    type Inbound = Gg18SignMsg<C>;
    type Outbound = Gg18SignMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            OnlineSignRound::Round4(state) => match msg {
                Gg18SignMsg::Round4(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineSignRound::Round4(s) = old {
                            self.round = OnlineSignRound::Round5(s.advance());
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 4,
                    got: msg_round(&msg),
                }),
            },
            OnlineSignRound::Round5(state) => match msg {
                Gg18SignMsg::Round5(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineSignRound::Round5(s) = old {
                            self.round = OnlineSignRound::Round6(s.advance(&mut self.rng)?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 5,
                    got: msg_round(&msg),
                }),
            },
            OnlineSignRound::Round6(state) => match msg {
                Gg18SignMsg::Round6(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineSignRound::Round6(s) = old {
                            self.round = OnlineSignRound::Round7(s.advance());
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 6,
                    got: msg_round(&msg),
                }),
            },
            OnlineSignRound::Round7(state) => match msg {
                Gg18SignMsg::Round7(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineSignRound::Round7(s) = old {
                            self.round = OnlineSignRound::Round8(s.advance()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 7,
                    got: msg_round(&msg),
                }),
            },
            OnlineSignRound::Round8(state) => match msg {
                Gg18SignMsg::Round8(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineSignRound::Round8(s) = old {
                            self.round = OnlineSignRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 8,
                    got: msg_round(&msg),
                }),
            },
            OnlineSignRound::Done(_) | OnlineSignRound::Gone => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            OnlineSignRound::Round4(state) => std::mem::take(&mut state.outgoing),
            OnlineSignRound::Round5(state) => std::mem::take(&mut state.outgoing),
            OnlineSignRound::Round6(state) => std::mem::take(&mut state.outgoing),
            OnlineSignRound::Round7(state) => std::mem::take(&mut state.outgoing),
            OnlineSignRound::Round8(state) => std::mem::take(&mut state.outgoing),
            OnlineSignRound::Done(_) | OnlineSignRound::Gone => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, OnlineSignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            OnlineSignRound::Done(sig) => Ok(sig),
            _ => Err(TecdsaError::Other("protocol not yet complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            OnlineSignRound::Round4(_) => 4,
            OnlineSignRound::Round5(_) => 5,
            OnlineSignRound::Round6(_) => 6,
            OnlineSignRound::Round7(_) => 7,
            OnlineSignRound::Round8(_) => 8,
            OnlineSignRound::Done(_) => 9,
            OnlineSignRound::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

/// Extract the round number from a message variant.
fn msg_round<C: TecdsaCurve>(msg: &Gg18SignMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        Gg18SignMsg::Round1Broadcast(_) | Gg18SignMsg::Round1P2p(_) => 1,
        Gg18SignMsg::Round2(_) => 2,
        Gg18SignMsg::Round3(_) => 3,
        Gg18SignMsg::Round4(_) => 4,
        Gg18SignMsg::Round5(_) => 5,
        Gg18SignMsg::Round6(_) => 6,
        Gg18SignMsg::Round7(_) => 7,
        Gg18SignMsg::Round8(_) => 8,
    }
}
