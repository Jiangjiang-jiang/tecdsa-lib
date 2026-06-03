// SPDX-License-Identifier: MIT OR Apache-2.0
//! LN18 threshold key generation (Protocol 5.1).
//!
//! A 5-round distributed key generation protocol where `n` parties produce a
//! shared ECDSA key using three `F_mult` sub-operations:
//!
//! 1. **init** (2 rounds): each party generates an ElGamal keypair share;
//!    the joint ElGamal public key is computed.
//! 2. **input** (2 rounds): each party inputs its ECDSA secret share `x_i`
//!    via commit-then-prove (F_{com-zk} hybrid model).
//! 3. **element-out** (1 round): parties jointly reveal `Q = x * G`
//!    without revealing the secret key `x = sum(x_i)`.
//!
//! ## Output
//!
//! Each party receives an [`Ln18KeyShare`] containing its secret share `x_i`,
//! the joint ECDSA public key `Q`, and ElGamal key material for use in signing.

pub mod msg;
mod rounds;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use msg::{msg_round, Ln18KeygenMsg};
use rand_core::CryptoRngCore;
use rounds::{InitRound1State, KeygenRound};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, SessionConfig, StateMachine};

use crate::key_share::Ln18KeyShare;

/// LN18 threshold key generation state machine.
pub struct Ln18KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: KeygenRound<C>,
    /// RNG kept across round transitions (needed for input and element-out sub-ops).
    rng: tecdsa_core::Csprng,
}

impl<C: TecdsaCurve> Ln18KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new LN18 keygen state machine.
    ///
    /// Samples the ECDSA secret share `x_i`, generates ElGamal key material,
    /// and queues the first round of broadcast messages.
    pub fn new(config: &SessionConfig, rng: &mut impl CryptoRngCore) -> Self {
        let state = InitRound1State::<C>::new(config, rng);
        Self {
            round: KeygenRound::InitRound1(state),
            rng: tecdsa_core::Csprng::new(),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Ln18KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Ln18KeyShare<C>;
    type Inbound = Ln18KeygenMsg<C>;
    type Outbound = Ln18KeygenMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            KeygenRound::InitRound1(state) => match msg {
                Ln18KeygenMsg::InitRound1(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::InitRound1(s) = old {
                            self.round = KeygenRound::InitRound2(s.advance()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 1,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::InitRound2(state) => match msg {
                Ln18KeygenMsg::InitRound2(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::InitRound2(s) = old {
                            self.round = KeygenRound::InputRound1(s.advance(&mut self.rng)?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 2,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::InputRound1(state) => match msg {
                Ln18KeygenMsg::InputRound1(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::InputRound1(s) = old {
                            self.round = KeygenRound::InputRound2(s.advance()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 3,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::InputRound2(state) => match msg {
                Ln18KeygenMsg::InputRound2(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::InputRound2(s) = old {
                            self.round = KeygenRound::ElementOut(s.advance(&mut self.rng)?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 4,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::ElementOut(state) => match msg {
                Ln18KeygenMsg::ElementOut(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::ElementOut(s) = old {
                            self.round = KeygenRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 5,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::Done(_) | KeygenRound::Gone => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            KeygenRound::InitRound1(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::InitRound2(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::InputRound1(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::InputRound2(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::ElementOut(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Done(_) | KeygenRound::Gone => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, KeygenRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            KeygenRound::Done(share) => Ok(share),
            _ => Err(TecdsaError::Other("protocol not yet complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            KeygenRound::InitRound1(_) => 1,
            KeygenRound::InitRound2(_) => 2,
            KeygenRound::InputRound1(_) => 3,
            KeygenRound::InputRound2(_) => 4,
            KeygenRound::ElementOut(_) => 5,
            KeygenRound::Done(_) => 6,
            KeygenRound::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
