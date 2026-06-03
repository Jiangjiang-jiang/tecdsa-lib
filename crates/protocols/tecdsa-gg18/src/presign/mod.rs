// SPDX-License-Identifier: MIT OR Apache-2.0
//! GG18 presigning protocol (Phases 1-4, message-independent).
//!
//! Produces a [`Gg18Presignature`] that can later be combined with a message
//! hash in the online signing phase (Phase 5).
//!
//! The presign runs 3 message rounds:
//!
//! 1. **Round 1 (Phase 1+2a merged):** Broadcast Com(g_γ_i) + P2P c_A with AliceProof.
//! 2. **Round 2 (Phase 2b):** P2P c_B with BobProofExt.
//! 3. **Round 3 (Phase 3+4 merged):** Broadcast δ_i + decommit g_γ_i + Schnorr proof for γ_i.
//!
//! After Round 3, each party has R, r, k_i, and sigma_i — everything needed
//! for online signing without knowing the message.
//!
//! # MtA backend
//!
//! This module uses Paillier MtA directly (inline `tecdsa_paillier` homomorphic
//! operations with `AliceProof`/`BobProofExt` ZK proofs) rather than the
//! `tecdsa_protocol::MtA` trait. See `rounds` module documentation for the
//! detailed rationale.

mod rounds;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
pub use rounds::PresignConfig;
use rounds::{PresignRound, Round1State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};
pub use types::Gg18Presignature;

use crate::sign::msg::Gg18SignMsg;

pub mod types;

/// GG18 presigning state machine (Phases 1-4, 3 message rounds).
pub struct Gg18PresignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: PresignRound<C>,
    /// RNG carried through the protocol for rounds that need randomness.
    rng: tecdsa_core::Csprng,
}

impl<C: TecdsaCurve> Gg18PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new GG18 presigning state machine.
    pub fn new(config: PresignConfig<C>, rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let state = Round1State::new(config, rng);
        Self {
            round: PresignRound::Round1(state),
            rng: tecdsa_core::Csprng::new(),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Gg18PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar:
        PrimeField<Repr = FieldBytes<C>> + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Output = Gg18Presignature<C>;
    type Inbound = Gg18SignMsg<C>;
    type Outbound = Gg18SignMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            PresignRound::Round1(state) => match msg {
                Gg18SignMsg::Round1Broadcast(m) => {
                    state.handle_broadcast(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round1(s) = old {
                            self.round = PresignRound::Round2(s.advance());
                        }
                    }
                    Ok(())
                }
                Gg18SignMsg::Round1P2p(m) => {
                    state.handle_p2p(from, m, &mut self.rng)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round1(s) = old {
                            self.round = PresignRound::Round2(s.advance());
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 1,
                    got: msg_round(&msg),
                }),
            },
            PresignRound::Round2(state) => match msg {
                Gg18SignMsg::Round2(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round2(s) = old {
                            self.round = PresignRound::Round3(s.advance());
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 2,
                    got: msg_round(&msg),
                }),
            },
            PresignRound::Round3(state) => match msg {
                Gg18SignMsg::Round3(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round3(s) = old {
                            self.round = PresignRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 3,
                    got: msg_round(&msg),
                }),
            },
            PresignRound::Done(_) | PresignRound::Gone => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRound::Round1(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Round2(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Round3(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Done(_) | PresignRound::Gone => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, PresignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            PresignRound::Done(presig) => Ok(presig),
            _ => Err(TecdsaError::Other("protocol not yet complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            PresignRound::Round1(_) => 1,
            PresignRound::Round2(_) => 2,
            PresignRound::Round3(_) => 3,
            PresignRound::Done(_) => 4,
            PresignRound::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

/// Extract the round number from a message variant (for error reporting).
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
