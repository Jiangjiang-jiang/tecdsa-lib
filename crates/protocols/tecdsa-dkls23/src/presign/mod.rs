// SPDX-License-Identifier: MIT OR Apache-2.0
//! DKLs23 presigning protocol (3 rounds, message-independent).
//!
//! Produces a [`Dkls23Presignature`] that can be consumed by the online
//! signing phase ([`crate::sign::Dkls23OnlineSignMachine`]).
//!
//! ## Protocol Rounds
//!
//! 1. **Round 1 (Init + Commit):** Each party samples a nonce share r_i,
//!    initializes RVOLE sender state for each counterparty, broadcasts
//!    H(salt || R_i), and P2P sends OteInitSenderMsg + nonce.
//! 2. **Round 2 (RVOLE phase 1 + Decommit):** Each party initializes
//!    MulReceiver using the counterparty's OteInitSenderMsg, runs phase 1,
//!    broadcasts (salt, R_i), and P2P sends OteDataToSender.
//! 3. **Round 3 (RVOLE sender + consistency):** Each party runs MulSender
//!    with [r_i, sk_i] and P2P sends MulDataToReceiver + consistency
//!    elements (Gamma^u, Gamma^v, psi, pk_i). Upon receiving, parties
//!    complete MulReceiver::run_phase2, verify decommitments, verify
//!    public key consistency, and assemble the presignature.
//!
//! Reference: Doerner, Kondi, Lee, shelat. "Threshold ECDSA in Three Rounds."
//! IEEE S&P 2023, Section 3.2, Protocol 3.6.

mod rounds;
pub mod types;

use elliptic_curve::{ops::Reduce, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
pub use rounds::PresignConfig;
use rounds::{PresignRound, Round1State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};
pub use types::{ideal_rvole, Dkls23Presignature, PartyRvoleData, RvoleCorrelation};

use crate::sign::msg::Dkls23SignMsg;

/// DKLs23 presigning state machine (3 rounds).
///
/// Drives a single party through the 3-round message-independent presigning
/// protocol using the real OT-based RVOLE from `tecdsa-ot::rvole`.
/// Create one instance per party via [`Dkls23PresignMachine::new`],
/// then feed messages through the [`StateMachine`] trait.
///
/// The type parameter `R` is the cryptographic RNG used throughout the
/// protocol. Typically `rand::rngs::ThreadRng` or `rand::rngs::OsRng`.
pub struct Dkls23PresignMachine<
    C: TecdsaCurve,
    R: CryptoRngCore + Send + 'static = rand_core::OsRng,
> where
    FieldBytesSize<C>: ModulusSize,
{
    round: PresignRound<C>,
    /// RNG stored for use in round transitions that require randomness.
    rng: R,
}

impl<C: TecdsaCurve, R: CryptoRngCore + Send + 'static> Dkls23PresignMachine<C, R>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>> + Reduce<FieldBytes<C>>,
{
    /// Create a new DKLs23 presign state machine.
    ///
    /// # Arguments
    ///
    /// * `config` - Presign configuration including key share and signing subset.
    /// * `rng` - Cryptographic RNG for nonce, mask, and RVOLE generation.
    pub fn new(config: PresignConfig<C>, mut rng: R) -> Self {
        let state = Round1State::new(config, &mut rng);
        Self {
            round: PresignRound::Round1(state),
            rng,
        }
    }
}

impl<C: TecdsaCurve, R: CryptoRngCore + Send + 'static> StateMachine for Dkls23PresignMachine<C, R>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>
        + Reduce<FieldBytes<C>>
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>,
{
    type Output = Dkls23Presignature<C>;
    type Inbound = Dkls23SignMsg<C>;
    type Outbound = Dkls23SignMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            PresignRound::Round1(state) => match msg {
                Dkls23SignMsg::Round1Broadcast(m) => {
                    state.handle_broadcast(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round1(s) = old {
                            self.round = PresignRound::Round2(s.advance(&mut self.rng)?);
                        }
                    }
                    Ok(())
                }
                Dkls23SignMsg::Round1P2p(m) => {
                    state.handle_p2p(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round1(s) = old {
                            self.round = PresignRound::Round2(s.advance(&mut self.rng)?);
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
                Dkls23SignMsg::Round2Broadcast(m) => {
                    state.handle_broadcast(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round2(s) = old {
                            self.round = PresignRound::Round3(s.advance(&mut self.rng)?);
                        }
                    }
                    Ok(())
                }
                Dkls23SignMsg::Round2P2p(m) => {
                    state.handle_p2p(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round2(s) = old {
                            self.round = PresignRound::Round3(s.advance(&mut self.rng)?);
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
                Dkls23SignMsg::Round3P2p(m) => {
                    state.handle_p2p(from, m)?;
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
            PresignRound::Done(_) | PresignRound::Poisoned => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRound::Round1(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Round2(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Round3(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Done(_) | PresignRound::Poisoned => Vec::new(),
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
            PresignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

/// Extract the round number from a message variant (for error reporting).
fn msg_round<C: TecdsaCurve>(msg: &Dkls23SignMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        Dkls23SignMsg::Round1Broadcast(_) | Dkls23SignMsg::Round1P2p(_) => 1,
        Dkls23SignMsg::Round2Broadcast(_) | Dkls23SignMsg::Round2P2p(_) => 2,
        Dkls23SignMsg::Round3P2p(_) => 3,
        Dkls23SignMsg::Round4Broadcast(_) => 4,
    }
}
