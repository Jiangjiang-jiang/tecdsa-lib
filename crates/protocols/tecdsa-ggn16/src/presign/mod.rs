// SPDX-License-Identifier: MIT OR Apache-2.0
//! GGN16 presigning protocol (Rounds 1-5).
//!
//! Produces a message-independent [`Ggn16Presignature`] that can be consumed
//! by the online signing phase ([`crate::sign::Ggn16OnlineSignMachine`]).

pub mod rounds;
pub mod types;

pub use types::Ggn16Presignature;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};

use crate::key_share::Ggn16KeyShare;
use crate::sign::msg::Ggn16SignMsg;
use rounds::{PresignConfig, PresignRound, Round1State};

/// GGN16 presigning state machine (Rounds 1-5).
///
/// Drives a single party through the 5-round message-independent presigning
/// protocol. Create one instance per party via [`Ggn16PresignMachine::new`],
/// then feed messages through the [`StateMachine`] trait.
pub struct Ggn16PresignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: PresignRound<C>,
    /// RNG seeds for generating secrets during round transitions.
    /// Index 0: Round 1 -> Round 2 (HomoMultProof generation)
    /// Index 1: Round 2 -> Round 3 (k_i, c_i sampling)
    /// Index 2: Round 3 -> Round 4 (NonceConsistProof generation)
    rng_seeds: [[u8; 32]; 3],
}

impl<C: TecdsaCurve> Ggn16PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new GGN16 presign state machine.
    ///
    /// # Arguments
    ///
    /// * `key_share` - This party's key share from keygen.
    /// * `my_id` - This party's identifier.
    /// * `signer_parties` - All signing party identifiers (including self).
    /// * `rng` - Cryptographic RNG.
    pub fn new(
        key_share: Ggn16KeyShare<C>,
        my_id: PartyId,
        signer_parties: Vec<PartyId>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let config = PresignConfig {
            key_share,
            my_id,
            signer_parties,
        };

        let mut rng_seeds = [[0u8; 32]; 3];
        for seed in &mut rng_seeds {
            rng.fill_bytes(seed);
        }

        let state = Round1State::new(config, rng);
        Self {
            round: PresignRound::Round1(state),
            rng_seeds,
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Ggn16PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Ggn16Presignature<C>;
    type Inbound = Ggn16SignMsg;
    type Outbound = Ggn16SignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            PresignRound::Round1(state) => match msg {
                Ggn16SignMsg::Round1(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round1(s) = old {
                            let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(
                                self.rng_seeds[0],
                            );
                            self.round = PresignRound::Round2(s.advance(&mut rng));
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
                Ggn16SignMsg::Round2(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round2(s) = old {
                            let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(
                                self.rng_seeds[1],
                            );
                            self.round = PresignRound::Round3(s.advance(&mut rng)?);
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
                Ggn16SignMsg::Round3(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round3(s) = old {
                            let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(
                                self.rng_seeds[2],
                            );
                            self.round = PresignRound::Round4(s.advance(&mut rng));
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 3,
                    got: msg_round(&msg),
                }),
            },
            PresignRound::Round4(state) => match msg {
                Ggn16SignMsg::Round4(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round4(s) = old {
                            self.round = PresignRound::Round5(s.advance()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 4,
                    got: msg_round(&msg),
                }),
            },
            PresignRound::Round5(state) => match msg {
                Ggn16SignMsg::Round5(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round5(s) = old {
                            self.round = PresignRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 5,
                    got: msg_round(&msg),
                }),
            },
            PresignRound::Done(_) | PresignRound::Poisoned => Err(TecdsaError::Other(
                "presign protocol already finished".into(),
            )),
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRound::Round1(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Round2(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Round3(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Round4(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Round5(state) => std::mem::take(&mut state.outgoing),
            PresignRound::Done(_) | PresignRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, PresignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            PresignRound::Done(presig) => Ok(presig),
            _ => Err(TecdsaError::Other(
                "presign protocol not yet complete".into(),
            )),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            PresignRound::Round1(_) => 1,
            PresignRound::Round2(_) => 2,
            PresignRound::Round3(_) => 3,
            PresignRound::Round4(_) => 4,
            PresignRound::Round5(_) => 5,
            PresignRound::Done(_) => 6,
            PresignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

/// Extract the round number from a message variant (for error reporting).
fn msg_round(msg: &Ggn16SignMsg) -> u16 {
    match msg {
        Ggn16SignMsg::Round1(_) => 1,
        Ggn16SignMsg::Round2(_) => 2,
        Ggn16SignMsg::Round3(_) => 3,
        Ggn16SignMsg::Round4(_) => 4,
        Ggn16SignMsg::Round5(_) => 5,
        Ggn16SignMsg::Round6(_) => 6,
    }
}
