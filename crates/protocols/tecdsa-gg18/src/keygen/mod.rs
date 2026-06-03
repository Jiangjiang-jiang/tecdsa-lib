// SPDX-License-Identifier: MIT OR Apache-2.0
//! GG18 threshold key generation (DKG) protocol.
//!
//! A 4-round distributed key generation protocol where `n` parties produce a
//! shared ECDSA key via Feldman VSS, Paillier key generation, Ring-Pedersen
//! parameter generation, hash commitments, and Schnorr `DLog` proofs.
//!
//! ## Protocol Rounds
//!
//! 1. **Commitment:** each party broadcasts a hash commitment to its public key
//!    contribution, Paillier encryption key, and Ring-Pedersen parameters.
//! 2. **Decommit + VSS:** each party broadcasts the decommitment and sends
//!    Feldman VSS shares to every other party via P2P.
//! 3. **`DLog` proof:** each party broadcasts a Schnorr proof of knowledge of
//!    its secret share.
//! 4. **Verify:** each party verifies all proofs and outputs `Gg18KeyShare`.

pub mod msg;
mod rounds;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use msg::Gg18KeygenMsg;
use rand_core::CryptoRngCore;
// Re-export precomputed key types for external constructors.
pub use rounds::{generate_n_tilde, PaillierPrecomputed};
use rounds::{KeygenRound, Round1State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, SessionConfig, StateMachine};

use crate::key_share::Gg18KeyShare;

/// GG18 threshold key generation state machine.
pub struct Gg18KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: KeygenRound<C>,
}

impl<C: TecdsaCurve> Gg18KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new GG18 keygen state machine.
    ///
    /// Generates initial secrets (EC secret, Paillier keypair, `N_tilde` params)
    /// and queues Round 1 broadcast messages.
    pub fn new(config: &SessionConfig, rng: &mut impl CryptoRngCore) -> Self {
        let state = Round1State::<C>::new(config, rng);
        Self {
            round: KeygenRound::Round1(state),
        }
    }

    /// Create a new GG18 keygen state machine with pre-generated Paillier keys.
    ///
    /// Useful for testing with smaller primes to avoid expensive key generation.
    pub fn new_with_precomputed(
        config: &SessionConfig,
        precomputed: PaillierPrecomputed,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let state = Round1State::<C>::new_with_precomputed(config, precomputed, rng);
        Self {
            round: KeygenRound::Round1(state),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Gg18KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar:
        PrimeField<Repr = FieldBytes<C>> + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Output = Gg18KeyShare<C>;
    type Inbound = Gg18KeygenMsg<C>;
    type Outbound = Gg18KeygenMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            KeygenRound::Round1(state) => match msg {
                Gg18KeygenMsg::Round1(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round1(s) = old {
                            self.round = KeygenRound::Round2(s.advance());
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 1,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::Round2(state) => match msg {
                Gg18KeygenMsg::Round2Broad(m) => {
                    state.handle_broad(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round2(s) = old {
                            self.round = KeygenRound::Round3(s.advance()?);
                        }
                    }
                    Ok(())
                }
                Gg18KeygenMsg::Round2Uni(m) => {
                    state.handle_uni(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round2(s) = old {
                            self.round = KeygenRound::Round3(s.advance()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 2,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::Round3(state) => match msg {
                Gg18KeygenMsg::Round3(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round3(s) = old {
                            self.round = KeygenRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 3,
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
            KeygenRound::Round1(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Round2(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Round3(state) => std::mem::take(&mut state.outgoing),
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
            KeygenRound::Round1(_) => 1,
            KeygenRound::Round2(_) => 2,
            KeygenRound::Round3(_) => 3,
            KeygenRound::Done(_) => 4,
            KeygenRound::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

/// Extract the round number from a message variant (for error reporting).
fn msg_round<C: TecdsaCurve>(msg: &Gg18KeygenMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        Gg18KeygenMsg::Round1(_) => 1,
        Gg18KeygenMsg::Round2Broad(_) | Gg18KeygenMsg::Round2Uni(_) => 2,
        Gg18KeygenMsg::Round3(_) => 3,
    }
}
