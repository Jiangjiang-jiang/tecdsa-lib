pub mod msg;
mod rounds;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use msg::KeygenMsg;
use rand_core::CryptoRngCore;
use rounds::{KeygenRound, Round1State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, SessionConfig, StateMachine};

use crate::key_share::Cggmp20CoreKeyShare;

pub struct Cggmp20KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: KeygenRound<C>,
}

impl<C: TecdsaCurve> Cggmp20KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: &SessionConfig, rng: &mut impl CryptoRngCore) -> Self {
        let state = Round1State::<C>::new(config, rng);
        Self {
            round: KeygenRound::Round1(state),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Cggmp20KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar:
        PrimeField<Repr = FieldBytes<C>> + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Output = Cggmp20CoreKeyShare<C>;
    type Inbound = KeygenMsg<C>;
    type Outbound = KeygenMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            KeygenRound::Round1(state) => match msg {
                KeygenMsg::Round1(m) => {
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
                KeygenMsg::Round2Broad(m) => {
                    state.handle_broad(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round2(s) = old {
                            self.round = KeygenRound::Round3(s.advance()?);
                        }
                    }
                    Ok(())
                }
                KeygenMsg::Round2Uni(m) => {
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
                KeygenMsg::Round3(m) => {
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

fn msg_round<C: TecdsaCurve>(msg: &KeygenMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        KeygenMsg::Round1(_) => 1,
        KeygenMsg::Round2Broad(_) | KeygenMsg::Round2Uni(_) => 2,
        KeygenMsg::Round3(_) => 3,
    }
}
