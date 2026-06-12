pub mod msg;
mod rounds;

use msg::AuxInfoMsg;
use rand_core::CryptoRngCore;
use rounds::{AuxInfoRound, Round1State};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, SessionConfig, StateMachine};

use crate::{key_share::AuxInfo, security_level::Cggmp20SecurityParams};

pub struct AuxInfoMachine<L: Cggmp20SecurityParams> {
    round: AuxInfoRound<L>,
}

impl<L: Cggmp20SecurityParams> AuxInfoMachine<L> {
    pub fn new(config: &SessionConfig, rng: &mut impl CryptoRngCore) -> Self {
        let state = Round1State::<L>::new(config, rng);
        Self {
            round: AuxInfoRound::Round1(state),
        }
    }
}

impl<L: Cggmp20SecurityParams> StateMachine for AuxInfoMachine<L> {
    type Output = AuxInfo;
    type Inbound = AuxInfoMsg;
    type Outbound = AuxInfoMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            AuxInfoRound::Round1(state) => match msg {
                AuxInfoMsg::Round1(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let AuxInfoRound::Round1(s) = old {
                            self.round = AuxInfoRound::Round2(s.advance());
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 1,
                    got: msg_round(&msg),
                }),
            },
            AuxInfoRound::Round2(state) => match msg {
                AuxInfoMsg::Round2(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let AuxInfoRound::Round2(s) = old {
                            self.round = AuxInfoRound::Round3(s.advance()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 2,
                    got: msg_round(&msg),
                }),
            },
            AuxInfoRound::Round3(state) => match msg {
                AuxInfoMsg::Round3(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let AuxInfoRound::Round3(s) = old {
                            self.round = AuxInfoRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 3,
                    got: msg_round(&msg),
                }),
            },
            AuxInfoRound::Done(_) | AuxInfoRound::Gone => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            AuxInfoRound::Round1(state) => std::mem::take(&mut state.outgoing),
            AuxInfoRound::Round2(state) => std::mem::take(&mut state.outgoing),
            AuxInfoRound::Round3(state) => std::mem::take(&mut state.outgoing),
            AuxInfoRound::Done(_) | AuxInfoRound::Gone => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, AuxInfoRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            AuxInfoRound::Done(aux) => Ok(aux),
            _ => Err(TecdsaError::Other("protocol not yet complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            AuxInfoRound::Round1(_) => 1,
            AuxInfoRound::Round2(_) => 2,
            AuxInfoRound::Round3(_) => 3,
            AuxInfoRound::Done(_) => 4,
            AuxInfoRound::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

fn msg_round(msg: &AuxInfoMsg) -> u16 {
    match msg {
        AuxInfoMsg::Round1(_) => 1,
        AuxInfoMsg::Round2(_) => 2,
        AuxInfoMsg::Round3(_) => 3,
    }
}
