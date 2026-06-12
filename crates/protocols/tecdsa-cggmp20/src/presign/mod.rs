pub mod msg;
mod rounds;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use msg::PresignMsg;
use rand_core::CryptoRngCore;
use rounds::{PresignRound, Round1State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, SessionConfig, StateMachine};

use crate::{
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    security_level::{Cggmp20SecurityParams, SecurityLevel128},
    sign::types::{Presignature, PresignaturePublicData},
};

pub struct Cggmp20PresignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: PresignRound<C>,
}

impl<C: TecdsaCurve> Cggmp20PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C: crate::bridge::BridgeCurve,
{
    pub fn new(
        config: &SessionConfig,
        core_share: &Cggmp20CoreKeyShare<C>,
        aux: &AuxInfo,
        signers: &[u16],
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        Self::with_security::<SecurityLevel128>(config, core_share, aux, signers, rng)
    }

    pub fn with_security<L: Cggmp20SecurityParams>(
        config: &SessionConfig,
        core_share: &Cggmp20CoreKeyShare<C>,
        aux: &AuxInfo,
        signers: &[u16],
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let state = Round1State::<C>::new(
            config,
            core_share,
            aux,
            signers,
            L::ELL,
            L::EPSILON,
            L::ELL_PRIME,
            rng,
        );
        Self {
            round: PresignRound::Round1(state),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Cggmp20PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar:
        PrimeField<Repr = FieldBytes<C>> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    C: crate::bridge::BridgeCurve,
{
    type Output = (Presignature<C>, PresignaturePublicData<C>);
    type Inbound = PresignMsg<C>;
    type Outbound = PresignMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            PresignRound::Round1(state) => match msg {
                PresignMsg::Round1(m) => {
                    state.handle(from, m)?;
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
                PresignMsg::Round2(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let PresignRound::Round2(s) = old {
                            self.round = PresignRound::Round3(s.advance()?);
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
                PresignMsg::Round3(m) => {
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
            PresignRound::Done(output) => Ok(output),
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

fn msg_round<C: TecdsaCurve>(msg: &PresignMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        PresignMsg::Round1(_) => 1,
        PresignMsg::Round2(_) => 2,
        PresignMsg::Round3(_) => 3,
    }
}
