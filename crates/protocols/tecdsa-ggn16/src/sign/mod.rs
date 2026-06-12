pub mod msg;
pub mod rounds;

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use msg::Ggn16SignMsg;
use rounds::{OnlineSignConfig, OnlineSignRound, Round6State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{
    state_machine::Outgoing, DataToSign, IaReport, PartyId, Signature, StateMachine,
};

use crate::presign::Ggn16Presignature;

pub struct Ggn16OnlineSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: OnlineSignRound<C>,
}

impl<C: TecdsaCurve> Ggn16OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    pub fn new(
        presignature: Ggn16Presignature<C>,
        message: DataToSign<C>,
    ) -> tecdsa_core::Result<Self> {
        let config = OnlineSignConfig {
            presignature,
            message,
        };
        let state = Round6State::new(config)?;
        Ok(Self {
            round: OnlineSignRound::Round6(state),
        })
    }
}

impl<C: TecdsaCurve> StateMachine for Ggn16OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Output = Signature<C>;
    type Inbound = Ggn16SignMsg;
    type Outbound = Ggn16SignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            OnlineSignRound::Round6(state) => match msg {
                Ggn16SignMsg::Round6(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineSignRound::Round6(s) = old {
                            self.round = OnlineSignRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 6,
                    got: sign_msg_round(&msg),
                }),
            },
            OnlineSignRound::Done(_) | OnlineSignRound::Poisoned => Err(TecdsaError::Other(
                "online sign protocol already finished".into(),
            )),
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            OnlineSignRound::Round6(state) => std::mem::take(&mut state.outgoing),
            OnlineSignRound::Done(_) | OnlineSignRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, OnlineSignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            OnlineSignRound::Done(sig) => Ok(sig),
            _ => Err(TecdsaError::Other(
                "online sign protocol not yet complete".into(),
            )),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            OnlineSignRound::Round6(_) => 6,
            OnlineSignRound::Done(_) => 7,
            OnlineSignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

fn sign_msg_round(msg: &Ggn16SignMsg) -> u16 {
    match msg {
        Ggn16SignMsg::Round1(_) => 1,
        Ggn16SignMsg::Round2(_) => 2,
        Ggn16SignMsg::Round3(_) => 3,
        Ggn16SignMsg::Round4(_) => 4,
        Ggn16SignMsg::Round5(_) => 5,
        Ggn16SignMsg::Round6(_) => 6,
    }
}
