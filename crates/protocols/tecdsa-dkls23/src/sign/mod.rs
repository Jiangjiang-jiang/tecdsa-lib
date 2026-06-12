pub mod msg;
mod rounds;

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use msg::Dkls23SignMsg;
pub use rounds::OnlineSignConfig;
use rounds::{OnlineSignRound, Round4State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Signature, StateMachine};

pub struct Dkls23OnlineSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: OnlineSignRound<C>,
}

impl<C: TecdsaCurve> Dkls23OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[must_use]
    pub fn new(config: OnlineSignConfig<C>) -> Self {
        let state = Round4State::new(config);
        Self {
            round: OnlineSignRound::Round4(state),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Dkls23OnlineSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar:
        PrimeField<Repr = FieldBytes<C>> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Output = Signature<C>;
    type Inbound = Dkls23SignMsg<C>;
    type Outbound = Dkls23SignMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            OnlineSignRound::Round4(state) => match msg {
                Dkls23SignMsg::Round4Broadcast(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let OnlineSignRound::Round4(s) = old {
                            self.round = OnlineSignRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 4,
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
            OnlineSignRound::Done(_) => 5,
            OnlineSignRound::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

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
