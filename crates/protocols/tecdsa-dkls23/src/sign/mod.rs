// SPDX-License-Identifier: MIT OR Apache-2.0
//! DKLs23 online signing protocol (Round 4, 1 round).
//!
//! Consumes a `Dkls23Presignature` and a message digest to produce a
//! threshold ECDSA signature in a single round of interaction.
//!
//! Each party computes its partial signature contributions `(u_i, w_i)`:
//!   u_i = r_i * mask_i + sum_j(c^u_{i,j} + d^u_{j,i})
//!   v_i = sk_i * mask_i + sum_j(c^v_{i,j} + d^v_{j,i})
//!   w_i = H(m) * phi_i + r_x * v_i
//! where mask_i = phi_i + sum_j(psi_{j,i}).
//!
//! After collecting all (u_j, w_j), the signature is assembled:
//!   s = sum(w_j) * sum(u_j)^{-1} mod q
//!
//! Reference: Doerner, Kondi, Lee, shelat. "Threshold ECDSA in Three Rounds."
//! IEEE S&P 2023, Section 3.2, Protocol 3.6.

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

/// DKLs23 online signing state machine (1 round).
///
/// Drives a single party through the 1-round online signing protocol.
/// Create one instance per party via [`Dkls23OnlineSignMachine::new`],
/// then feed messages through the [`StateMachine`] trait.
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
    /// Create a new DKLs23 online signing state machine.
    ///
    /// # Arguments
    ///
    /// * `config` - Online signing configuration with presignature and message.
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
