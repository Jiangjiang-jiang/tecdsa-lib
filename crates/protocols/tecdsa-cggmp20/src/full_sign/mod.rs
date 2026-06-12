pub mod msg;

use std::collections::BTreeMap;

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use msg::{FullSignMsg, MsgRound4};
use rand_core::CryptoRngCore;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{
    state_machine::Outgoing, IaReport, PartyId, Recipient, SessionConfig, StateMachine,
};

use crate::{
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    presign::Cggmp20PresignMachine,
    security_level::{Cggmp20SecurityParams, SecurityLevel128},
    sign::types::{DataToSign, PartialSignature, PresignaturePublicData, Signature},
};

pub(crate) struct Round4State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub received: BTreeMap<PartyId, C::Scalar>,
    pub own_partial: PartialSignature<C>,
    pub presig_public: PresignaturePublicData<C>,
    pub public_key: C::ProjectivePoint,
    pub message: DataToSign<C>,
    pub outgoing: Vec<Outgoing<FullSignMsg<C>>>,
    pub expected: usize,
}

#[derive(Default)]
pub(crate) enum FullSignPhase<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Presigning(Cggmp20PresignMachine<C>),
    Signing(Round4State<C>),
    Done(Signature<C>),
    #[default]
    Gone,
}

pub struct FullSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    phase: FullSignPhase<C>,
    my_id: PartyId,
    message: DataToSign<C>,
    public_key: C::ProjectivePoint,
    signers_count: usize,
}

impl<C: TecdsaCurve> FullSignMachine<C>
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
        message: DataToSign<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        Self::with_security::<SecurityLevel128>(config, core_share, aux, signers, message, rng)
    }

    pub fn with_security<L: Cggmp20SecurityParams>(
        config: &SessionConfig,
        core_share: &Cggmp20CoreKeyShare<C>,
        aux: &AuxInfo,
        signers: &[u16],
        message: DataToSign<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let public_key = core_share.public_key;
        let signers_count = signers.len();
        let my_id = config.local_party.id;
        let presign =
            Cggmp20PresignMachine::with_security::<L>(config, core_share, aux, signers, rng);
        Self {
            phase: FullSignPhase::Presigning(presign),
            my_id,
            message,
            public_key,
            signers_count,
        }
    }
}

impl<C: TecdsaCurve> StateMachine for FullSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    C::Scalar:
        PrimeField<Repr = FieldBytes<C>> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    C: crate::bridge::BridgeCurve,
{
    type Output = Signature<C>;
    type Inbound = FullSignMsg<C>;
    type Outbound = FullSignMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.phase {
            FullSignPhase::Presigning(presign) => {
                let pmsg = match msg {
                    FullSignMsg::Presign(m) => m,
                    FullSignMsg::Round4(_) => {
                        return Err(TecdsaError::RoundMismatch {
                            expected: 1,
                            got: 4,
                        });
                    }
                };

                presign.handle(from, pmsg)?;

                if presign.is_done() {
                    let old = std::mem::take(&mut self.phase);
                    let presign_machine = match old {
                        FullSignPhase::Presigning(pm) => pm,
                        _ => unreachable!(),
                    };

                    let (presignature, presig_public) = presign_machine.finish()?;

                    let own_partial = presignature.partial_sign(&self.message);

                    let outgoing = vec![Outgoing {
                        to: Recipient::Broadcast,
                        msg: FullSignMsg::Round4(MsgRound4 {
                            sigma: own_partial.sigma,
                        }),
                    }];

                    let expected = self.signers_count - 1;

                    self.phase = FullSignPhase::Signing(Round4State {
                        my_id: self.my_id,
                        received: BTreeMap::new(),
                        own_partial,
                        presig_public,
                        public_key: self.public_key,
                        message: self.message,
                        outgoing,
                        expected,
                    });
                }
                Ok(())
            }

            FullSignPhase::Signing(state) => {
                let r4msg = match msg {
                    FullSignMsg::Round4(m) => m,
                    FullSignMsg::Presign(_) => {
                        return Err(TecdsaError::RoundMismatch {
                            expected: 4,
                            got: 1,
                        });
                    }
                };

                if state.received.contains_key(&from) {
                    return Err(TecdsaError::DuplicateMessage(from.0));
                }
                state.received.insert(from, r4msg.sigma);

                if state.received.len() == state.expected {
                    let old = std::mem::take(&mut self.phase);
                    let s4 = match old {
                        FullSignPhase::Signing(s) => s,
                        _ => unreachable!(),
                    };

                    let mut all_partials: BTreeMap<PartyId, PartialSignature<C>> = BTreeMap::new();
                    all_partials.insert(s4.my_id, s4.own_partial);
                    for (pid, sigma) in s4.received {
                        all_partials.insert(pid, PartialSignature { sigma });
                    }
                    let partials: Vec<_> = all_partials.into_values().collect();

                    let sig = PartialSignature::combine(
                        &partials,
                        &s4.presig_public,
                        &s4.public_key,
                        &s4.message,
                    )?;

                    self.phase = FullSignPhase::Done(sig);
                }
                Ok(())
            }

            FullSignPhase::Done(_) | FullSignPhase::Gone => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.phase {
            FullSignPhase::Presigning(presign) => presign
                .drain_outgoing()
                .into_iter()
                .map(|o| Outgoing {
                    to: o.to,
                    msg: FullSignMsg::Presign(o.msg),
                })
                .collect(),
            FullSignPhase::Signing(state) => std::mem::take(&mut state.outgoing),
            FullSignPhase::Done(_) | FullSignPhase::Gone => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.phase, FullSignPhase::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.phase {
            FullSignPhase::Done(sig) => Ok(sig),
            _ => Err(TecdsaError::Other("protocol not yet complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.phase {
            FullSignPhase::Presigning(presign) => presign.current_round(),
            FullSignPhase::Signing(_) => 4,
            FullSignPhase::Done(_) => 5,
            FullSignPhase::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
