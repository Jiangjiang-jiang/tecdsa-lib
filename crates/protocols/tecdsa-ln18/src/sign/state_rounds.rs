#![allow(non_snake_case)]

use std::{collections::BTreeMap, sync::Arc};

use elliptic_curve::{
    group::{Curve as CurveGroup, GroupEncoding},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{
    ecdsa::{low_s_normalize, Signature},
    Outgoing, PartyId, Recipient,
};

use super::{
    msg::{
        Ln18OfflineSignMsg, Ln18OnlineSignMsg, SerElementOut, SerInputRound1, SerInputRound2,
        SerMultRound1, SerMultRound2, SerMultRound3, SerMultRound4, SerMultRound5,
    },
    mta_hybrid::{Ln18MtaHybrid, Ln18MtaLocalParams, Ln18MtaOp},
};
use crate::{
    f_mult::{
        affine::{affine, AffineInput},
        element_out::{ElementOutMsg, ElementOutState},
        input::{InputOutput, InputRound1Msg, InputRound2Msg, InputState},
        mult::{
            MultOutput, MultRound1Msg, MultRound1Result, MultRound2Result, MultRound3Result,
            MultRound4Result, MultState,
        },
    },
    key_share::Ln18OfflineSignState,
    sign::rounds::Ln18PresignParams,
};

pub struct Ln18OfflineSignParams<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub base: Ln18PresignParams<C>,
    pub signer_parties: Vec<PartyId>,
    pub mta: Arc<Ln18MtaHybrid<C>>,
}

#[derive(Default)]
pub(crate) enum OfflineRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    InputRound1(OfflineInputRound1<C>),
    InputRound2(OfflineInputRound2<C>),
    Done(Ln18OfflineSignState<C>),
    #[default]
    Gone,
}

pub(crate) struct OfflineInputRound1<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub signer_parties: Vec<PartyId>,
    pub mta: Arc<Ln18MtaHybrid<C>>,
    pub base: Ln18PresignParams<C>,
    pub weighted_x_input: InputOutput<C>,
    pub input_k_state: InputState<C>,
    pub input_rho_state: InputState<C>,
    pub outgoing: Vec<Outgoing<Ln18OfflineSignMsg<C>>>,
    pub received: BTreeMap<PartyId, (InputRound1Msg, InputRound1Msg)>,
}

impl<C: TecdsaCurve> OfflineInputRound1<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        params: Ln18OfflineSignParams<C>,
        rng: &mut impl CryptoRngCore,
    ) -> tecdsa_core::Result<Self> {
        let signer_parties = params.signer_parties.clone();

        if !signer_parties.contains(&my_id) {
            return Err(TecdsaError::Other("my_id not in signer_parties".into()));
        }

        let stored_x = &params.base.stored_x_input;
        let weighted_x_input = InputOutput {
            ciphertext: stored_x.ciphertext.clone(),
            a_i: stored_x.a_i,
            s_i: stored_x.s_i,
            per_party_cts: stored_x.per_party_cts.clone(),
        };

        let k_i = C::random_scalar(rng);
        let rho_i = C::random_scalar(rng);

        let elgamal_pk = params.base.init_output.elgamal_pk;

        let (input_k_state, input_k_r1) =
            InputState::<C>::new(my_id, signer_parties.clone(), elgamal_pk, k_i, rng);
        let (input_rho_state, input_rho_r1) =
            InputState::<C>::new(my_id, signer_parties.clone(), elgamal_pk, rho_i, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18OfflineSignMsg::Round1Input {
                k: SerInputRound1::from_msg(&input_k_r1),
                rho: SerInputRound1::from_msg(&input_rho_r1),
            },
        }];

        Ok(Self {
            my_id,
            all_parties,
            signer_parties,
            mta: params.mta,
            base: params.base,
            weighted_x_input,
            input_k_state,
            input_rho_state,
            outgoing,
            received: BTreeMap::new(),
        })
    }

    pub fn handle(
        &mut self,
        from: PartyId,
        k_r1: InputRound1Msg,
        rho_r1: InputRound1Msg,
    ) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signer_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown sender {from}")));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate Round-1 from {from}")));
        }
        self.received.insert(from, (k_r1, rho_r1));
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.signer_parties.len() - 1
    }

    pub fn advance(mut self) -> tecdsa_core::Result<OfflineInputRound2<C>> {
        let peer_k_r1: Vec<InputRound1Msg> =
            self.received.values().map(|(k, _)| k.clone()).collect();
        let peer_rho_r1: Vec<InputRound1Msg> =
            self.received.values().map(|(_, r)| r.clone()).collect();

        let input_k_r2 = self
            .input_k_state
            .handle_round1(&peer_k_r1)
            .map_err(|e| TecdsaError::Other(format!("input(k) R1: {e}")))?;
        let input_rho_r2 = self
            .input_rho_state
            .handle_round1(&peer_rho_r1)
            .map_err(|e| TecdsaError::Other(format!("input(rho) R1: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18OfflineSignMsg::Round2Input {
                k: SerInputRound2::from_msg(&input_k_r2),
                rho: SerInputRound2::from_msg(&input_rho_r2),
            },
        }];

        Ok(OfflineInputRound2 {
            my_id: self.my_id,
            all_parties: self.all_parties,
            signer_parties: self.signer_parties,
            mta: self.mta,
            base: self.base,
            weighted_x_input: self.weighted_x_input,
            input_k_state: self.input_k_state,
            input_rho_state: self.input_rho_state,
            outgoing,
            received: BTreeMap::new(),
        })
    }
}

pub(crate) struct OfflineInputRound2<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub signer_parties: Vec<PartyId>,
    pub mta: Arc<Ln18MtaHybrid<C>>,
    pub base: Ln18PresignParams<C>,
    pub weighted_x_input: InputOutput<C>,
    pub input_k_state: InputState<C>,
    pub input_rho_state: InputState<C>,
    pub outgoing: Vec<Outgoing<Ln18OfflineSignMsg<C>>>,
    pub received: BTreeMap<PartyId, (InputRound2Msg<C>, InputRound2Msg<C>)>,
}

impl<C: TecdsaCurve> OfflineInputRound2<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn handle(
        &mut self,
        from: PartyId,
        k_r2: InputRound2Msg<C>,
        rho_r2: InputRound2Msg<C>,
    ) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signer_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown sender {from}")));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate Round-2 from {from}")));
        }
        self.received.insert(from, (k_r2, rho_r2));
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.signer_parties.len() - 1
    }

    pub fn finish(self) -> tecdsa_core::Result<Ln18OfflineSignState<C>> {
        let peer_k_r2: Vec<InputRound2Msg<C>> =
            self.received.values().map(|(k, _)| k.clone()).collect();
        let peer_rho_r2: Vec<InputRound2Msg<C>> =
            self.received.values().map(|(_, r)| r.clone()).collect();

        let input_k = self
            .input_k_state
            .finish_round2(&peer_k_r2)
            .map_err(|e| TecdsaError::Other(format!("input(k) R2: {e}")))?;
        let input_rho = self
            .input_rho_state
            .finish_round2(&peer_rho_r2)
            .map_err(|e| TecdsaError::Other(format!("input(rho) R2: {e}")))?;

        Ok(Ln18OfflineSignState {
            my_id: self.my_id,
            all_parties: self.all_parties,
            input_k,
            input_rho,
            paillier_dk: self.base.paillier_dk,
            paillier_eks: self.base.paillier_eks,
            ntilde_params: self.base.ntilde_params,
            stored_x_input: self.base.stored_x_input,
            signer_parties: self.signer_parties,
            weighted_x_input: self.weighted_x_input,
            elgamal_dk: self.base.init_output.d_i,
            elgamal_pk: self.base.init_output.elgamal_pk,
            elgamal_pk_shares: self.base.init_output.elgamal_pk_shares,
            mta: self.mta,
        })
    }
}

pub struct Ln18OnlineSignParams<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub offline_state: Ln18OfflineSignState<C>,
    pub message_digest: C::Scalar,
}

#[derive(Default)]
pub(crate) enum OnlineRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round3(OnlineRound3<C>),
    PendingBeta(PendingBetaState<C>),
    Round4(OnlineRound4<C>),
    Round5(OnlineRound5<C>),
    Round6(OnlineRound6<C>),
    Round7(OnlineRound7<C>),
    Round8(OnlineRound8<C>),
    Done(Signature<C>),
    #[default]
    Gone,
}

#[derive(Default)]
pub(crate) enum PendingOnlineStart<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    WaitingForTau {
        offline: Ln18OfflineSignState<C>,
        message_digest: C::Scalar,
        buffered: Vec<(PartyId, ElementOutMsg<C>, MultRound1Msg<C>)>,
    },
    Active(OnlineRound3Active<C>),
    #[default]
    Taken,
}

pub(crate) struct PendingBetaState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub r: C::Scalar,
    pub offline: Ln18OfflineSignState<C>,
    pub alpha_as_input: InputOutput<C>,
    pub mult1_state: MultState<C>,
    pub own_mult1_r1: MultRound1Msg<C>,
    pub received: BTreeMap<PartyId, (ElementOutMsg<C>, MultRound1Msg<C>)>,
    pub outgoing: Vec<Outgoing<Ln18OnlineSignMsg<C>>>,
    pub buffered_r4: Vec<(
        PartyId,
        crate::f_mult::mult::MultRound2Msg<C>,
        MultRound1Msg<C>,
    )>,
}

impl<C: TecdsaCurve> PendingBetaState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    pub fn try_resolve(
        mut self,
        rng: &mut impl CryptoRngCore,
    ) -> tecdsa_core::Result<Result<OnlineRound4<C>, Self>> {
        let rho_i = self.offline.input_rho.a_i;
        let alpha_i = self.alpha_as_input.a_i;

        let mta_params = Ln18MtaLocalParams::<C> {
            paillier_dk: self.offline.paillier_dk.clone(),
            paillier_eks: self.offline.paillier_eks.clone(),
            ntilde_params: self.offline.ntilde_params.clone(),
            _marker: core::marker::PhantomData,
        };

        let beta_result = self.offline.mta.submit_and_try_get(
            Ln18MtaOp::Beta,
            self.my_id,
            mta_params,
            rho_i,
            alpha_i,
            rng,
        )?;

        let beta_i = match beta_result {
            Some(b) => b,
            None => return Ok(Err(self)),
        };

        let peer_mult1_r1: Vec<MultRound1Msg<C>> =
            self.received.values().map(|(_, m)| m.clone()).collect();
        let (mult1_r2, mult1_r1_result) = self
            .mult1_state
            .handle_round1(&peer_mult1_r1, &self.own_mult1_r1, rng)
            .map_err(|e| TecdsaError::Other(format!("mult1 R1: {e}")))?;

        let (mult2_state, mult2_r1) = MultState::<C>::new(
            self.my_id,
            self.signer_parties.clone(),
            &self.offline.input_rho,
            &self.alpha_as_input,
            beta_i,
            self.offline.elgamal_pk,
            self.offline.elgamal_dk,
            self.offline.elgamal_pk_shares.clone(),
            rng,
        );

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18OnlineSignMsg::Round4 {
                mult1_r2: SerMultRound2::from_msg(&mult1_r2),
                mult2_r1: SerMultRound1::from_msg(&mult2_r1),
            },
        }];

        let mut round4 = OnlineRound4 {
            my_id: self.my_id,
            signer_parties: self.signer_parties,
            r: self.r,
            mult1_state: self.mult1_state,
            mult1_r1_result,
            mult2_state,
            own_mult2_r1: mult2_r1,
            outgoing,
            received: BTreeMap::new(),
        };

        for (from, mult1_r2, mult2_r1) in self.buffered_r4 {
            let _ = round4.handle(from, mult1_r2, mult2_r1);
        }

        Ok(Ok(round4))
    }
}

pub(crate) struct OnlineRound3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub state: PendingOnlineStart<C>,
    pub outgoing: Vec<Outgoing<Ln18OnlineSignMsg<C>>>,
}

pub(crate) struct OnlineRound3Active<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub message_digest: C::Scalar,
    pub offline: Ln18OfflineSignState<C>,
    pub eo_state: ElementOutState<C>,
    #[allow(dead_code)]
    pub own_eo_msg: ElementOutMsg<C>,
    pub mult1_state: MultState<C>,
    pub own_mult1_r1: MultRound1Msg<C>,
    pub received: BTreeMap<PartyId, (ElementOutMsg<C>, MultRound1Msg<C>)>,
}

impl<C: TecdsaCurve> OnlineRound3<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    pub fn new(params: Ln18OnlineSignParams<C>, rng: &mut impl CryptoRngCore) -> Self {
        let offline = params.offline_state;
        let message_digest = params.message_digest;

        let k_i = offline.input_k.a_i;
        let rho_i = offline.input_rho.a_i;

        let mta_params = Ln18MtaLocalParams::<C> {
            paillier_dk: offline.paillier_dk.clone(),
            paillier_eks: offline.paillier_eks.clone(),
            ntilde_params: offline.ntilde_params.clone(),
            _marker: core::marker::PhantomData,
        };

        let tau_result = offline.mta.submit_and_try_get(
            Ln18MtaOp::Tau,
            offline.my_id,
            mta_params,
            k_i,
            rho_i,
            rng,
        );

        match tau_result {
            Ok(Some(tau_i)) => {
                let (active, outgoing) = Self::create_active(offline, message_digest, tau_i, rng);
                Self {
                    state: PendingOnlineStart::Active(active),
                    outgoing,
                }
            }
            _ => {
                Self {
                    state: PendingOnlineStart::WaitingForTau {
                        offline,
                        message_digest,
                        buffered: Vec::new(),
                    },
                    outgoing: Vec::new(),
                }
            }
        }
    }

    pub fn try_resolve_pending(&mut self, rng: &mut impl CryptoRngCore) {
        let should_resolve =
            if let PendingOnlineStart::WaitingForTau { ref offline, .. } = self.state {
                let k_i = offline.input_k.a_i;
                let rho_i = offline.input_rho.a_i;

                let mta_params = Ln18MtaLocalParams::<C> {
                    paillier_dk: offline.paillier_dk.clone(),
                    paillier_eks: offline.paillier_eks.clone(),
                    ntilde_params: offline.ntilde_params.clone(),
                    _marker: core::marker::PhantomData,
                };

                let tau_result = offline.mta.submit_and_try_get(
                    Ln18MtaOp::Tau,
                    offline.my_id,
                    mta_params,
                    k_i,
                    rho_i,
                    rng,
                );

                match tau_result {
                    Ok(Some(tau_i)) => Some(tau_i),
                    _ => None,
                }
            } else {
                None
            };

        if let Some(tau_i) = should_resolve {
            let old = std::mem::take(&mut self.state);
            if let PendingOnlineStart::WaitingForTau {
                offline,
                message_digest,
                buffered,
            } = old
            {
                let (mut active, outgoing) =
                    Self::create_active(offline, message_digest, tau_i, rng);
                for (from, eo_msg, mult1_r1) in buffered {
                    let _ = active.handle(from, eo_msg, mult1_r1);
                }
                self.state = PendingOnlineStart::Active(active);
                self.outgoing = outgoing;
            }
        }
    }

    fn create_active(
        offline: Ln18OfflineSignState<C>,
        message_digest: C::Scalar,
        tau_i: C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> (OnlineRound3Active<C>, Vec<Outgoing<Ln18OnlineSignMsg<C>>>) {
        let my_id = offline.my_id;
        let signer_parties = offline.signer_parties.clone();

        let (eo_state, eo_msg) = ElementOutState::<C>::new(
            my_id,
            signer_parties.clone(),
            offline.input_k.a_i,
            offline.input_k.s_i,
            offline.input_k.per_party_cts.clone(),
            offline.elgamal_pk,
            rng,
        );

        let (mult1_state, mult1_r1) = MultState::<C>::new(
            my_id,
            signer_parties.clone(),
            &offline.input_k,
            &offline.input_rho,
            tau_i,
            offline.elgamal_pk,
            offline.elgamal_dk,
            offline.elgamal_pk_shares.clone(),
            rng,
        );

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18OnlineSignMsg::Round3 {
                element_out: SerElementOut::from_msg(&eo_msg),
                mult1_r1: SerMultRound1::from_msg(&mult1_r1),
            },
        }];

        let active = OnlineRound3Active {
            my_id,
            signer_parties,
            message_digest,
            offline,
            eo_state,
            own_eo_msg: eo_msg,
            mult1_state,
            own_mult1_r1: mult1_r1,
            received: BTreeMap::new(),
        };

        (active, outgoing)
    }
}

impl<C: TecdsaCurve> OnlineRound3Active<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    pub fn handle(
        &mut self,
        from: PartyId,
        eo_msg: ElementOutMsg<C>,
        mult1_r1: MultRound1Msg<C>,
    ) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signer_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown sender {from}")));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate Round-3 from {from}")));
        }
        self.received.insert(from, (eo_msg, mult1_r1));
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.signer_parties.len() - 1
    }

    pub fn advance(
        mut self,
        rng: &mut impl CryptoRngCore,
    ) -> tecdsa_core::Result<Result<OnlineRound4<C>, PendingBetaState<C>>> {
        let peer_eo_msgs: Vec<ElementOutMsg<C>> =
            self.received.values().map(|(e, _)| e.clone()).collect();
        let eo_output = self
            .eo_state
            .finish(&peer_eo_msgs)
            .map_err(|e| TecdsaError::Other(format!("element-out: {e}")))?;
        let R = eo_output.element;
        let r: C::Scalar = C::xcoord_mod_q(&R.to_affine());
        if r.is_zero().into() {
            return Err(TecdsaError::Other(
                "r is zero -- probability < 2^{-256}".into(),
            ));
        }

        let stored_wx = &self.offline.weighted_x_input;
        let aff_input = AffineInput::<C> {
            ciphertext: stored_wx.ciphertext.clone(),
            a_i: stored_wx.a_i,
            s_i: stored_wx.s_i,
            per_party_cts: stored_wx.per_party_cts.clone(),
        };
        let m_prime = self.message_digest;
        let alpha_out = affine::<C>(aff_input, &r, &m_prime, self.signer_parties.len() as u16);
        let alpha_as_input = InputOutput {
            ciphertext: alpha_out.ciphertext,
            a_i: alpha_out.a_i,
            s_i: alpha_out.s_i,
            per_party_cts: alpha_out.per_party_cts,
        };

        let rho_i = self.offline.input_rho.a_i;
        let alpha_i = alpha_as_input.a_i;
        let mta_params = Ln18MtaLocalParams::<C> {
            paillier_dk: self.offline.paillier_dk.clone(),
            paillier_eks: self.offline.paillier_eks.clone(),
            ntilde_params: self.offline.ntilde_params.clone(),
            _marker: core::marker::PhantomData,
        };
        let beta_result = self.offline.mta.submit_and_try_get(
            Ln18MtaOp::Beta,
            self.my_id,
            mta_params,
            rho_i,
            alpha_i,
            rng,
        )?;

        let beta_i = match beta_result {
            Some(b) => b,
            None => {
                return Ok(Err(PendingBetaState {
                    my_id: self.my_id,
                    signer_parties: self.signer_parties,
                    r,
                    offline: self.offline,
                    alpha_as_input,
                    mult1_state: self.mult1_state,
                    own_mult1_r1: self.own_mult1_r1,
                    received: self.received,
                    outgoing: Vec::new(),
                    buffered_r4: Vec::new(),
                }));
            }
        };

        let peer_mult1_r1: Vec<MultRound1Msg<C>> =
            self.received.values().map(|(_, m)| m.clone()).collect();
        let (mult1_r2, mult1_r1_result) = self
            .mult1_state
            .handle_round1(&peer_mult1_r1, &self.own_mult1_r1, rng)
            .map_err(|e| TecdsaError::Other(format!("mult1 R1: {e}")))?;

        let (mult2_state, mult2_r1) = MultState::<C>::new(
            self.my_id,
            self.signer_parties.clone(),
            &self.offline.input_rho,
            &alpha_as_input,
            beta_i,
            self.offline.elgamal_pk,
            self.offline.elgamal_dk,
            self.offline.elgamal_pk_shares.clone(),
            rng,
        );

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18OnlineSignMsg::Round4 {
                mult1_r2: SerMultRound2::from_msg(&mult1_r2),
                mult2_r1: SerMultRound1::from_msg(&mult2_r1),
            },
        }];

        Ok(Ok(OnlineRound4 {
            my_id: self.my_id,
            signer_parties: self.signer_parties,
            r,
            mult1_state: self.mult1_state,
            mult1_r1_result,
            mult2_state,
            own_mult2_r1: mult2_r1,
            outgoing,
            received: BTreeMap::new(),
        }))
    }
}

pub(crate) struct OnlineRound4<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub r: C::Scalar,
    pub mult1_state: MultState<C>,
    pub mult1_r1_result: MultRound1Result<C>,
    pub mult2_state: MultState<C>,
    pub own_mult2_r1: MultRound1Msg<C>,
    pub outgoing: Vec<Outgoing<Ln18OnlineSignMsg<C>>>,
    pub received: BTreeMap<PartyId, (crate::f_mult::mult::MultRound2Msg<C>, MultRound1Msg<C>)>,
}

impl<C: TecdsaCurve> OnlineRound4<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn handle(
        &mut self,
        from: PartyId,
        mult1_r2: crate::f_mult::mult::MultRound2Msg<C>,
        mult2_r1: MultRound1Msg<C>,
    ) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signer_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown sender {from}")));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate Round-4 from {from}")));
        }
        self.received.insert(from, (mult1_r2, mult2_r1));
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.signer_parties.len() - 1
    }

    pub fn advance(mut self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<OnlineRound5<C>> {
        let peer_mult1_r2: Vec<_> = self.received.values().map(|(m, _)| m.clone()).collect();
        let peer_mult2_r1: Vec<_> = self.received.values().map(|(_, m)| m.clone()).collect();

        let (mult1_r3, mult1_r2_result) = self
            .mult1_state
            .handle_round2(&peer_mult1_r2, &self.mult1_r1_result, rng)
            .map_err(|e| TecdsaError::Other(format!("mult1 R2: {e}")))?;
        let (mult2_r2, mult2_r1_result) = self
            .mult2_state
            .handle_round1(&peer_mult2_r1, &self.own_mult2_r1, rng)
            .map_err(|e| TecdsaError::Other(format!("mult2 R1: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18OnlineSignMsg::Round5 {
                mult1_r3: SerMultRound3::from_msg(&mult1_r3),
                mult2_r2: SerMultRound2::from_msg(&mult2_r2),
            },
        }];

        Ok(OnlineRound5 {
            my_id: self.my_id,
            signer_parties: self.signer_parties,
            r: self.r,
            mult1_state: self.mult1_state,
            mult1_r2_result,
            own_mult1_r3: mult1_r3,
            mult2_state: self.mult2_state,
            mult2_r1_result,
            outgoing,
            received: BTreeMap::new(),
        })
    }
}

pub(crate) struct OnlineRound5<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub r: C::Scalar,
    pub mult1_state: MultState<C>,
    pub mult1_r2_result: MultRound2Result<C>,
    pub own_mult1_r3: crate::f_mult::mult::MultRound3Msg<C>,
    pub mult2_state: MultState<C>,
    pub mult2_r1_result: MultRound1Result<C>,
    pub outgoing: Vec<Outgoing<Ln18OnlineSignMsg<C>>>,
    pub received: BTreeMap<
        PartyId,
        (
            crate::f_mult::mult::MultRound3Msg<C>,
            crate::f_mult::mult::MultRound2Msg<C>,
        ),
    >,
}

impl<C: TecdsaCurve> OnlineRound5<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn handle(
        &mut self,
        from: PartyId,
        mult1_r3: crate::f_mult::mult::MultRound3Msg<C>,
        mult2_r2: crate::f_mult::mult::MultRound2Msg<C>,
    ) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signer_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown sender {from}")));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate Round-5 from {from}")));
        }
        self.received.insert(from, (mult1_r3, mult2_r2));
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.signer_parties.len() - 1
    }

    pub fn advance(self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<OnlineRound6<C>> {
        let peer_mult1_r3: Vec<_> = self.received.values().map(|(m, _)| m.clone()).collect();
        let peer_mult2_r2: Vec<_> = self.received.values().map(|(_, m)| m.clone()).collect();

        let (mult1_r4, mult1_r3_result) = self
            .mult1_state
            .handle_round3(
                &peer_mult1_r3,
                &self.own_mult1_r3,
                &self.mult1_r2_result,
                rng,
            )
            .map_err(|e| TecdsaError::Other(format!("mult1 R3: {e}")))?;
        let (mult2_r3, mult2_r2_result) = self
            .mult2_state
            .handle_round2(&peer_mult2_r2, &self.mult2_r1_result, rng)
            .map_err(|e| TecdsaError::Other(format!("mult2 R2: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18OnlineSignMsg::Round6 {
                mult1_r4: SerMultRound4::from_msg(&mult1_r4),
                mult2_r3: SerMultRound3::from_msg(&mult2_r3),
            },
        }];

        Ok(OnlineRound6 {
            my_id: self.my_id,
            signer_parties: self.signer_parties,
            r: self.r,
            mult1_state: self.mult1_state,
            mult1_r2_result: self.mult1_r2_result,
            mult1_r3_result,
            mult2_state: self.mult2_state,
            mult2_r2_result,
            own_mult2_r3: mult2_r3,
            outgoing,
            received: BTreeMap::new(),
        })
    }
}

pub(crate) struct OnlineRound6<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub r: C::Scalar,
    pub mult1_state: MultState<C>,
    pub mult1_r2_result: MultRound2Result<C>,
    pub mult1_r3_result: MultRound3Result<C>,
    pub mult2_state: MultState<C>,
    pub mult2_r2_result: MultRound2Result<C>,
    pub own_mult2_r3: crate::f_mult::mult::MultRound3Msg<C>,
    pub outgoing: Vec<Outgoing<Ln18OnlineSignMsg<C>>>,
    pub received: BTreeMap<
        PartyId,
        (
            crate::f_mult::mult::MultRound4Msg<C>,
            crate::f_mult::mult::MultRound3Msg<C>,
        ),
    >,
}

impl<C: TecdsaCurve> OnlineRound6<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn handle(
        &mut self,
        from: PartyId,
        mult1_r4: crate::f_mult::mult::MultRound4Msg<C>,
        mult2_r3: crate::f_mult::mult::MultRound3Msg<C>,
    ) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signer_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown sender {from}")));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate Round-6 from {from}")));
        }
        self.received.insert(from, (mult1_r4, mult2_r3));
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.signer_parties.len() - 1
    }

    pub fn advance(self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<OnlineRound7<C>> {
        let peer_mult1_r4: Vec<_> = self.received.values().map(|(m, _)| m.clone()).collect();
        let peer_mult2_r3: Vec<_> = self.received.values().map(|(_, m)| m.clone()).collect();

        let (mult1_r5, mult1_r4_result) = self
            .mult1_state
            .handle_round4(
                &peer_mult1_r4,
                &self.mult1_r2_result,
                &self.mult1_r3_result,
                rng,
            )
            .map_err(|e| TecdsaError::Other(format!("mult1 R4: {e}")))?;
        let (mult2_r4, mult2_r3_result) = self
            .mult2_state
            .handle_round3(
                &peer_mult2_r3,
                &self.own_mult2_r3,
                &self.mult2_r2_result,
                rng,
            )
            .map_err(|e| TecdsaError::Other(format!("mult2 R3: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18OnlineSignMsg::Round7 {
                mult1_r5: SerMultRound5::from_msg(&mult1_r5),
                mult2_r4: SerMultRound4::from_msg(&mult2_r4),
            },
        }];

        Ok(OnlineRound7 {
            my_id: self.my_id,
            signer_parties: self.signer_parties,
            r: self.r,
            mult1_state: self.mult1_state,
            mult1_r4_result,
            mult2_state: self.mult2_state,
            mult2_r2_result: self.mult2_r2_result,
            mult2_r3_result,
            outgoing,
            received: BTreeMap::new(),
        })
    }
}

pub(crate) struct OnlineRound7<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub r: C::Scalar,
    pub mult1_state: MultState<C>,
    pub mult1_r4_result: MultRound4Result<C>,
    pub mult2_state: MultState<C>,
    pub mult2_r2_result: MultRound2Result<C>,
    pub mult2_r3_result: MultRound3Result<C>,
    pub outgoing: Vec<Outgoing<Ln18OnlineSignMsg<C>>>,
    pub received: BTreeMap<
        PartyId,
        (
            crate::f_mult::mult::MultRound5Msg<C>,
            crate::f_mult::mult::MultRound4Msg<C>,
        ),
    >,
}

impl<C: TecdsaCurve> OnlineRound7<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn handle(
        &mut self,
        from: PartyId,
        mult1_r5: crate::f_mult::mult::MultRound5Msg<C>,
        mult2_r4: crate::f_mult::mult::MultRound4Msg<C>,
    ) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signer_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown sender {from}")));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate Round-7 from {from}")));
        }
        self.received.insert(from, (mult1_r5, mult2_r4));
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.signer_parties.len() - 1
    }

    pub fn advance(self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<OnlineRound8<C>> {
        let peer_mult1_r5: Vec<_> = self.received.values().map(|(m, _)| m.clone()).collect();
        let peer_mult2_r4: Vec<_> = self.received.values().map(|(_, m)| m.clone()).collect();

        let tau_output = self
            .mult1_state
            .finish_round5(&peer_mult1_r5, &self.mult1_r4_result)
            .map_err(|e| TecdsaError::Other(format!("mult1 R5: {e}")))?;

        let (mult2_r5, mult2_r4_result) = self
            .mult2_state
            .handle_round4(
                &peer_mult2_r4,
                &self.mult2_r2_result,
                &self.mult2_r3_result,
                rng,
            )
            .map_err(|e| TecdsaError::Other(format!("mult2 R4: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ln18OnlineSignMsg::Round8 {
                mult2_r5: SerMultRound5::from_msg(&mult2_r5),
            },
        }];

        Ok(OnlineRound8 {
            my_id: self.my_id,
            signer_parties: self.signer_parties,
            r: self.r,
            tau_output,
            mult2_state: self.mult2_state,
            mult2_r4_result,
            outgoing,
            received: BTreeMap::new(),
        })
    }
}

pub(crate) struct OnlineRound8<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub r: C::Scalar,
    pub tau_output: MultOutput<C>,
    pub mult2_state: MultState<C>,
    pub mult2_r4_result: MultRound4Result<C>,
    pub outgoing: Vec<Outgoing<Ln18OnlineSignMsg<C>>>,
    pub received: BTreeMap<PartyId, crate::f_mult::mult::MultRound5Msg<C>>,
}

impl<C: TecdsaCurve> OnlineRound8<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn handle(
        &mut self,
        from: PartyId,
        mult2_r5: crate::f_mult::mult::MultRound5Msg<C>,
    ) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signer_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown sender {from}")));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::Other(format!("duplicate Round-8 from {from}")));
        }
        self.received.insert(from, mult2_r5);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.received.len() == self.signer_parties.len() - 1
    }

    pub fn finish(self) -> tecdsa_core::Result<Signature<C>> {
        let peer_mult2_r5: Vec<_> = self.received.values().cloned().collect();

        let beta_output = self
            .mult2_state
            .finish_round5(&peer_mult2_r5, &self.mult2_r4_result)
            .map_err(|e| TecdsaError::Other(format!("mult2 R5: {e}")))?;

        let tau = self.tau_output.c;
        let beta = beta_output.c;
        let tau_inv = tau
            .invert()
            .into_option()
            .ok_or_else(|| TecdsaError::Other("tau is not invertible".into()))?;
        let s = low_s_normalize::<C>(tau_inv * beta);

        Ok(Signature { r: self.r, s })
    }
}
