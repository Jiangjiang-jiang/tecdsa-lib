#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{
    low_s_normalize, verify_ecdsa, DataToSign, Outgoing, PartyId, Recipient, Signature,
};
use zeroize::Zeroize;

use crate::{
    presign::Dkls23Presignature,
    sign::msg::{Dkls23SignMsg, SignR4Broadcast},
    utils::validate_sender,
};

#[derive(Default)]
pub(crate) enum OnlineSignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round4(Round4State<C>),
    Done(Signature<C>),
    #[default]
    Gone,
}

pub struct OnlineSignConfig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub presignature: Dkls23Presignature<C>,
    pub message: DataToSign<C>,
}

pub(crate) struct Round4State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    signer_parties: Vec<PartyId>,
    message: DataToSign<C>,
    public_key: C::ProjectivePoint,
    r_x: C::Scalar,
    u_i: C::Scalar,
    w_i: C::Scalar,
    pub outgoing: Vec<Outgoing<Dkls23SignMsg<C>>>,
    round4_msgs: BTreeMap<PartyId, SignR4Broadcast<C>>,
}

impl<C: TecdsaCurve> Round4State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: OnlineSignConfig<C>) -> Self {
        let presig = config.presignature;
        let message = config.message;
        let m = *message.digest();

        let mut mask_sum = presig.phi_i;
        for &psi_ji in presig.received_psi.values() {
            mask_sum += psi_ji;
        }

        let mut cu_du_sum = C::Scalar::ZERO;
        let mut cv_dv_sum = C::Scalar::ZERO;
        for data in presig.rvole_data.values() {
            cu_du_sum = cu_du_sum + data.c_u + data.d_u;
            cv_dv_sum = cv_dv_sum + data.c_v + data.d_v;
        }

        let u_i = presig.r_i * mask_sum + cu_du_sum;

        let v_i = presig.sk_i * mask_sum + cv_dv_sum;

        let w_i = m * presig.phi_i + presig.r_x * v_i;

        let my_id = presig.my_id;
        let signer_parties = presig.signer_parties.clone();
        let public_key = presig.key_share.public_key;
        let r_x = presig.r_x;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Dkls23SignMsg::Round4Broadcast(SignR4Broadcast { u_i, w_i }),
        }];

        Self {
            my_id,
            signer_parties,
            message,
            public_key,
            r_x,
            u_i,
            w_i,
            outgoing,
            round4_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignR4Broadcast<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.signer_parties)?;
        if self.round4_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round4_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round4_msgs.len() == self.expected_count()
    }

    pub fn finish(mut self) -> tecdsa_core::Result<Signature<C>>
    where
        C::ProjectivePoint:
            elliptic_curve::ops::LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    {
        let mut u_sum = self.u_i;
        let mut w_sum = self.w_i;
        for &pid in &self.signer_parties {
            if pid == self.my_id {
                continue;
            }
            let msg = &self.round4_msgs[&pid];
            u_sum += msg.u_i;
            w_sum += msg.w_i;
        }

        let u_inv = u_sum
            .invert()
            .into_option()
            .ok_or_else(|| TecdsaError::InvalidShare("u_sum is zero, cannot invert".into()))?;
        let s = w_sum * u_inv;

        let s = low_s_normalize::<C>(s);

        let sig = Signature { r: self.r_x, s };

        verify_ecdsa::<C>(&sig, &self.public_key, &self.message)?;

        self.u_i.zeroize();
        self.w_i.zeroize();

        Ok(sig)
    }
}
