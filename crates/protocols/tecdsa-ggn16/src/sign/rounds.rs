#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    backend::Integer,
    conv::{integer_to_scalar, scalar_to_integer},
    threshold::{combine_partials, partial_decrypt, PartialDecryption},
};
use tecdsa_protocol::{
    low_s_normalize, verify_ecdsa, DataToSign, Outgoing, PartyId, Recipient, Signature,
};

use crate::{
    presign::Ggn16Presignature,
    sign::msg::{Ggn16SignMsg, SignRound6Msg},
};

pub(crate) struct OnlineSignConfig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub presignature: Ggn16Presignature<C>,
    pub message: DataToSign<C>,
}

#[derive(Default)]
pub(crate) enum OnlineSignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round6(Round6State<C>),
    Done(Signature<C>),
    #[default]
    Poisoned,
}

#[allow(dead_code)]
pub(crate) struct Round6State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub presignature: Ggn16Presignature<C>,
    pub message: DataToSign<C>,
    pub sigma: Integer,
    pub my_partial: PartialDecryption,
    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round6_msgs: BTreeMap<PartyId, SignRound6Msg>,
}

impl<C: TecdsaCurve> Round6State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    pub fn new(config: OnlineSignConfig<C>) -> tecdsa_core::Result<Self> {
        let presig = config.presignature;
        let ek = &presig.key_share.threshold_setup.ek;
        let setup = &presig.key_share.threshold_setup;

        let m = *config.message.digest();
        let r = presig.r;
        let psi = presig.psi;

        let m_int = scalar_to_integer::<C>(&m);
        let r_int = scalar_to_integer::<C>(&r);
        let psi_int = scalar_to_integer::<C>(&psi);

        let m_u = ek
            .omul(&m_int, &presig.u)
            .map_err(|e| TecdsaError::Other(format!("omul m*u failed: {e}")))?;

        let r_v = ek
            .omul(&r_int, &presig.v)
            .map_err(|e| TecdsaError::Other(format!("omul r*v failed: {e}")))?;

        let inner = ek
            .oadd(&m_u, &r_v)
            .map_err(|e| TecdsaError::Other(format!("oadd inner failed: {e}")))?;

        let sigma = ek
            .omul(&psi_int, &inner)
            .map_err(|e| TecdsaError::Other(format!("omul psi*inner failed: {e}")))?;

        let my_partial = partial_decrypt(&sigma, &presig.key_share.decryption_share, setup);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round6(SignRound6Msg {
                partial_sigma: my_partial.clone(),
            }),
        }];

        Ok(Self {
            presignature: presig,
            message: config.message,
            sigma,
            my_partial,
            outgoing,
            round6_msgs: BTreeMap::new(),
        })
    }

    fn expected_count(&self) -> usize {
        self.presignature.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound6Msg) -> tecdsa_core::Result<()> {
        let my_id = self.presignature.my_id;
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.presignature.signer_parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round6_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round6_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round6_msgs.len() == self.expected_count()
    }

    pub fn finish(mut self) -> tecdsa_core::Result<Signature<C>> {
        let setup = &self.presignature.key_share.threshold_setup;
        let my_id = self.presignature.my_id;

        let mut partials = vec![self.my_partial];
        for pid in &self.presignature.signer_parties {
            if *pid == my_id {
                continue;
            }
            let r6 = self.round6_msgs.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round6 message from party {pid}"))
            })?;
            partials.push(r6.partial_sigma.clone());
        }

        let s_raw = combine_partials(&partials, setup).map_err(|e| {
            TecdsaError::Other(format!("threshold decryption of sigma failed: {e}"))
        })?;

        let mut s_scalar = integer_to_scalar::<C>(&s_raw);

        s_scalar = low_s_normalize::<C>(s_scalar);

        let r = self.presignature.r;

        let sig = Signature { r, s: s_scalar };

        verify_ecdsa::<C>(&sig, &self.presignature.key_share.public_key, &self.message)?;

        self.sigma = Integer::from(0u32);

        Ok(sig)
    }
}
