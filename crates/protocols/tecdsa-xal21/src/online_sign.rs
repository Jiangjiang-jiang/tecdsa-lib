use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    error::Xal21Error,
    key_share::Xal21Party1KeyShare,
    offline_sign::{Party1Presignature, Party2Presignature},
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party2OnlineMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub s2: C::Scalar,
}

pub fn party2_compute_s2<C: TecdsaCurve>(
    presig: &Party2Presignature<C>,
    message: &DataToSign<C>,
) -> Result<Party2OnlineMsg<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let h = *message.digest();

    let k2_plus_r1 = presig.k2 + presig.r1;
    let k2_plus_r1_inv = k2_plus_r1
        .invert()
        .into_option()
        .ok_or_else(|| Xal21Error::ProtocolState("k_2 + r_1 is zero, cannot invert".into()))?;

    let s2 = k2_plus_r1_inv * (h + presig.r * presig.x2_prime);

    Ok(Party2OnlineMsg { s2 })
}

pub fn party1_compute_signature<C: TecdsaCurve>(
    key_share: &Xal21Party1KeyShare<C>,
    presig: &Party1Presignature<C>,
    p2_msg: &Party2OnlineMsg<C>,
    message: &DataToSign<C>,
) -> Result<Signature<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    let k1_inv = presig
        .k1
        .invert()
        .into_option()
        .ok_or_else(|| Xal21Error::ProtocolState("k_1 is zero, cannot invert".into()))?;

    let s_raw = k1_inv * (p2_msg.s2 + presig.r * presig.x1_prime);

    let s = low_s_normalize::<C>(s_raw);

    let signature = Signature { r: presig.r, s };

    verify_ecdsa::<C>(&signature, &key_share.public_key, message).map_err(|e| {
        Xal21Error::EcdsaVerification(format!("final signature verification failed: {e}"))
    })?;

    Ok(signature)
}

pub fn online_sign<C: TecdsaCurve>(
    p1_key: &Xal21Party1KeyShare<C>,
    p1_presig: &Party1Presignature<C>,
    p2_presig: &Party2Presignature<C>,
    message: &DataToSign<C>,
) -> Result<Signature<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    let p2_msg = party2_compute_s2::<C>(p2_presig, message)?;

    party1_compute_signature::<C>(p1_key, p1_presig, &p2_msg, message)
}
