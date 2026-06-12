#![allow(non_snake_case)]

pub mod machine;
pub mod msg;

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytes, FieldBytesSize, PrimeField};
pub use machine::Xal23SignMachine;
pub use msg::Xal23SignMsg;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{low_s_normalize, DataToSign, Signature};

use crate::presign::Xal23Presignature;

#[derive(Clone, Debug)]
pub struct PartialSignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub s_i: <C as CurveArithmetic>::Scalar,
}

pub fn partial_sign<C: TecdsaCurve>(
    presig: &Xal23Presignature<C>,
    data: &DataToSign<C>,
) -> PartialSignature<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let m = *data.digest();
    let s_i = m * presig.k_i + presig.r * presig.sigma_i;
    PartialSignature { s_i }
}

pub fn combine_signatures<C: TecdsaCurve>(
    presig: &Xal23Presignature<C>,
    partials: &[PartialSignature<C>],
    data: &DataToSign<C>,
) -> tecdsa_core::Result<Signature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint:
        elliptic_curve::ops::LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    use elliptic_curve::Field;

    let s: C::Scalar = partials.iter().fold(C::Scalar::ZERO, |acc, p| acc + p.s_i);
    let s = low_s_normalize::<C>(s);

    let sig = Signature { r: presig.r, s };

    tecdsa_protocol::verify_ecdsa(&sig, &presig.public_key, data)?;

    Ok(sig)
}
