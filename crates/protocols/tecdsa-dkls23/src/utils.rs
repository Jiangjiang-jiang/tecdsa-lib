#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::PartyId;

pub fn validate_sender(
    from: PartyId,
    my_id: PartyId,
    parties: &[PartyId],
) -> tecdsa_core::Result<()> {
    if from == my_id {
        return Err(TecdsaError::Other("received message from self".into()));
    }
    if !parties.contains(&from) {
        return Err(TecdsaError::UnknownSender(from.0));
    }
    Ok(())
}

pub fn validate_sender_no_dup<V>(
    from: PartyId,
    my_id: PartyId,
    parties: &[PartyId],
    received_map: &BTreeMap<PartyId, V>,
) -> tecdsa_core::Result<()> {
    validate_sender(from, my_id, parties)?;
    if received_map.contains_key(&from) {
        return Err(TecdsaError::DuplicateMessage(from.0));
    }
    Ok(())
}

#[allow(clippy::result_unit_err)]
pub fn deserialize_point<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::ProjectivePoint, ()>
where
    FieldBytesSize<C>: ModulusSize,
{
    let repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
    let buf_len = repr.as_ref().len();
    if bytes.len() != buf_len {
        return Err(());
    }
    let mut repr = repr;
    repr.as_mut().copy_from_slice(bytes);
    let opt = C::ProjectivePoint::from_bytes(&repr);
    Option::from(opt).ok_or(())
}

#[allow(clippy::result_unit_err)]
pub fn deserialize_scalar<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::Scalar, ()>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let fb = FieldBytes::<C>::try_from(bytes).map_err(|_| ())?;
    Option::from(<C::Scalar as PrimeField>::from_repr(fb)).ok_or(())
}

pub use tecdsa_curve::conv::scalar_to_bytes;
