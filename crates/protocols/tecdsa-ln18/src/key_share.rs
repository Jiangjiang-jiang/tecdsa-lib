use std::{collections::BTreeMap, sync::Arc};

use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{zk::mta_range::NTildeParams, DecryptionKey, EncryptionKey};
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

use crate::{f_mult::input::InputOutput, sign::mta_hybrid::Ln18MtaHybrid};

pub struct Ln18KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub party_index: u16,
    pub secret_share: C::Scalar,
    pub public_key: C::ProjectivePoint,
    pub public_shares: Vec<C::ProjectivePoint>,
    pub n: u16,
    pub t: u16,
}

impl<C: TecdsaCurve> Clone for Ln18KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            party_index: self.party_index,
            secret_share: self.secret_share,
            public_key: self.public_key,
            public_shares: self.public_shares.clone(),
            n: self.n,
            t: self.t,
        }
    }
}

impl<C: TecdsaCurve> Zeroize for Ln18KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

#[allow(non_snake_case)]
pub struct Ln18Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub R: C::ProjectivePoint,
    pub r: C::Scalar,
    pub tau_i: C::Scalar,
    pub stored_rho_input: InputOutput<C>,
    pub stored_x_input: InputOutput<C>,
    pub elgamal_dk: C::Scalar,
    pub elgamal_pk: C::ProjectivePoint,
    pub elgamal_pk_shares: Vec<C::ProjectivePoint>,
}

#[allow(non_snake_case)]
pub struct Ln18OfflineSignState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub input_k: InputOutput<C>,
    pub input_rho: InputOutput<C>,
    pub paillier_dk: DecryptionKey,
    pub paillier_eks: BTreeMap<PartyId, EncryptionKey>,
    pub ntilde_params: BTreeMap<PartyId, NTildeParams>,
    pub stored_x_input: InputOutput<C>,
    pub signer_parties: Vec<PartyId>,
    pub weighted_x_input: InputOutput<C>,
    pub elgamal_dk: C::Scalar,
    pub elgamal_pk: C::ProjectivePoint,
    pub elgamal_pk_shares: Vec<C::ProjectivePoint>,
    pub mta: Arc<Ln18MtaHybrid<C>>,
}

impl<C: TecdsaCurve> Zeroize for Ln18OfflineSignState<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.input_k.a_i.zeroize();
        self.input_k.s_i.zeroize();
        self.input_rho.a_i.zeroize();
        self.input_rho.s_i.zeroize();
        self.weighted_x_input.a_i.zeroize();
        self.weighted_x_input.s_i.zeroize();
        self.elgamal_dk.zeroize();
    }
}
