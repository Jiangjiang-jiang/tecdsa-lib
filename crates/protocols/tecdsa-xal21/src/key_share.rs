use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{zk::mta_range::NTildeParams, DecryptionKey, EncryptionKey};
use zeroize::Zeroize;

pub struct Xal21Party1KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub secret_share: <C as CurveArithmetic>::Scalar,
    pub public_key: C::ProjectivePoint,
    pub public_share: C::ProjectivePoint,
    pub ek: EncryptionKey,
    pub ntilde: NTildeParams,
}

impl<C: TecdsaCurve> Zeroize for Xal21Party1KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

pub struct Xal21Party2KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub secret_share: <C as CurveArithmetic>::Scalar,
    pub public_key: C::ProjectivePoint,
    pub public_share_p1: C::ProjectivePoint,
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub ntilde: NTildeParams,
}

impl<C: TecdsaCurve> Zeroize for Xal21Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}
