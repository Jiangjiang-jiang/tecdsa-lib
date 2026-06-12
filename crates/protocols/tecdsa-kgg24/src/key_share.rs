use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{DecryptionKey, EncryptionKey};
use zeroize::Zeroize;

pub struct Kgg24Party1KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub secret_share: <C as CurveArithmetic>::Scalar,
    pub public_key: C::ProjectivePoint,
    pub dk: DecryptionKey,
}

impl<C: TecdsaCurve> Zeroize for Kgg24Party1KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

pub struct Kgg24Party2KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub secret_share: <C as CurveArithmetic>::Scalar,
    pub public_key: C::ProjectivePoint,
    pub c_key: tecdsa_paillier::Ciphertext,
    pub ek: EncryptionKey,
}

impl<C: TecdsaCurve> Zeroize for Kgg24Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}
