use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{DecryptionKey, EncryptionKey};
use zeroize::Zeroize;

use crate::setup::SetupData;

pub struct Abc24ServerKeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub secret_share: <C as CurveArithmetic>::Scalar,
    pub public_key: C::ProjectivePoint,
    pub client_public_share: C::ProjectivePoint,
    pub dk: DecryptionKey,
    pub setup: SetupData,
}

impl<C: TecdsaCurve> Zeroize for Abc24ServerKeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

pub struct Abc24ClientKeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub secret_share: <C as CurveArithmetic>::Scalar,
    pub public_key: C::ProjectivePoint,
    pub server_public_share: C::ProjectivePoint,
    pub enc_x2: tecdsa_paillier::Ciphertext,
    pub ek: EncryptionKey,
    pub setup: SetupData,
}

impl<C: TecdsaCurve> Zeroize for Abc24ClientKeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}
