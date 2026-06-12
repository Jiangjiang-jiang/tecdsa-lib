use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
pub use tecdsa_protocol::{DataToSign, Signature};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub big_r: C::ProjectivePoint,
    pub k_tilde: <C as CurveArithmetic>::Scalar,
    pub chi_tilde: <C as CurveArithmetic>::Scalar,
}

impl<C: TecdsaCurve> Zeroize for Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k_tilde.zeroize();
        self.chi_tilde.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct PresignaturePublicData<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub big_r: C::ProjectivePoint,
    pub commitments: Vec<PresignatureCommitment<C>>,
}

#[derive(Debug, Clone)]
pub struct PresignatureCommitment<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub tilde_delta: C::ProjectivePoint,
    pub tilde_s: C::ProjectivePoint,
}

#[derive(Debug, Clone)]
pub struct PartialSignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub sigma: <C as CurveArithmetic>::Scalar,
}
