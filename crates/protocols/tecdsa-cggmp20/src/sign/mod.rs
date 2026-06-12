pub mod types;

use elliptic_curve::{
    group::Curve as CurveGroup, ops::LinearCombination, sec1::ModulusSize, CurveArithmetic, Field,
    FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
pub use types::{
    DataToSign, PartialSignature, Presignature, PresignatureCommitment, PresignaturePublicData,
    Signature,
};

impl<C: TecdsaCurve> Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn partial_sign(&self, message: &DataToSign<C>) -> PartialSignature<C> {
        let r = C::xcoord_mod_q(&self.big_r.to_affine());
        let m = *message.digest();
        let sigma = self.k_tilde * m + r * self.chi_tilde;
        PartialSignature { sigma }
    }
}

impl<C: TecdsaCurve> PartialSignature<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn combine(
        partials: &[PartialSignature<C>],
        presig_public: &PresignaturePublicData<C>,
        public_key: &C::ProjectivePoint,
        message: &DataToSign<C>,
    ) -> tecdsa_core::Result<Signature<C>>
    where
        C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    {
        if partials.len() != presig_public.commitments.len() {
            return Err(TecdsaError::Other(
                "partial signatures count does not match commitments count".into(),
            ));
        }

        let r = C::xcoord_mod_q(&presig_public.big_r.to_affine());
        let m = *message.digest();
        let gamma = presig_public.big_r;

        for (i, (partial, commitment)) in
            partials.iter().zip(&presig_public.commitments).enumerate()
        {
            let lhs = gamma * partial.sigma;
            let rhs = commitment.tilde_delta * m + commitment.tilde_s * r;
            if lhs != rhs {
                return Err(TecdsaError::InvalidShare(format!(
                    "partial signature {i} failed commitment check"
                )));
            }
        }

        let s = partials
            .iter()
            .fold(<C as CurveArithmetic>::Scalar::ZERO, |acc, p| acc + p.sigma);

        let s = tecdsa_protocol::low_s_normalize::<C>(s);

        let sig = Signature { r, s };
        tecdsa_protocol::verify_ecdsa::<C>(&sig, public_key, message)?;
        Ok(sig)
    }
}
