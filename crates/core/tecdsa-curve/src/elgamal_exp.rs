use elliptic_curve::{group::Group, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};

use crate::TecdsaCurve;

#[derive(Clone, Debug)]
pub struct EgexpCiphertext<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub a: C::ProjectivePoint,
    pub b: C::ProjectivePoint,
}

impl<C: TecdsaCurve> PartialEq for EgexpCiphertext<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<C: TecdsaCurve> Eq for EgexpCiphertext<C> where FieldBytesSize<C>: ModulusSize {}

pub fn encrypt<C: TecdsaCurve>(
    pk: &C::ProjectivePoint,
    m: &C::Scalar,
    r: &C::Scalar,
) -> EgexpCiphertext<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    let g = C::generator();
    EgexpCiphertext {
        a: g * r,
        b: *pk * r + g * m,
    }
}

pub fn encrypt_random<C: TecdsaCurve>(
    pk: &C::ProjectivePoint,
    m: &C::Scalar,
    rng: &mut impl rand_core::CryptoRngCore,
) -> (EgexpCiphertext<C>, C::Scalar)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let r = C::random_scalar(rng);
    let ct = encrypt::<C>(pk, m, &r);
    (ct, r)
}

impl<C: TecdsaCurve> EgexpCiphertext<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        Self {
            a: self.a + other.a,
            b: self.b + other.b,
        }
    }

    #[must_use]
    pub fn scalar_mul(&self, c: &C::Scalar) -> Self {
        Self {
            a: self.a * c,
            b: self.b * c,
        }
    }

    #[must_use]
    pub fn rerandomize(&self, pk: &C::ProjectivePoint, s: &C::Scalar) -> Self {
        let g = C::generator();
        Self {
            a: self.a + g * s,
            b: self.b + *pk * s,
        }
    }

    #[must_use]
    pub fn decrypt_to_point(&self, dk: &C::Scalar) -> C::ProjectivePoint {
        self.b - self.a * dk
    }

    #[must_use]
    pub fn identity() -> Self {
        Self {
            a: C::ProjectivePoint::identity(),
            b: C::ProjectivePoint::identity(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    #[cfg(feature = "secp256k1")]
    fn setup_keys(
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> (
        <C as elliptic_curve::CurveArithmetic>::Scalar,
        <C as elliptic_curve::CurveArithmetic>::ProjectivePoint,
    ) {
        let dk = C::random_scalar(rng);
        let pk = C::generator() * dk;
        (dk, pk)
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = rand::thread_rng();
        let (dk, pk) = setup_keys(&mut rng);
        let m = C::random_scalar(&mut rng);

        let (ct, _r) = encrypt_random::<C>(&pk, &m, &mut rng);
        let decrypted = ct.decrypt_to_point(&dk);

        let expected = C::generator() * m;
        assert_eq!(decrypted, expected, "decrypt(encrypt(m)) should equal m*G");
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn homomorphic_add() {
        let mut rng = rand::thread_rng();
        let (dk, pk) = setup_keys(&mut rng);
        let m1 = C::random_scalar(&mut rng);
        let m2 = C::random_scalar(&mut rng);

        let (ct1, _) = encrypt_random::<C>(&pk, &m1, &mut rng);
        let (ct2, _) = encrypt_random::<C>(&pk, &m2, &mut rng);

        let ct_sum = ct1.add(&ct2);
        let decrypted = ct_sum.decrypt_to_point(&dk);

        let expected = C::generator() * (m1 + m2);
        assert_eq!(
            decrypted, expected,
            "Enc(m1) + Enc(m2) should decrypt to (m1+m2)*G"
        );
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn scalar_mul_homomorphic() {
        let mut rng = rand::thread_rng();
        let (dk, pk) = setup_keys(&mut rng);
        let m = C::random_scalar(&mut rng);
        let c = C::random_scalar(&mut rng);

        let (ct, _) = encrypt_random::<C>(&pk, &m, &mut rng);
        let ct_scaled = ct.scalar_mul(&c);
        let decrypted = ct_scaled.decrypt_to_point(&dk);

        let expected = C::generator() * (c * m);
        assert_eq!(decrypted, expected, "c * Enc(m) should decrypt to (c*m)*G");
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn rerandomize_preserves_plaintext() {
        let mut rng = rand::thread_rng();
        let (dk, pk) = setup_keys(&mut rng);
        let m = C::random_scalar(&mut rng);

        let (ct, _) = encrypt_random::<C>(&pk, &m, &mut rng);
        let s = C::random_scalar(&mut rng);
        let ct_rerand = ct.rerandomize(&pk, &s);

        assert_ne!(ct, ct_rerand, "rerandomize should change the ciphertext");

        let decrypted_original = ct.decrypt_to_point(&dk);
        let decrypted_rerand = ct_rerand.decrypt_to_point(&dk);
        let expected = C::generator() * m;

        assert_eq!(
            decrypted_original, expected,
            "original should decrypt to m*G"
        );
        assert_eq!(
            decrypted_rerand, expected,
            "rerandomized should decrypt to same m*G"
        );
    }
}
