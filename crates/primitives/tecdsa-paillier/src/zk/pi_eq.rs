use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use fast_paillier::{backend::Integer, DecryptionKey, EncryptionKey};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;

const TAU: u32 = 256;

const KAPPA: u32 = 80;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PiEqProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub gamma_1: fast_paillier::Ciphertext,
    pub gamma_2: C::ProjectivePoint,
    pub z1: Integer,
    pub z2: Integer,
}

impl<C: TecdsaCurve> Clone for PiEqProof<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            gamma_1: self.gamma_1.clone(),
            gamma_2: self.gamma_2,
            z1: self.z1.clone(),
            z2: self.z2.clone(),
        }
    }
}

impl<C: TecdsaCurve> PiEqProof<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        ssid: &[u8],
        ek: &EncryptionKey,
        _dk: &DecryptionKey,
        c: &fast_paillier::Ciphertext,
        x1_point: &C::ProjectivePoint,
        x_hat_1: &Integer,
        enc_nonce: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let n = ek.n();
        let q_int = curve_order::<C>();

        let b_bound = &q_int * &q_int * Integer::u_pow_u(2, 2 * (TAU + KAPPA));
        let b = b_bound.random_below_ref(rng);

        let delta = sample_coprime_to_n(n, rng);

        let gamma_1 = raw_encrypt(n, &b, &delta);
        let gamma_2 = scalar_mul_generator::<C>(&b);

        let sigma_scalar = fiat_shamir_challenge::<C>(ssid, c, x1_point, &gamma_1, &gamma_2);
        let sigma_bytes = sigma_scalar.to_repr();
        let sigma_int = Integer::from_bytes_msf(sigma_bytes.as_ref());

        let z1 = x_hat_1 * &sigma_int + &b;

        let z2 = enc_nonce
            .pow_mod_ref(&sigma_int, n)
            .expect("pow_mod for z2 must succeed")
            * &delta;
        let z2 = z2.modulo_ref(n);

        Self {
            gamma_1,
            gamma_2,
            z1,
            z2,
        }
    }

    #[must_use]
    pub fn verify(
        &self,
        ssid: &[u8],
        ek: &EncryptionKey,
        c: &fast_paillier::Ciphertext,
        x1_point: &C::ProjectivePoint,
    ) -> bool {
        let n = ek.n();
        let nn = ek.nn();
        let q_int = curve_order::<C>();

        if self.z2.cmp0().is_eq() {
            return false;
        }

        if !c.gcd_ref(n).is_one() {
            return false;
        }

        let z1_upper = &q_int * &q_int * &Integer::u_pow_u(2, 2 * (TAU + KAPPA))
            + (&q_int * &q_int - &q_int) * &Integer::u_pow_u(2, TAU + 2 * KAPPA);
        if self.z1.cmp0().is_lt() {
            return false;
        }
        if self.z1 > z1_upper {
            return false;
        }

        let sigma_scalar =
            fiat_shamir_challenge::<C>(ssid, c, x1_point, &self.gamma_1, &self.gamma_2);
        let sigma_bytes = sigma_scalar.to_repr();
        let sigma_int = Integer::from_bytes_msf(sigma_bytes.as_ref());

        let c_to_sigma = c
            .pow_mod_ref(&sigma_int, nn)
            .expect("pow_mod for C^sigma must succeed");
        let lhs = (&self.gamma_1 * &c_to_sigma).modulo_ref(nn);
        let rhs = raw_encrypt(n, &self.z1, &self.z2);
        if lhs != rhs {
            return false;
        }

        let rhs_ec = scalar_mul_generator::<C>(&self.z1);
        let lhs_ec = self.gamma_2 + *x1_point * sigma_scalar;
        if lhs_ec != rhs_ec {
            return false;
        }

        true
    }
}

fn curve_order<C: TecdsaCurve>() -> Integer
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let neg_one = -C::Scalar::ONE;
    let neg_one_bytes = neg_one.to_repr();
    let q_minus_1 = Integer::from_bytes_msf(neg_one_bytes.as_ref());
    &q_minus_1 + 1u8
}

fn raw_encrypt(n: &Integer, plaintext: &Integer, nonce: &Integer) -> Integer {
    let nn = n * n;
    let term1 = (Integer::one() + plaintext * n).modulo_ref(&nn);
    let term2 = nonce
        .pow_mod_ref(n, &nn)
        .expect("pow_mod for r^N must succeed");
    (&term1 * &term2).modulo_ref(&nn)
}

fn sample_coprime_to_n(n: &Integer, rng: &mut impl CryptoRngCore) -> Integer {
    loop {
        let candidate = n.random_below_ref(rng);
        if candidate.cmp0().is_gt() && candidate.gcd_ref(n).is_one() {
            return candidate;
        }
    }
}

fn scalar_mul_generator<C: TecdsaCurve>(b: &Integer) -> C::ProjectivePoint
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let scalar = tecdsa_curve::conv::bytes_to_scalar::<C>(&b.to_bytes_msf());
    C::generator() * scalar
}

fn fiat_shamir_challenge<C: TecdsaCurve>(
    ssid: &[u8],
    c: &fast_paillier::Ciphertext,
    x1_point: &C::ProjectivePoint,
    gamma_1: &fast_paillier::Ciphertext,
    gamma_2: &C::ProjectivePoint,
) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1_bytes = x1_point.to_bytes();
    let gamma_2_bytes = gamma_2.to_bytes();

    let hash: [u8; 32] = Sha256::new()
        .chain_update(b"kgg24-pi-eq")
        .chain_update(ssid)
        .chain_update(c.to_bytes_msf())
        .chain_update(x1_bytes.as_ref())
        .chain_update(gamma_1.to_bytes_msf())
        .chain_update(gamma_2_bytes.as_ref())
        .finalize()
        .into();

    tecdsa_curve::conv::bytes_to_scalar::<C>(&hash)
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;

    use super::*;

    fn setup_test_scenario() -> (
        DecryptionKey,
        EncryptionKey,
        fast_paillier::Ciphertext,
        Integer,
        Integer,
        <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint,
    ) {
        let mut rng = rand_core::OsRng;

        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let x1 = <Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let x1_point = <Secp256k1 as TecdsaCurve>::generator() * x1;

        let q_int = curve_order::<Secp256k1>();
        let x1_bytes = x1.to_repr();
        let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
        let noise_bound = Integer::u_pow_u(2, TAU + 2 * KAPPA);
        let t = noise_bound.random_below_ref(&mut rng);
        let x_hat_1 = &x1_int + &t * &q_int;

        let (c, enc_nonce) = dk
            .encrypt_with_random(&mut rng, &x_hat_1)
            .expect("encryption must succeed");

        (dk, ek, c, x_hat_1, enc_nonce, x1_point)
    }

    #[test]
    fn pi_eq_proof_valid() {
        let mut rng = rand_core::OsRng;
        let (dk, ek, c, x_hat_1, enc_nonce, x1_point) = setup_test_scenario();

        let ssid = b"test-ssid";
        let proof = PiEqProof::<Secp256k1>::prove(
            ssid, &ek, &dk, &c, &x1_point, &x_hat_1, &enc_nonce, &mut rng,
        );

        assert!(
            proof.verify(ssid, &ek, &c, &x1_point),
            "valid Pi_eq proof must verify"
        );
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn pi_eq_proof_wrong_ssid_fails() {
        let mut rng = rand_core::OsRng;
        let (dk, ek, c, x_hat_1, enc_nonce, x1_point) = setup_test_scenario();

        let proof = PiEqProof::<Secp256k1>::prove(
            b"ssid-1", &ek, &dk, &c, &x1_point, &x_hat_1, &enc_nonce, &mut rng,
        );

        assert!(
            !proof.verify(b"ssid-2", &ek, &c, &x1_point),
            "proof with wrong ssid must not verify"
        );
    }

    #[test]
    fn pi_eq_proof_wrong_point_fails() {
        let mut rng = rand_core::OsRng;
        let (dk, ek, c, x_hat_1, enc_nonce, x1_point) = setup_test_scenario();

        let ssid = b"test-ssid";
        let proof = PiEqProof::<Secp256k1>::prove(
            ssid, &ek, &dk, &c, &x1_point, &x_hat_1, &enc_nonce, &mut rng,
        );

        let wrong_scalar = <Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let wrong_point = <Secp256k1 as TecdsaCurve>::generator() * wrong_scalar;

        assert!(
            !proof.verify(ssid, &ek, &c, &wrong_point),
            "proof with wrong EC point must not verify"
        );
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn pi_eq_proof_wrong_ciphertext_fails() {
        let mut rng = rand_core::OsRng;
        let (dk, ek, c, x_hat_1, enc_nonce, x1_point) = setup_test_scenario();

        let ssid = b"test-ssid";
        let proof = PiEqProof::<Secp256k1>::prove(
            ssid, &ek, &dk, &c, &x1_point, &x_hat_1, &enc_nonce, &mut rng,
        );

        let different_plaintext = Integer::from(42u8);
        let (wrong_c, _) = ek
            .encrypt_with_random(&mut rng, &different_plaintext)
            .expect("encryption");

        assert!(
            !proof.verify(ssid, &ek, &wrong_c, &x1_point),
            "proof with wrong ciphertext must not verify"
        );
    }

    #[test]
    #[ignore = "redundant negative test"]
    fn pi_eq_proof_wrong_key_fails() {
        let mut rng = rand_core::OsRng;
        let (dk, ek, c, x_hat_1, enc_nonce, x1_point) = setup_test_scenario();

        let ssid = b"test-ssid";
        let proof = PiEqProof::<Secp256k1>::prove(
            ssid, &ek, &dk, &c, &x1_point, &x_hat_1, &enc_nonce, &mut rng,
        );

        let dk2 = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek2 = dk2.encryption_key().clone();

        assert!(
            !proof.verify(ssid, &ek2, &c, &x1_point),
            "proof with wrong Paillier key must not verify"
        );
    }
}
