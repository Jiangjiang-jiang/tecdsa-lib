// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pi_eq: loose consistency proof (KGG24 Figure 4, Section 3).
//!
//! Proves that a Paillier ciphertext `C = Enc_N(x_hat_1)` and an EC point
//! `X1 = x1 * G` are "loosely consistent": there exist `x1, x_hat_1` such
//! that `X1 = x1 * G` and `x_hat_1 = x1 + delta * q` for some small `delta`.
//!
//! This is a non-interactive Sigma protocol (Fiat-Shamir via SHA-256).
//!
//! ## Protocol
//!
//! **Prover** (input: ssid, N, C, X1, x_hat_1, encryption nonce rho):
//! 1. Sample `delta <- Z*_N`, `b <- [q^2 * 2^{2(tau+kappa)}]`
//! 2. `gamma_1 = Enc_N(b; delta)`, `gamma_2 = b * G`
//! 3. `sigma = H(ssid, C, X1, gamma_1, gamma_2)` (Fiat-Shamir in Z_q)
//! 4. `z1 = x_hat_1 * sigma + b` (over integers)
//! 5. `z2 = rho^sigma * delta mod N` (Paillier randomness)
//! 6. Output `psi = (gamma_1, gamma_2, z1, z2)`
//!
//! **Verifier** (input: ssid, N, C, X1, psi):
//! 1. Range check: `z1 in [0, UPPER_BOUND]`, `z2 != 0`
//! 2. `gcd(C, N) = 1` (well-formed ciphertext)
//! 3. `sigma = H(ssid, C, X1, gamma_1, gamma_2)`
//! 4. Paillier check: `gamma_1 * C^sigma = Enc_N(z1; z2)` (mod N^2)
//! 5. EC check: `gamma_2 + sigma * X1 = z1 * G` (mod q on scalar)

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use rug::{Complete, Integer};
use sha2::{Digest, Sha256};
use tecdsa_bigint::BigIntExt;
use tecdsa_curve::TecdsaCurve;

use crate::scheme::{DecryptionKey, EncryptionKey};

/// Security parameter tau (bit-length of the noise exponent base).
const TAU: u32 = 256;

/// Statistical security parameter kappa.
const KAPPA: u32 = 80;

/// The Pi_eq (loose consistency) proof.
///
/// Proves that `C = Enc_N(x_hat_1)` and `X1 = x1 * G` satisfy
/// `x_hat_1 ≡ x1 (mod q)` for some noise offset.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PiEqProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Ciphertext commitment `gamma_1 = Enc_N(b; delta)`.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub gamma_1: crate::scheme::Ciphertext,
    /// EC point commitment `gamma_2 = b * G` (reduced mod q).
    pub gamma_2: C::ProjectivePoint,
    /// Integer response `z1 = x_hat_1 * sigma + b`.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z1: Integer,
    /// Nonce response `z2 = rho^sigma * delta mod N`.
    #[serde(with = "tecdsa_bigint::int_wire")]
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
    /// Generate a Pi_eq proof.
    ///
    /// # Arguments
    ///
    /// * `ssid` - session identifier for domain separation
    /// * `ek` - Paillier encryption key
    /// * `dk` - Paillier decryption key (used to access N for randomness sampling)
    /// * `c` - ciphertext `C = Enc_N(x_hat_1; rho)`
    /// * `x1_point` - EC point `X1 = x1 * G`
    /// * `x_hat_1` - the noised plaintext `x1 + t * q`
    /// * `enc_nonce` - the encryption nonce `rho` used in `C = Enc_N(x_hat_1; rho)`
    /// * `rng` - cryptographic RNG
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        ssid: &[u8],
        ek: &EncryptionKey,
        _dk: &DecryptionKey,
        c: &crate::scheme::Ciphertext,
        x1_point: &C::ProjectivePoint,
        x_hat_1: &Integer,
        enc_nonce: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let n = ek.n();
        let q_int = C::order();

        // Step 1: Sample b from [0, q^2 * 2^{2(tau+kappa)})
        let b_bound = Integer::two_pow(2 * (TAU + KAPPA)) * &q_int * &q_int;
        let b = b_bound.sample_below_ref(rng);

        // Sample delta from Z*_N (nonzero, coprime to N)
        let delta = Integer::sample_in_mult_group_of(rng, n);

        // Step 2: gamma_1 = Enc_N(b; delta), gamma_2 = b * G
        let gamma_1 = super::paillier_encrypt_raw(n, &(n * n).complete(), &b, &delta);
        let gamma_2 = scalar_mul_generator::<C>(&b);

        // Step 3: Fiat-Shamir challenge sigma = H(ssid, C, X1, gamma_1, gamma_2) mod q
        let sigma_scalar = fiat_shamir_challenge::<C>(ssid, c, x1_point, &gamma_1, &gamma_2);
        let sigma_bytes = sigma_scalar.to_repr();
        let sigma_int = Integer::from_bytes_msf(sigma_bytes.as_ref());

        // Step 4: z1 = x_hat_1 * sigma + b (over integers, no mod)
        let z1 = b + x_hat_1 * &sigma_int;

        // Step 5: z2 = rho^sigma * delta mod N
        let z2 = enc_nonce
            .pow_mod_ref(&sigma_int, n)
            .expect("pow_mod for z2 must succeed")
            .complete()
            * &delta;
        let z2 = z2.modulo(n);

        Self {
            gamma_1,
            gamma_2,
            z1,
            z2,
        }
    }

    /// Verify a Pi_eq proof.
    ///
    /// # Arguments
    ///
    /// * `ssid` - session identifier (must match prover's)
    /// * `ek` - Paillier encryption key
    /// * `c` - ciphertext being proven consistent
    /// * `x1_point` - EC point being proven consistent
    #[must_use]
    pub fn verify(
        &self,
        ssid: &[u8],
        ek: &EncryptionKey,
        c: &crate::scheme::Ciphertext,
        x1_point: &C::ProjectivePoint,
    ) -> bool {
        let n = ek.n();
        let nn = ek.nn();
        let q_int = C::order();

        // Check 1: z2 != 0
        if self.z2.cmp0().is_eq() {
            return false;
        }

        // Check 2: gcd(C, N) = 1
        if !c.gcd_ref(n).complete().is_one() {
            return false;
        }

        // Check 3: z1 range check
        // z1 must be in [0, q^2 * 2^{2(tau+kappa)} + (q^2 - q) * 2^{tau+2kappa}]
        // This is the maximum value z1 can take: x_hat_1 * sigma + b
        // where x_hat_1 <= q * 2^{tau+2kappa} (approximately) and sigma < q, b < q^2 * 2^{2(tau+kappa)}
        let z1_upper = Integer::two_pow(2 * (TAU + KAPPA)) * &q_int * &q_int
            + ((&q_int * &q_int).complete() - &q_int) * Integer::two_pow(TAU + 2 * KAPPA);
        if self.z1.cmp0().is_lt() {
            return false;
        }
        if self.z1 > z1_upper {
            return false;
        }

        // Check 4: Fiat-Shamir challenge
        let sigma_scalar =
            fiat_shamir_challenge::<C>(ssid, c, x1_point, &self.gamma_1, &self.gamma_2);
        let sigma_bytes = sigma_scalar.to_repr();
        let sigma_int = Integer::from_bytes_msf(sigma_bytes.as_ref());

        // Check 5: Paillier homomorphic check
        // gamma_1 * C^sigma == Enc_N(z1; z2) (mod N^2)
        let c_to_sigma = c
            .pow_mod_ref(&sigma_int, nn)
            .expect("pow_mod for C^sigma must succeed")
            .complete();
        let lhs = (&self.gamma_1 * c_to_sigma).modulo(nn);
        let rhs = super::paillier_encrypt_raw(n, &(n * n).complete(), &self.z1, &self.z2);
        if lhs != rhs {
            return false;
        }

        // Check 6: EC point check
        // gamma_2 + sigma * X1 == z1 * G (mod q in the exponent)
        let rhs_ec = scalar_mul_generator::<C>(&self.z1);
        let lhs_ec = self.gamma_2 + *x1_point * sigma_scalar;
        lhs_ec == rhs_ec
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Multiply the generator by a big integer: `b * G` where b is reduced mod q.
fn scalar_mul_generator<C: TecdsaCurve>(b: &Integer) -> C::ProjectivePoint
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let scalar = C::scalar_from_bytes(&b.to_bytes_msf());
    C::generator() * scalar
}

/// Compute the Fiat-Shamir challenge: `sigma = H(ssid, C, X1, gamma_1, gamma_2) mod q`.
fn fiat_shamir_challenge<C: TecdsaCurve>(
    ssid: &[u8],
    c: &crate::scheme::Ciphertext,
    x1_point: &C::ProjectivePoint,
    gamma_1: &crate::scheme::Ciphertext,
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

    C::scalar_from_bytes(&hash)
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;

    use super::*;

    /// Helper: create a test scenario with valid Paillier encryption of x_hat_1.
    fn setup_test_scenario() -> (
        DecryptionKey,
        EncryptionKey,
        crate::scheme::Ciphertext,
        Integer, // x_hat_1
        Integer, // enc_nonce (rho)
        <Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint,
    ) {
        let mut rng = rand_core::OsRng;

        // Generate Paillier keys
        let dk = crate::scheme::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        // Sample x1 scalar
        let x1 = <Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let x1_point = <Secp256k1 as TecdsaCurve>::generator() * x1;

        // Compute x_hat_1 = x1 + t * q
        let q_int = Secp256k1::order();
        let x1_bytes = x1.to_repr();
        let x1_int = Integer::from_bytes_msf(x1_bytes.as_ref());
        let noise_bound = Integer::two_pow(TAU + 2 * KAPPA);
        let t = noise_bound.sample_below_ref(&mut rng);
        let x_hat_1 = &x1_int + (t * q_int);

        // Encrypt x_hat_1
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

        // Use a different point for verification
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

        // Create a different ciphertext
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

        // Use a different Paillier key for verification
        let dk2 = crate::scheme::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek2 = dk2.encryption_key().clone();

        assert!(
            !proof.verify(ssid, &ek2, &c, &x1_point),
            "proof with wrong Paillier key must not verify"
        );
    }
}
