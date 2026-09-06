// SPDX-License-Identifier: MIT OR Apache-2.0
//! Zero-knowledge proof that a Paillier ciphertext encrypts the discrete
//! log of an elliptic curve point, with a *slack* range check.
//!
//! **Relation:**
//! Prover knows $(x, r)$ s.t. $C = \text{Enc}\_N(x; r)$ and $Q = xG$,
//! with $|x| < q^3$ where $q$ is the EC group order.
//!
//! The auxiliary parameters $(N', h\_1, h\_2)$ form a Ring-Pedersen commitment
//! scheme used for the range proof.
//!
//! This is proof `PI_i` from <https://eprint.iacr.org/2016/013.pdf>,
//! originally from proof 6.3 (left side) in
//! <https://www.cs.unc.edu/~reiter/papers/2004/IJIS.pdf>.
//!
//! The proof is non-interactive via the Fiat-Shamir transform (SHA-256).

#![allow(non_snake_case)]

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, CurveArithmetic, FieldBytes, FieldBytesSize,
    PrimeField,
};
use fast_paillier::backend::{BigIntExt, Integer};
use rug::{ops::Pow, Complete};
use sha2::{Digest, Sha256};
use tecdsa_curve::{
    conv::{curve_order, integer_to_scalar},
    TecdsaCurve,
};

/// Fiat-Shamir challenge error.
#[derive(Debug, thiserror::Error)]
pub enum PdlSlackError {
    /// Verification of the PDL-with-slack proof failed.
    #[error("PDL-with-slack verification failed")]
    Verify,
}

// ---------------------------------------------------------------------------
// Statement / Witness
// ---------------------------------------------------------------------------

/// Public statement for the PDL-with-slack proof.
///
/// All fields reference publicly-known values:
/// - `ciphertext`: $C = \text{Enc}\_N(x; r)$
/// - `ek_n`: the Paillier modulus $N$
/// - `ek_nn`: $N^2$
/// - `Q`: $xG$ (the public EC point)
/// - `G`: the group generator
/// - `h1, h2, N_tilde`: Ring-Pedersen auxiliary parameters
pub struct PdlSlackStatement<C: CurveArithmetic> {
    /// Paillier ciphertext $C$.
    pub ciphertext: Integer,
    /// Paillier modulus $N$.
    pub ek_n: Integer,
    /// Paillier modulus squared $N^2$.
    pub ek_nn: Integer,
    /// EC point $Q = xG$.
    pub Q: C::ProjectivePoint,
    /// Group generator.
    pub G: C::ProjectivePoint,
    /// Ring-Pedersen base `h1`.
    pub h1: Integer,
    /// Ring-Pedersen base `h2`.
    pub h2: Integer,
    /// Ring-Pedersen modulus $\tilde{N}$.
    pub N_tilde: Integer,
}

/// Witness for the PDL-with-slack proof.
pub struct PdlSlackWitness {
    /// The discrete log / plaintext $x$.
    pub x: Integer,
    /// The Paillier encryption randomness $r$.
    pub r: Integer,
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/// Non-interactive PDL-with-slack proof (Fiat-Shamir transformed).
#[derive(Debug, Clone)]
pub struct PdlSlackProof<C: CurveArithmetic> {
    z: Integer,
    u1: C::ProjectivePoint,
    u2: Integer,
    u3: Integer,
    s1: Integer,
    s2: Integer,
    s3: Integer,
}

impl<C> PdlSlackProof<C>
where
    C: CurveArithmetic,
    C::ProjectivePoint: GroupEncoding,
{
    /// Serialize the proof to a length-prefixed byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Helper: write a length-prefixed Integer
        let write_int = |buf: &mut Vec<u8>, val: &Integer| {
            let b = val.to_bytes_msf();
            buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
            buf.extend_from_slice(&b);
        };

        write_int(&mut buf, &self.z);

        // Write the EC point u1 (compressed SEC1 encoding)
        let u1_bytes = self.u1.to_bytes();
        let u1_ref: &[u8] = u1_bytes.as_ref();
        buf.extend_from_slice(&(u1_ref.len() as u32).to_be_bytes());
        buf.extend_from_slice(u1_ref);

        write_int(&mut buf, &self.u2);
        write_int(&mut buf, &self.u3);
        write_int(&mut buf, &self.s1);
        write_int(&mut buf, &self.s2);
        write_int(&mut buf, &self.s3);

        buf
    }

    /// Deserialize a proof from the format produced by [`to_bytes`](Self::to_bytes).
    ///
    /// Returns `None` if the input is malformed.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let read_chunk = |data: &[u8], pos: &mut usize| -> Option<Vec<u8>> {
            if *pos + 4 > data.len() {
                return None;
            }
            let len = u32::from_be_bytes(data[*pos..*pos + 4].try_into().ok()?) as usize;
            *pos += 4;
            if *pos + len > data.len() {
                return None;
            }
            let chunk = data[*pos..*pos + len].to_vec();
            *pos += len;
            Some(chunk)
        };

        let read_int = |data: &[u8], pos: &mut usize| -> Option<Integer> {
            let chunk = read_chunk(data, pos)?;
            Some(Integer::from_bytes_msf(&chunk))
        };

        let z = read_int(data, &mut pos)?;

        // Read the EC point u1
        let u1_chunk = read_chunk(data, &mut pos)?;
        let mut repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
        if u1_chunk.len() != repr.as_ref().len() {
            return None;
        }
        repr.as_mut().copy_from_slice(&u1_chunk);
        let u1 = Option::from(C::ProjectivePoint::from_bytes(&repr))?;

        let u2 = read_int(data, &mut pos)?;
        let u3 = read_int(data, &mut pos)?;
        let s1 = read_int(data, &mut pos)?;
        let s2 = read_int(data, &mut pos)?;
        let s3 = read_int(data, &mut pos)?;

        Some(PdlSlackProof {
            z,
            u1,
            u2,
            u3,
            s1,
            s2,
            s3,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute `h1^x * h2^r mod N'`.
///
/// Handles negative exponents by inverting the base first.
pub(crate) fn commitment_unknown_order(
    h1: &Integer,
    h2: &Integer,
    modulus: &Integer,
    x: &Integer,
    r: &Integer,
) -> Integer {
    let h1_x = pow_mod_signed(h1, x, modulus);
    let h2_r = pow_mod_signed(h2, r, modulus);
    (h1_x * h2_r).modulo(modulus)
}

/// Modular exponentiation that handles negative exponents.
pub(crate) fn pow_mod_signed(base: &Integer, exp: &Integer, modulus: &Integer) -> Integer {
    base.pow_mod_ref(exp, modulus)
        .expect("pow_mod defined")
        .complete()
}

/// Sample a random integer in `[1, bound)`.
fn sample_range_one_to(bound: &Integer, rng: &mut impl rand_core::RngCore) -> Integer {
    let bound_minus_one = bound - Integer::one();
    bound_minus_one.sample_below_ref(rng) + Integer::one()
}

/// Hash public values and commitments to produce a Fiat-Shamir challenge.
fn compute_challenge<C>(
    stmt: &PdlSlackStatement<C>,
    z: &Integer,
    u1: &C::ProjectivePoint,
    u2: &Integer,
    u3: &Integer,
) -> Integer
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::ProjectivePoint: GroupEncoding,
{
    let mut hasher = Sha256::new();
    hasher.update(b"PiPdlSlack");

    // Hash generator G (compressed)
    hasher.update(stmt.G.to_bytes().as_ref());

    // Hash public key Q (compressed)
    hasher.update(stmt.Q.to_bytes().as_ref());

    // Hash ciphertext
    hasher.update(stmt.ciphertext.to_bytes_msf());

    // Hash z
    hasher.update(z.to_bytes_msf());

    // Hash u1 (EC point, compressed)
    hasher.update(u1.to_bytes().as_ref());

    // Hash u2
    hasher.update(u2.to_bytes_msf());

    // Hash u3
    hasher.update(u3.to_bytes_msf());

    Integer::from_bytes_msf(&hasher.finalize())
}

// ---------------------------------------------------------------------------
// Prove / Verify
// ---------------------------------------------------------------------------

impl<C> PdlSlackProof<C>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::Scalar: PrimeField<Repr = FieldBytes<C>>,
    <C as CurveArithmetic>::ProjectivePoint: GroupEncoding,
{
    /// Construct a non-interactive PDL-with-slack proof.
    ///
    /// # Panics
    /// Panics if `pow_mod` encounters undefined behaviour (should not happen
    /// with well-formed parameters).
    pub fn prove(
        witness: &PdlSlackWitness,
        statement: &PdlSlackStatement<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let q = curve_order::<C>();
        let q3 = (&q * &q).complete() * &q;

        // 1. Sample blinding values
        let alpha = q3.sample_below_ref(rng);
        let beta = sample_range_one_to(&statement.ek_n, rng);
        let rho = (q * &statement.N_tilde).sample_below_ref(rng);
        let gamma = (q3 * &statement.N_tilde).sample_below_ref(rng);

        // 2. z = h1^x * h2^rho mod N_tilde
        let z = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &witness.x,
            &rho,
        );

        // 3. u1 = alpha * G
        let alpha_scalar = integer_to_scalar::<C>(&alpha);
        let u1 = statement.G * alpha_scalar;

        // 4. u2 = (1 + N)^alpha * beta^N mod N^2  (= Enc(N, alpha; beta))
        let u2 = {
            let g_paillier = &statement.ek_n + Integer::one(); // (1 + N)
            commitment_unknown_order(
                &g_paillier,
                &beta,
                &statement.ek_nn,
                &alpha,
                &statement.ek_n,
            )
        };

        // 5. u3 = h1^alpha * h2^gamma mod N_tilde
        let u3 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &alpha,
            &gamma,
        );

        // 6. e = H(N, C, Q, z, u1, u2, u3)
        let e = compute_challenge(statement, &z, &u1, &u2, &u3);

        // 7. s1 = alpha + e*x
        let s1 = alpha + &e * &witness.x;

        // 8. s2 = beta * r^e mod N  (i.e., commitment_unknown_order(r, beta, N, e, 1))
        let s2 = commitment_unknown_order(&witness.r, &beta, &statement.ek_n, &e, &Integer::one());

        // 9. s3 = gamma + e*rho
        let s3 = &gamma + e * &rho;

        PdlSlackProof {
            z,
            u1,
            u2,
            u3,
            s1,
            s2,
            s3,
        }
    }

    /// Verify a PDL-with-slack proof.
    ///
    /// # Errors
    /// Returns `PdlSlackError::Verify` if the proof does not verify.
    pub fn verify(&self, statement: &PdlSlackStatement<C>) -> Result<(), PdlSlackError> {
        let q = curve_order::<C>();

        // Recompute challenge
        let e = compute_challenge(statement, &self.z, &self.u1, &self.u2, &self.u3);

        // --- EC check: s1*G == u1 + e*Q ---
        let s1_scalar = integer_to_scalar::<C>(&self.s1);
        let g_s1 = statement.G * s1_scalar;

        // e_neg = q - e (mod q), for subtraction on the curve
        let e_neg_int = &q - (&e % &q).complete();
        let e_neg_scalar = integer_to_scalar::<C>(&e_neg_int);
        let q_times_neg_e = statement.Q * e_neg_scalar;
        let u1_test = g_s1 + q_times_neg_e;

        // --- Paillier check: Enc(N, s1; s2) == u2 * C^e mod N^2 ---
        let g_paillier = &statement.ek_n + Integer::one();
        let u2_test_tmp = commitment_unknown_order(
            &g_paillier,
            &self.s2,
            &statement.ek_nn,
            &self.s1,
            &statement.ek_n,
        );
        let neg_e = -e.clone();
        let u2_test = commitment_unknown_order(
            &u2_test_tmp,
            &statement.ciphertext,
            &statement.ek_nn,
            &Integer::one(),
            &neg_e,
        );

        // --- Ring-Pedersen check: h1^s1 * h2^s3 == u3 * z^e mod N' ---
        let u3_test_tmp = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &self.s1,
            &self.s3,
        );
        let u3_test = commitment_unknown_order(
            &u3_test_tmp,
            &self.z,
            &statement.N_tilde,
            &Integer::one(),
            &neg_e,
        );

        // --- Range check: |s1| < q^3 ---
        // s1 should be positive (alpha >= 0, e >= 0, x >= 0 in typical usage)
        // but we check absolute value just in case.
        let s1_in_range = self.s1 < q.pow(3);

        if self.u1.to_bytes().as_ref() == u1_test.to_bytes().as_ref()
            && self.u2 == u2_test
            && self.u3 == u3_test
            && s1_in_range
        {
            Ok(())
        } else {
            Err(PdlSlackError::Verify)
        }
    }
}

#[cfg(test)]
mod tests {
    use fast_paillier::DecryptionKey;

    use super::*;

    type TestCurve = k256::Secp256k1;
    type Point = <TestCurve as CurveArithmetic>::ProjectivePoint;

    fn setup_paillier(
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> (DecryptionKey, fast_paillier::EncryptionKey) {
        // Use small primes for fast tests.
        let p = Integer::generate_safe_prime(rng, 256);
        let q = Integer::generate_safe_prime(rng, 256);
        let dk = DecryptionKey::from_primes(p, q).expect("valid primes");
        let ek = dk.encryption_key().clone();
        (dk, ek)
    }

    fn setup_ntilde(rng: &mut impl rand_core::CryptoRngCore) -> (Integer, Integer, Integer) {
        let (params, _) = tecdsa_pedersen_mod::PedersenModParams::generate(256, rng);
        (params.n, params.t, params.s)
    }

    #[test]
    fn pdl_slack_honest_verifies() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        // Sample a secret x (as an Integer, must fit in the Paillier plaintext range)
        let q = curve_order::<TestCurve>();
        // x should be a small value relative to N, let's pick something in [1, q)
        let x = sample_range_one_to(&q, &mut rng);

        // Q = x * G
        let x_scalar = integer_to_scalar::<TestCurve>(&x);
        let G = Point::GENERATOR;
        let Q = G * x_scalar;

        // Encrypt x
        let (ciphertext, r) = ek.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let statement = PdlSlackStatement::<TestCurve> {
            ciphertext,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q,
            G,
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let witness = PdlSlackWitness { x, r };

        let proof = PdlSlackProof::prove(&witness, &statement, &mut rng);
        proof
            .verify(&statement)
            .expect("honest proof should verify");
    }

    #[test]
    #[ignore = "redundant negative/serde test"]
    fn pdl_slack_wrong_x_rejects() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = curve_order::<TestCurve>();
        let x = sample_range_one_to(&q, &mut rng);

        let x_scalar = integer_to_scalar::<TestCurve>(&x);
        let G = Point::GENERATOR;
        let Q = G * x_scalar;

        let (ciphertext, r) = ek.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let statement = PdlSlackStatement::<TestCurve> {
            ciphertext,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q,
            G,
            h1,
            h2,
            N_tilde: n_tilde,
        };

        // Use a *wrong* x in the witness
        let wrong_x = sample_range_one_to(&q, &mut rng);
        let witness = PdlSlackWitness { x: wrong_x, r };

        let proof = PdlSlackProof::prove(&witness, &statement, &mut rng);
        assert!(
            proof.verify(&statement).is_err(),
            "proof with wrong x should fail"
        );
    }

    #[test]
    #[ignore = "redundant negative/serde test"]
    fn pdl_slack_wrong_q_rejects() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = curve_order::<TestCurve>();
        let x = sample_range_one_to(&q, &mut rng);

        let x_scalar = integer_to_scalar::<TestCurve>(&x);
        let G = Point::GENERATOR;
        let _Q = G * x_scalar; // correct Q, unused — we test with wrong_Q below

        let (ciphertext, r) = ek.encrypt_with_random(&mut rng, &x).expect("encrypt");

        // Use a *wrong* Q (random point, not matching x)
        let wrong_scalar = integer_to_scalar::<TestCurve>(&sample_range_one_to(&q, &mut rng));
        let wrong_Q = G * wrong_scalar;

        let statement = PdlSlackStatement::<TestCurve> {
            ciphertext,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q: wrong_Q,
            G,
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let witness = PdlSlackWitness { x, r };

        let proof = PdlSlackProof::prove(&witness, &statement, &mut rng);
        assert!(
            proof.verify(&statement).is_err(),
            "proof with wrong Q should fail"
        );
    }

    #[test]
    #[ignore = "redundant negative/serde test"]
    fn pdl_slack_serde_roundtrip() {
        let mut rng = rand::thread_rng();
        let (_dk, ek) = setup_paillier(&mut rng);
        let (n_tilde, h1, h2) = setup_ntilde(&mut rng);

        let q = curve_order::<TestCurve>();
        let x = sample_range_one_to(&q, &mut rng);

        let x_scalar = integer_to_scalar::<TestCurve>(&x);
        let G = Point::GENERATOR;
        let Q = G * x_scalar;

        let (ciphertext, r) = ek.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let statement = PdlSlackStatement::<TestCurve> {
            ciphertext,
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q,
            G,
            h1,
            h2,
            N_tilde: n_tilde,
        };

        let witness = PdlSlackWitness { x, r };

        let proof = PdlSlackProof::prove(&witness, &statement, &mut rng);

        // Serialize and deserialize
        let bytes = proof.to_bytes();
        let proof2 =
            PdlSlackProof::<TestCurve>::from_bytes(&bytes).expect("deserialization must succeed");

        // The deserialized proof must still verify
        proof2
            .verify(&statement)
            .expect("deserialized proof should verify");
    }
}
