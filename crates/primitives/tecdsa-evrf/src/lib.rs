// SPDX-License-Identifier: MIT OR Apache-2.0
//! DDH exponent VRF (eVRF) for the tecdsa threshold ECDSA library.
//!
//! Implements the Chaum-Pedersen DDH-based eVRF construction used in the Trout protocol.
//!
//! # Construction
//!
//! Given a secret key `sk` and input `x`:
//!
//! 1. Hash-to-curve: `H = hash_to_curve(x)` (try-and-increment via SHA-256).
//! 2. Evaluate: `Y = sk * H`.
//! 3. Prove via Chaum-Pedersen DLEQ: prove `log_G(PK) = log_H(Y) = sk`.
//!
//! The DLEQ proof convinces a verifier that `(G, PK, H, Y)` is a DDH tuple,
//! i.e., that `Y` was computed honestly from the public key `PK = sk * G`.

pub mod zk;

use elliptic_curve::{
    group::Curve as _, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;
pub use zk::EvrfProof;

// ──────────────────────────────────────────────────────────────────────────────
// Hash-to-curve (try-and-increment via SHA-256)
// ──────────────────────────────────────────────────────────────────────────────

/// Hash an arbitrary byte string to a curve point using the try-and-increment
/// method with SHA-256.
///
/// For each counter `i = 0, 1, 2, ...` we compute `SHA-256(i || input)` and
/// try to interpret it as a compressed x-coordinate.  The first one that
/// yields a valid point is returned.
pub(crate) fn hash_to_curve<C>(input: &[u8]) -> C::AffinePoint
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
{
    let field_len = FieldBytes::<C>::default().len();
    for counter in 0u32.. {
        let hash = Sha256::new()
            .chain_update(counter.to_le_bytes())
            .chain_update(b"tecdsa-evrf-h2c:")
            .chain_update(input)
            .finalize();

        // SEC1 compressed encoding: 0x02 prefix + field-element-sized x-coordinate.
        let mut compressed = vec![0u8; 1 + field_len];
        compressed[0] = 0x02;
        let copy_len = field_len.min(hash.len());
        compressed[1..1 + copy_len].copy_from_slice(&hash[..copy_len]);

        if let Ok(pt) = C::point_from_bytes(&compressed) {
            return pt;
        }
    }
    unreachable!("hash_to_curve: no valid point found after 2^32 iterations")
}

// ──────────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────────

/// Secret key for the DDH eVRF.
pub struct EvrfSecretKey<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    scalar: C::Scalar,
}

/// Public key for the DDH eVRF: `PK = sk * G`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvrfPublicKey<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub point: C::AffinePoint,
}

/// Output of an eVRF evaluation: `Y = sk * H` where `H = hash_to_curve(input)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvrfOutput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub point: C::AffinePoint,
}

// ──────────────────────────────────────────────────────────────────────────────
// Zeroize / Drop for EvrfSecretKey
// ──────────────────────────────────────────────────────────────────────────────

impl<C: TecdsaCurve> Zeroize for EvrfSecretKey<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

impl<C: TecdsaCurve> Drop for EvrfSecretKey<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// EvrfCurve bound alias
// ──────────────────────────────────────────────────────────────────────────────

/// Combined trait alias for the curve bounds used throughout this crate.
pub trait EvrfCurve: TecdsaCurve<Scalar: PrimeField<Repr = FieldBytes<Self>>>
where
    FieldBytesSize<Self>: ModulusSize,
{
}

impl<C> EvrfCurve for C
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
}

// ──────────────────────────────────────────────────────────────────────────────
// EvrfSecretKey implementation
// ──────────────────────────────────────────────────────────────────────────────

impl<C: EvrfCurve> EvrfSecretKey<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Generate a fresh random secret/public key pair.
    pub fn generate(rng: &mut impl CryptoRngCore) -> (Self, EvrfPublicKey<C>) {
        let scalar = C::random_scalar(rng);
        let point = (C::generator() * scalar).to_affine();
        (Self { scalar }, EvrfPublicKey { point })
    }

    /// Return a reference to the underlying secret scalar.
    #[must_use]
    pub fn scalar(&self) -> &C::Scalar {
        &self.scalar
    }

    /// Evaluate the eVRF on `input`.
    ///
    /// Returns `(output, proof)` where the proof certifies that `output` was
    /// computed honestly using this key.
    ///
    /// # Panics
    ///
    /// Panics if `hash_to_curve` fails to find a valid point (negligible
    /// probability).
    pub fn eval(
        &self,
        input: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> (EvrfOutput<C>, EvrfProof<C>) {
        let h_affine: C::AffinePoint = hash_to_curve::<C>(input);
        let h_proj: C::ProjectivePoint = h_affine.into();

        let y_proj: C::ProjectivePoint = h_proj * self.scalar;
        let y_affine = y_proj.to_affine();
        let output = EvrfOutput { point: y_affine };

        let proof = EvrfProof::prove_with_h(self, &h_affine, &output, rng);
        (output, proof)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use k256::Secp256k1;
    use rand::rngs::OsRng;

    use super::*;

    type Sk = EvrfSecretKey<Secp256k1>;

    #[test]
    fn evrf_eval_deterministic() {
        let mut rng = OsRng;
        let (sk, _pk) = Sk::generate(&mut rng);
        let input = b"test-input-deterministic";

        let (out1, _) = sk.eval(input, &mut rng);
        let (out2, _) = sk.eval(input, &mut rng);
        assert_eq!(
            out1.point, out2.point,
            "eVRF output must be deterministic in key+input"
        );
    }

    #[test]
    fn evrf_proof_verifies_honest() {
        let mut rng = OsRng;
        let (sk, pk) = Sk::generate(&mut rng);
        let input = b"honest-evaluation-input";

        let (output, proof) = sk.eval(input, &mut rng);
        assert!(
            proof.verify(&pk, input, &output),
            "honest proof must verify"
        );
    }

    #[test]
    fn evrf_proof_rejects_wrong_input() {
        let mut rng = OsRng;
        let (sk, pk) = Sk::generate(&mut rng);

        let (output, proof) = sk.eval(b"correct-input", &mut rng);
        assert!(
            !proof.verify(&pk, b"wrong-input", &output),
            "proof must not verify for a different input"
        );
    }

    #[test]
    fn evrf_proof_rejects_wrong_key() {
        let mut rng = OsRng;
        let (sk, _pk_correct) = Sk::generate(&mut rng);
        let (_sk2, pk_wrong) = Sk::generate(&mut rng);

        let (output, proof) = sk.eval(b"key-mismatch-input", &mut rng);
        assert!(
            !proof.verify(&pk_wrong, b"key-mismatch-input", &output),
            "proof must not verify under a different public key"
        );
    }

    #[test]
    fn evrf_different_inputs_give_different_outputs() {
        let mut rng = OsRng;
        let (sk, _pk) = Sk::generate(&mut rng);

        let (out1, _) = sk.eval(b"input-a", &mut rng);
        let (out2, _) = sk.eval(b"input-b", &mut rng);
        assert_ne!(
            out1.point, out2.point,
            "different inputs must yield different outputs"
        );
    }

    #[test]
    fn evrf_different_keys_give_different_outputs() {
        let mut rng = OsRng;
        let (sk1, _pk1) = Sk::generate(&mut rng);
        let (sk2, _pk2) = Sk::generate(&mut rng);
        let input = b"same-input";

        let (out1, _) = sk1.eval(input, &mut rng);
        let (out2, _) = sk2.eval(input, &mut rng);
        assert_ne!(
            out1.point, out2.point,
            "different keys must yield different outputs"
        );
    }
}
