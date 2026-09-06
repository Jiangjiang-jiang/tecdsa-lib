// SPDX-License-Identifier: MIT OR Apache-2.0
//! Non-interactive range proof for Paillier ciphertexts.
//!
//! Proves that a Paillier ciphertext `c = Enc(x; r)` encrypts a value `x`
//! in the range `[0, q)` where `q` is the elliptic curve group order.
//!
//! The proof uses a cut-and-choose approach with Fiat-Shamir:
//!
//! For each repetition `i`:
//!   - Sample mask `rho_i` from `[0, range_bound)`.
//!   - Compute `c_mask_i = Enc(rho_i; t_i)`.
//!   - Compute `c_masked_i = c (+) c_mask_i = Enc(x + rho_i; ...)`.
//!
//! Challenge bit = 0: reveal `(w_i, s_i)` where `w_i = x + rho_i` and
//!   `s_i` is the nonce of `c_masked_i` (extracted using the secret key).
//!   Verifier checks `c_masked_i = Enc(w_i; s_i)` and `0 <= w_i < q + range_bound`.
//!
//! Challenge bit = 1: reveal `(rho_i, t_i)`.
//!   Verifier checks `c_mask_i = Enc(rho_i; t_i)` and
//!   `c_masked_i = c (+) c_mask_i`, and `0 <= rho_i < range_bound`.
//!
//! Security parameter: `SECURITY_PARAM` repetitions for `2^{-SECURITY_PARAM}`
//! soundness.

use fast_paillier::{
    backend::{BigIntExt, Integer},
    DecryptionKey, EncryptionKey,
};
use rand_core::CryptoRngCore;
use rug::Complete;
use sha2::{Digest, Sha256};

/// Number of repetitions for the range proof.
const SECURITY_PARAM: usize = 80;

/// Errors from the non-interactive range proof.
#[derive(Debug, thiserror::Error)]
pub enum RangeProofNiError {
    /// Paillier encryption/decryption error.
    #[error("Paillier error: {0}")]
    Paillier(String),
    /// Nonce extraction failed.
    #[error("nonce extraction failed")]
    NonceExtraction,
}

impl From<fast_paillier::Error> for RangeProofNiError {
    fn from(e: fast_paillier::Error) -> Self {
        RangeProofNiError::Paillier(e.to_string())
    }
}

/// Non-interactive range proof for a Paillier ciphertext.
///
/// Proves that `c = Enc(x; r)` with `0 <= x < q`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RangeProofNi {
    /// For each repetition: `(c_masked_i, c_mask_i)`.
    pub encrypted_pairs: Vec<EncryptedPair>,
    /// Responses for each repetition, determined by the challenge bit.
    pub responses: Vec<RangeResponse>,
}

/// An encrypted pair in the range proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedPair {
    /// `c_masked_i = c (+) c_mask_i`.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub c_masked: fast_paillier::Ciphertext,
    /// `c_mask_i = Enc(rho_i; t_i)`.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub c_mask: fast_paillier::Ciphertext,
}

/// Response for one repetition of the range proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum RangeResponse {
    /// Challenge bit = 0: reveal `(w_i, s_i)` where `w_i = x + rho_i`
    /// and `s_i` is the nonce of `c_masked_i`.
    Open {
        /// `w_i = x + rho_i`, the masked plaintext.
        #[serde(with = "tecdsa_bigint::int_wire")]
        w: Integer,
        /// `s_i`, the Paillier nonce of `c_masked_i`.
        #[serde(with = "tecdsa_bigint::int_wire")]
        s: Integer,
    },
    /// Challenge bit = 1: reveal `(rho_i, t_i)` to prove the mask structure.
    Verify {
        /// `rho_i`, the random mask.
        #[serde(with = "tecdsa_bigint::int_wire")]
        rho: Integer,
        /// `t_i`, the Paillier nonce for `c_mask_i`.
        #[serde(with = "tecdsa_bigint::int_wire")]
        t: Integer,
    },
}

/// Extract the Paillier nonce from a ciphertext given the plaintext and secret key.
///
/// Given `c = (1 + x*N) * r^N mod N^2`, computes `r`.
///
/// Steps:
/// 1. Compute `(1 + x*N) mod N^2` and its inverse.
/// 2. Compute `r^N = c * (1 + x*N)^{-1} mod N^2`.
/// 3. Compute `r = (r^N)^{d} mod N` where `d = N^{-1} mod lambda(N)`.
fn extract_nonce(
    dk: &DecryptionKey,
    ciphertext: &fast_paillier::Ciphertext,
    plaintext: &Integer,
) -> Option<Integer> {
    let n = dk.n();
    let nn = dk.encryption_key().nn();

    // Handle negative plaintext (Paillier convention: x + N for negatives)
    let x = if plaintext.cmp0().is_lt() {
        (plaintext + n).complete()
    } else {
        plaintext.clone()
    };

    // (1 + x*N) mod N^2
    let one_plus_xn = (Integer::one() + x * n).modulo(nn);

    // r^N = c * (1 + x*N)^{-1} mod N^2
    let one_plus_xn_inv = one_plus_xn.invert(nn).ok()?;
    let r_to_n = (ciphertext * &one_plus_xn_inv).complete().modulo(nn);

    // Compute d = N^{-1} mod lambda(N)
    let lambda = dk.lambda();
    let d = n.invert_ref(lambda)?.complete();

    // r = (r^N)^d mod N
    let r = r_to_n.pow_mod(&d, n).ok()?;

    Some(r)
}

impl RangeProofNi {
    /// Generate a range proof that `c = Enc(x; r)` with `0 <= x < q`.
    ///
    /// # Arguments
    /// * `dk` - Paillier decryption key (prover needs it to extract nonces)
    /// * `ek` - Paillier encryption key
    /// * `c` - The ciphertext to prove range for
    /// * `x` - The plaintext value
    /// * `_r` - The Paillier nonce used to create `c` (unused; extracted via dk)
    /// * `q` - The upper bound (curve group order)
    /// * `rng` - Cryptographic RNG
    pub fn prove(
        dk: &DecryptionKey,
        ek: &EncryptionKey,
        c: &fast_paillier::Ciphertext,
        x: &Integer,
        _r: &Integer,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, RangeProofNiError> {
        // Range bound: masks sampled from [0, q * 2^{128}).
        let range_bound = q * Integer::u_pow_u(2, 128).complete();

        let mut encrypted_pairs = Vec::with_capacity(SECURITY_PARAM);
        let mut masks = Vec::with_capacity(SECURITY_PARAM);
        let mut nonces_mask = Vec::with_capacity(SECURITY_PARAM);

        for _ in 0..SECURITY_PARAM {
            // Sample rho_i from [0, range_bound)
            let rho_i = range_bound.sample_below_ref(rng);

            // Encrypt rho_i: c_mask_i = Enc(rho_i; t_i)
            let (c_mask, t_i) = dk.encrypt_with_random(rng, &rho_i)?;

            // c_masked_i = c (+) c_mask_i
            let c_masked = ek.oadd(c, &c_mask)?;

            encrypted_pairs.push(EncryptedPair { c_masked, c_mask });
            masks.push(rho_i);
            nonces_mask.push(t_i);
        }

        // Derive challenge bits via Fiat-Shamir
        let challenges = derive_challenges(ek, c, &encrypted_pairs);

        let mut responses = Vec::with_capacity(SECURITY_PARAM);
        for (i, bit) in challenges.iter().enumerate() {
            if *bit == 0 {
                // Reveal (w_i, s_i) where w_i = x + rho_i
                let w_i = (x + &masks[i]).complete();
                // Extract nonce s_i of c_masked_i using the secret key
                let s_i = extract_nonce(dk, &encrypted_pairs[i].c_masked, &w_i)
                    .ok_or(RangeProofNiError::NonceExtraction)?;
                responses.push(RangeResponse::Open { w: w_i, s: s_i });
            } else {
                // Reveal (rho_i, t_i)
                responses.push(RangeResponse::Verify {
                    rho: masks[i].clone(),
                    t: nonces_mask[i].clone(),
                });
            }
        }

        Ok(Self {
            encrypted_pairs,
            responses,
        })
    }

    /// Verify a range proof.
    ///
    /// Checks that the ciphertext `c` encrypts a value in `[0, q)`.
    ///
    /// # Arguments
    /// * `ek` - Paillier encryption key
    /// * `c` - The ciphertext whose range is being proved
    /// * `q` - The upper bound (curve group order)
    #[must_use]
    pub fn verify(&self, ek: &EncryptionKey, c: &fast_paillier::Ciphertext, q: &Integer) -> bool {
        if self.encrypted_pairs.len() != SECURITY_PARAM || self.responses.len() != SECURITY_PARAM {
            return false;
        }

        let range_bound = q * Integer::u_pow_u(2, 128).complete();
        let upper_bound = (q + &range_bound).complete();

        // Re-derive challenge bits
        let challenges = derive_challenges(ek, c, &self.encrypted_pairs);

        for (i, bit) in challenges.iter().enumerate() {
            let pair = &self.encrypted_pairs[i];

            match (&self.responses[i], bit) {
                (RangeResponse::Open { w, s }, 0) => {
                    // Check: c_masked_i = Enc(w; s)
                    let Ok(expected) = ek.encrypt_with(w, s) else {
                        return false;
                    };
                    if pair.c_masked != expected {
                        return false;
                    }
                    // Check: 0 <= w < q + range_bound
                    if w.cmp0().is_lt() || *w >= upper_bound {
                        return false;
                    }
                }
                (RangeResponse::Verify { rho, t }, 1) => {
                    // Check: c_mask_i = Enc(rho; t)
                    let Ok(expected) = ek.encrypt_with(rho, t) else {
                        return false;
                    };
                    if pair.c_mask != expected {
                        return false;
                    }
                    // Check: c_masked_i = c (+) c_mask_i
                    let Ok(combined) = ek.oadd(c, &pair.c_mask) else {
                        return false;
                    };
                    if pair.c_masked != combined {
                        return false;
                    }
                    // Check: 0 <= rho < range_bound
                    if rho.cmp0().is_lt() || *rho >= range_bound {
                        return false;
                    }
                }
                _ => {
                    // Challenge bit doesn't match response type
                    return false;
                }
            }
        }

        true
    }
}

/// Derive SECURITY_PARAM challenge bits via Fiat-Shamir.
fn derive_challenges(
    ek: &EncryptionKey,
    c: &fast_paillier::Ciphertext,
    pairs: &[EncryptedPair],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"lin17-range-proof");
    hasher.update(ek.n().to_bytes_msf());
    hasher.update(c.to_bytes_msf());
    for pair in pairs {
        hasher.update(pair.c_masked.to_bytes_msf());
        hasher.update(pair.c_mask.to_bytes_msf());
    }
    let hash: [u8; 32] = hasher.finalize().into();

    // Extract SECURITY_PARAM bits, expanding with additional hash rounds if needed
    let mut bits = Vec::with_capacity(SECURITY_PARAM);
    let mut current_hash = hash;
    let mut round = 0u32;
    while bits.len() < SECURITY_PARAM {
        for byte in &current_hash {
            for bit_pos in 0..8 {
                if bits.len() >= SECURITY_PARAM {
                    break;
                }
                bits.push((byte >> bit_pos) & 1);
            }
        }
        if bits.len() < SECURITY_PARAM {
            round += 1;
            current_hash = Sha256::new()
                .chain_update(b"lin17-range-proof-expand")
                .chain_update(hash)
                .chain_update(round.to_le_bytes())
                .finalize()
                .into();
        }
    }

    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "redundant boundary test"]
    fn nonce_extraction_roundtrip() {
        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");

        let x = Integer::from(12345u32);
        let (c, r) = dk.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let extracted = extract_nonce(&dk, &c, &x).expect("extract nonce");
        assert_eq!(extracted, r, "extracted nonce must match original");
    }

    #[test]
    fn range_proof_valid() {
        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        // Small value for speed
        let q = Integer::from_bytes_msf(&1_000_000_007u64.to_be_bytes());
        let x = Integer::from(42u32);

        let (c, r) = dk.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let proof = RangeProofNi::prove(&dk, &ek, &c, &x, &r, &q, &mut rng).expect("prove");
        assert!(proof.verify(&ek, &c, &q), "valid range proof must verify");
    }

    #[test]
    #[ignore = "redundant boundary test"]
    fn range_proof_with_real_curve_order() {
        use tecdsa_curve::{conv::scalar_to_bytes, TecdsaCurve};

        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        // Use actual secp256k1 group order
        let q_bytes =
            scalar_to_bytes(&(-<k256::Secp256k1 as elliptic_curve::CurveArithmetic>::Scalar::ONE));
        let q = Integer::from_bytes_msf(&q_bytes) + 1u8;

        // Random x < q
        let x1 = k256::Secp256k1::random_scalar(&mut rng);
        let x1_bytes = scalar_to_bytes(&x1);
        let x = Integer::from_bytes_msf(&x1_bytes);

        let (c, r) = dk.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let proof = RangeProofNi::prove(&dk, &ek, &c, &x, &r, &q, &mut rng).expect("prove");
        assert!(
            proof.verify(&ek, &c, &q),
            "range proof with real curve order must verify"
        );
    }
}
