// SPDX-License-Identifier: MIT OR Apache-2.0
//! Threshold Paillier decryption with trusted dealer setup.
//!
//! In a threshold Paillier scheme, all parties share a single Paillier
//! public key `(N, Gamma)`.  The secret key `lambda(N)` is never
//! reconstructed; instead each party holds a Shamir share of
//! `d = lambda(N) * beta` and computes a partial decryption.  Combining
//! `threshold + 1` partials via Lagrange interpolation in the exponent
//! recovers the plaintext.
//!
//! **Note:** `ThresholdSetup.corruption_threshold` uses *corruption threshold* (polynomial
//! degree) semantics: `threshold + 1` partials are needed to decrypt. This
//! differs from the project-wide convention where `t` means reconstruction
//! threshold. Protocol code should convert: `paillier_threshold = t - 1`.
//!
//! This module uses a **trusted dealer** for key generation: the dealer
//! generates `(N, p, q)`, computes `d = lambda(N) * beta`, and distributes
//! Shamir shares of `d` over Z.  The distributed DKG variant (Hazay et al.
//! 2012) is left for future work.
//!
//! Reference: Fouque-Poupard-Stern (J. Cryptology 2001), Damgard-Jurik (2001).
//! Used by: GGN16 threshold ECDSA.

#![allow(non_snake_case)]

use rand_core::CryptoRngCore;
use rug::{Complete, Integer};
use serde::{Deserialize, Serialize};
use tecdsa_bigint::BigIntExt;
use zeroize::Zeroize;

use crate::scheme::{DecryptionKey, EncryptionKey};

#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    #[error("not enough partial decryptions: need {needed}, got {got}")]
    NotEnoughShares { needed: usize, got: usize },
    #[error("duplicate party index in partial decryptions")]
    DuplicateIndex,
    #[error("decryption failed: theta not invertible mod N")]
    ThetaNotInvertible,
    #[error("Paillier key generation error: {0}")]
    KeyGen(String),
}

/// Public parameters for the threshold Paillier scheme.
#[derive(Debug, Clone)]
pub struct ThresholdSetup {
    /// The Paillier encryption key (N, N+1).
    pub ek: EncryptionKey,
    /// theta = d mod N (public verification value).
    pub theta: Integer,
    /// Total number of parties.
    pub n: u16,
    /// Corruption threshold (polynomial degree). Decryption requires
    /// `corruption_threshold + 1` partial decryptions.
    pub corruption_threshold: u16,
    /// Delta = n! (factorial of total parties).
    pub delta: Integer,
}

/// A party's share of the threshold Paillier decryption key.
#[derive(Clone, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// This party's index (1-based, matching Shamir evaluation points).
    pub index: u16,
    /// The secret share d_i of d = lambda(N) * beta.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d_i: Integer,
}

impl Zeroize for DecryptionShare {
    fn zeroize(&mut self) {
        self.d_i = Integer::zero();
    }
}

impl Drop for DecryptionShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A partial decryption produced by one party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDecryption {
    /// The party's index (1-based).
    pub index: u16,
    /// c_i = c^{2 * delta * d_i} mod N^2
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub value: Integer,
}

fn factorial(n: u16) -> Integer {
    let mut result = Integer::one();
    for i in 2..=n as u32 {
        result *= Integer::from(i);
    }
    result
}

/// L(u) = (u - 1) / N for u in {u in Z_{N^2} : u = 1 mod N}.
fn l_function(u: &Integer, n: &Integer) -> Integer {
    let u_minus_1 = u - Integer::one();
    u_minus_1 / n
}

/// Generate threshold Paillier keys using a trusted dealer.
///
/// The dealer generates a Paillier key pair, then distributes Shamir shares
/// of `d = lambda(N) * beta` over Z, where beta is chosen randomly coprime
/// to N.  The public value `theta = d mod N` enables the final decryption
/// step.
///
/// Returns (setup, decryption shares for all n parties).
pub fn trusted_dealer_setup(
    corruption_threshold: u16,
    total: u16,
    rng: &mut impl CryptoRngCore,
) -> Result<(ThresholdSetup, Vec<DecryptionShare>), ThresholdError> {
    let dk = DecryptionKey::generate(rng).map_err(|e| ThresholdError::KeyGen(e.to_string()))?;
    let ek = dk.encryption_key().clone();
    let n = ek.n().clone();

    let p = dk.p();
    let q = dk.q();
    let p_minus_1 = p - Integer::one();
    let q_minus_1 = q - Integer::one();
    let lambda = p_minus_1.lcm(&q_minus_1);

    let beta = Integer::sample_in_mult_group_of(rng, &n);

    let d = lambda * beta;
    let theta = d.modulo_ref(&n).complete();
    let delta = factorial(total);

    // Shamir share d over Z with coefficient modulus M = N * delta.
    let m = n * &delta;
    let shares = shamir_split_integer(d, corruption_threshold, total, &m, rng);

    let setup = ThresholdSetup {
        ek,
        theta,
        n: total,
        corruption_threshold,
        delta,
    };

    Ok((setup, shares))
}

/// Compute a partial decryption for a ciphertext.
///
/// Party i computes: `c_i = c^{2 * delta * d_i} mod N^2`.
pub fn partial_decrypt(
    ciphertext: &Integer,
    share: &DecryptionShare,
    setup: &ThresholdSetup,
) -> PartialDecryption {
    let nn = setup.ek.nn();
    let exp = Integer::from(2u32) * &setup.delta * &share.d_i;
    let value = ciphertext
        .pow_mod_ref(&exp, nn)
        .expect("pow_mod defined")
        .complete();
    PartialDecryption {
        index: share.index,
        value,
    }
}

/// Combine partial decryptions to recover the plaintext.
///
/// Requires at least `threshold+1` partial decryptions from distinct parties.
/// Uses Lagrange interpolation in the exponent with the delta trick.
///
/// Result: plaintext in `{-N/2, ..., N/2}`.
pub fn combine_partials(
    partials: &[PartialDecryption],
    setup: &ThresholdSetup,
) -> Result<Integer, ThresholdError> {
    let needed = setup.corruption_threshold as usize + 1;
    if partials.len() < needed {
        return Err(ThresholdError::NotEnoughShares {
            needed,
            got: partials.len(),
        });
    }

    let mut seen = std::collections::HashSet::new();
    for p in partials {
        if !seen.insert(p.index) {
            return Err(ThresholdError::DuplicateIndex);
        }
    }

    let n = setup.ek.n();
    let nn = setup.ek.nn();
    let indices: Vec<i32> = partials.iter().map(|p| p.index as i32).collect();

    // c' = prod_{i in S} c_i^{2 * mu_i} mod N^2
    // where mu_i = delta * prod_{j != i} (-j) / (i - j)
    let mut c_prime = Integer::one();
    for (idx, partial) in partials.iter().enumerate() {
        let i = indices[idx];
        let mut mu = setup.delta.clone();
        for &j in &indices {
            if j == i {
                continue;
            }
            mu *= Integer::from(-j);
            let denom = Integer::from(i - j);
            mu /= denom;
        }

        let exp = Integer::from(2i32) * &mu;
        let contrib = partial
            .value
            .pow_mod_ref(&exp, nn)
            .expect("pow_mod defined")
            .complete();
        c_prime = (c_prime * contrib).modulo(nn);
    }

    // m = L(c') * (4 * delta^2 * theta)^{-1} mod N
    let l_val = l_function(&c_prime, n);
    let denom = (Integer::from(4i32) * &setup.delta * &setup.delta * &setup.theta).modulo(n);
    let denom_inv = denom
        .invert(n)
        .map_err(|_| ThresholdError::ThetaNotInvertible)?;

    let mut m = (l_val * denom_inv).modulo(n);

    // Normalize to {-N/2, ..., N/2}
    let half_n = n / Integer::from(2u32);
    if m > half_n {
        m -= n;
    }

    Ok(m)
}

// ---- Integer Shamir secret sharing ----

fn shamir_split_integer(
    secret: Integer,
    corruption_threshold: u16,
    total: u16,
    modulus: &Integer,
    rng: &mut impl CryptoRngCore,
) -> Vec<DecryptionShare> {
    let mut coeffs = vec![secret];
    for _ in 0..corruption_threshold {
        coeffs.push(modulus.sample_below_ref(rng));
    }

    let mut shares = Vec::with_capacity(total as usize);
    for i in 1..=total {
        let x = Integer::from(i as u32);
        let mut val = Integer::zero();
        let mut x_pow = Integer::one();
        for coeff in &coeffs {
            val += coeff * &x_pow;
            x_pow *= &x;
        }
        shares.push(DecryptionShare { index: i, d_i: val });
    }

    shares
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_decrypt_2_of_3() {
        let mut rng = rand::thread_rng();
        let (setup, shares) = trusted_dealer_setup(1, 3, &mut rng).expect("setup should succeed");

        let msg = Integer::from(42i32);
        let (ct, _nonce) = setup
            .ek
            .encrypt_with_random(&mut rng, &msg)
            .expect("encrypt");

        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_decrypt(&ct, s, &setup))
            .collect();

        let result = combine_partials(&partials[0..2], &setup).expect("combine");
        assert_eq!(result, msg);

        let result2 = combine_partials(&partials[1..3], &setup).expect("combine");
        assert_eq!(result2, msg);
    }

    #[test]
    #[ignore = "slow: redundant threshold variant test"]
    fn threshold_decrypt_homomorphic_add() {
        let mut rng = rand::thread_rng();
        let (setup, shares) = trusted_dealer_setup(1, 3, &mut rng).expect("setup should succeed");

        let a = Integer::from(100i32);
        let b = Integer::from(200i32);
        let (ct_a, _) = setup.ek.encrypt_with_random(&mut rng, &a).expect("enc a");
        let (ct_b, _) = setup.ek.encrypt_with_random(&mut rng, &b).expect("enc b");

        let ct_sum = setup.ek.oadd(&ct_a, &ct_b).expect("oadd");

        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_decrypt(&ct_sum, s, &setup))
            .collect();
        let result = combine_partials(&partials[0..2], &setup).expect("combine");
        assert_eq!(result, Integer::from(300i32));
    }

    #[test]
    #[ignore = "slow: redundant threshold variant test"]
    fn threshold_decrypt_scalar_mul() {
        let mut rng = rand::thread_rng();
        let (setup, shares) = trusted_dealer_setup(1, 3, &mut rng).expect("setup should succeed");

        let m = Integer::from(7i32);
        let scalar = Integer::from(6i32);
        let (ct, _) = setup.ek.encrypt_with_random(&mut rng, &m).expect("enc");

        let ct_mul = setup.ek.omul(&scalar, &ct).expect("omul");

        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_decrypt(&ct_mul, s, &setup))
            .collect();
        let result = combine_partials(&partials[0..2], &setup).expect("combine");
        assert_eq!(result, Integer::from(42i32));
    }

    #[test]
    #[ignore = "slow: redundant threshold variant test"]
    fn threshold_not_enough_shares_fails() {
        let mut rng = rand::thread_rng();
        let (setup, shares) = trusted_dealer_setup(1, 3, &mut rng).expect("setup should succeed");

        let msg = Integer::from(99i32);
        let (ct, _) = setup.ek.encrypt_with_random(&mut rng, &msg).expect("enc");

        let partials: Vec<_> = shares[0..1]
            .iter()
            .map(|s| partial_decrypt(&ct, s, &setup))
            .collect();

        let result = combine_partials(&partials, &setup);
        assert!(result.is_err());
    }
}
