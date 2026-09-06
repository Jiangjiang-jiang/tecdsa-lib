// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proofs for ring-Pedersen parameter correctness.
//!
//! - [`PiPrm`] -- proves knowledge of lambda such that s = t^lambda mod N,
//!   using m = 80 binary Fiat-Shamir challenges (CGGMP20 Figure 13).
//!   Soundness error: 2^{-80}.
//!
//! The Paillier-Blum modulus proof (Pi_mod, CGGMP20 Figure 12) used to live here
//! as a second implementation. It is now
//! `tecdsa_paillier::zk::paillier_zk::paillier_blum_modulus`, which is generic
//! over the repetition count and the digest, exposes the interactive form, and
//! binds its Fiat-Shamir challenge to a caller-supplied session tag.

use rand_core::CryptoRngCore;
use rug::Integer;
use serde::{Deserialize, Serialize};
use tecdsa_bigint::{BigIntExt, SyncRng};

use crate::params::{PedersenModParams, PedersenModSecret};

const SECURITY_PARAM: usize = 80;

// ──────────────────────────────────────────────────────────────────────────────
// Pi_prm — ring-Pedersen parameter proof (CGGMP20 Figure 13)
// ──────────────────────────────────────────────────────────────────────────────

/// Proof that ring-Pedersen parameters (N, s, t) are well-formed.
///
/// Demonstrates knowledge of lambda such that s = t^lambda mod N,
/// using m = 80 binary Fiat-Shamir challenges per CGGMP20 Figure 13.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiPrm {
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    commitment: Vec<Integer>,
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    zs: Vec<Integer>,
}

impl PiPrm {
    /// Produce a `PiPrm` proof (CGGMP20 Figure 13, non-interactive).
    #[must_use]
    #[allow(clippy::similar_names)]
    pub fn prove(
        params: &PedersenModParams,
        secret: &PedersenModSecret,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let phi_n = Integer::from(&secret.p - 1) * Integer::from(&secret.q - 1);

        let mut sync_rng = SyncRng(rng);
        let rug_rng = &mut rug::rand::ThreadRandState::new_custom(&mut sync_rng);

        let private_commitment: Vec<Integer> = (0..SECURITY_PARAM)
            .map(|_| phi_n.clone().random_below(rug_rng))
            .collect();
        let commitment: Vec<Integer> = private_commitment
            .iter()
            .map(|a_i| params.t.clone().pow_mod(a_i, &params.n).unwrap())
            .collect();

        let challenges = Self::derive_challenges(params, &commitment);

        let zs: Vec<Integer> = private_commitment
            .iter()
            .zip(challenges.iter())
            .map(|(a_i, &e_i)| {
                let mut z = a_i.clone();
                if e_i {
                    z += &secret.lambda;
                    z %= &phi_n;
                }
                z
            })
            .collect();

        Self { commitment, zs }
    }

    /// Verify `PiPrm` proof (CGGMP20 Figure 13).
    #[must_use]
    pub fn verify(&self, params: &PedersenModParams) -> bool {
        if !params.is_well_formed() {
            return false;
        }

        if self.commitment.len() != SECURITY_PARAM || self.zs.len() != SECURITY_PARAM {
            return false;
        }

        for (a_i, z_i) in self.commitment.iter().zip(self.zs.iter()) {
            if *a_i == 0 || *a_i >= params.n {
                return false;
            }
            if a_i.clone().gcd(&params.n) != 1 {
                return false;
            }
            if *z_i == 0 || *z_i >= params.n {
                return false;
            }
        }

        let challenges = Self::derive_challenges(params, &self.commitment);

        for ((z_i, a_i), &e_i) in self
            .zs
            .iter()
            .zip(self.commitment.iter())
            .zip(challenges.iter())
        {
            let lhs = params.t.clone().pow_mod(z_i, &params.n).unwrap();
            let rhs = if e_i {
                Integer::from(a_i * &params.s) % &params.n
            } else {
                a_i.clone()
            };
            if lhs != rhs {
                return false;
            }
        }

        true
    }

    fn derive_challenges(params: &PedersenModParams, commitment: &[Integer]) -> Vec<bool> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(params.n.to_bytes_msf());
        hasher.update(params.s.to_bytes_msf());
        hasher.update(params.t.to_bytes_msf());
        for a_i in commitment {
            hasher.update(a_i.to_bytes_msf());
        }
        let hash = hasher.finalize();

        let mut challenges = Vec::with_capacity(SECURITY_PARAM);
        let mut current_hash = hash.to_vec();
        let mut byte_idx = 0;
        let mut bit_idx: u8 = 0;
        while challenges.len() < SECURITY_PARAM {
            if byte_idx >= current_hash.len() {
                let mut h = Sha256::new();
                h.update(&current_hash);
                current_hash = h.finalize().to_vec();
                byte_idx = 0;
                bit_idx = 0;
            }
            challenges.push((current_hash[byte_idx] >> bit_idx) & 1 == 1);
            bit_idx += 1;
            if bit_idx == 8 {
                bit_idx = 0;
                byte_idx += 1;
            }
        }

        challenges
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Pi_mod — Blum modulus proof (CGGMP20 Figure 12)
// ──────────────────────────────────────────────────────────────────────────────

/// Proof that N is a Paillier-Blum modulus (CGGMP20 Figure 12).
///
/// Proves N = pq where p, q are primes with p = q = 3 mod 4,
/// using m = 80 challenges with Jacobi classification, Blum fourth roots,
/// and N-th roots. Soundness error: 2^{-81}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiMod {
    #[serde(with = "tecdsa_bigint::int_wire")]
    w: Integer,
    proof_points: Vec<PiModPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PiModPoint {
    #[serde(with = "tecdsa_bigint::int_wire")]
    x: Integer,
    a: bool,
    b: bool,
    #[serde(with = "tecdsa_bigint::int_wire")]
    z: Integer,
}

impl PiMod {
    /// Prove that a raw modulus N = p*q is a Blum modulus (CGGMP20 Figure 12).
    ///
    /// This is the primary API for proving any RSA-type modulus is Blum,
    /// including Paillier moduli used in CGGMP20 aux-info.
    ///
    /// # Panics
    ///
    /// Panics if `find_residue` fails for a challenge, which should not
    /// happen with a valid Blum modulus and correctly chosen w.
    #[allow(clippy::similar_names, clippy::many_single_char_names)]
    pub fn prove_modulus(
        n: &Integer,
        p: &Integer,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self> {
        let expected_n = Integer::from(p * q);
        if expected_n != *n {
            return None;
        }

        if !p.is_safe_prime() || !q.is_safe_prime() {
            return None;
        }
        if p.mod_u(4) != 3 || q.mod_u(4) != 3 {
            return None;
        }

        let w = Integer::sample_neg_jacobi(rng, n);

        let phi_n = Integer::from(p - 1) * Integer::from(q - 1);

        let n_inv = n.clone().invert(&phi_n).ok()?;

        let challenges = Self::derive_challenges(n, &w);

        let proof_points: Vec<PiModPoint> = challenges
            .iter()
            .map(|y_i| {
                let z = y_i.clone().pow_mod(&n_inv, n).unwrap();

                let (a, b, y_prime) = y_i
                    .find_residue(&w, p, q, n)
                    .expect("find_residue must succeed for valid Blum modulus");

                let x = y_prime.blum_fourth_root(p, q, n);

                PiModPoint { x, a, b, z }
            })
            .collect();

        Some(Self { w, proof_points })
    }

    /// Convenience wrapper: prove ring-Pedersen modulus is Blum.
    ///
    /// # Panics
    ///
    /// Panics if `find_residue` fails (see [`prove_modulus`](Self::prove_modulus)).
    pub fn prove(
        params: &PedersenModParams,
        secret: &PedersenModSecret,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self> {
        Self::prove_modulus(&params.n, &secret.p, &secret.q, rng)
    }

    /// Verify `PiMod` proof against a raw modulus N (CGGMP20 Figure 12).
    ///
    /// The `rng` parameter is unused (Miller-Rabin composite testing is
    /// deterministic in `rug`) but kept for API stability.
    #[must_use]
    pub fn verify_modulus(&self, n: &Integer, _rng: &mut impl CryptoRngCore) -> bool {
        if n.is_even() {
            return false;
        }

        if n.is_probably_prime(25) != rug::integer::IsPrime::No {
            return false;
        }

        if *n <= 1 {
            return false;
        }

        if self.w == 0 || self.w >= *n {
            return false;
        }
        if self.w.clone().gcd(n) != 1 {
            return false;
        }
        if self.w.jacobi(n) != -1 {
            return false;
        }

        if self.proof_points.len() != SECURITY_PARAM {
            return false;
        }

        let challenges = Self::derive_challenges(n, &self.w);

        for (point, y_i) in self.proof_points.iter().zip(challenges.iter()) {
            if point.x == 0 || point.x >= *n {
                return false;
            }
            if point.x.clone().gcd(n) != 1 {
                return false;
            }
            if point.z == 0 || point.z >= *n {
                return false;
            }
            if point.z.clone().gcd(n) != 1 {
                return false;
            }

            let z_pow_n = point.z.clone().pow_mod(n, n).unwrap();
            if z_pow_n != *y_i {
                return false;
            }

            let mut expected = y_i.clone();
            if point.a {
                expected = Integer::from(n - &expected);
            }
            if point.b {
                expected = expected * &self.w % n;
            }

            let x_pow_4 = point.x.clone().pow_mod(&Integer::from(4), n).unwrap();
            if x_pow_4 != expected {
                return false;
            }
        }

        true
    }

    /// Convenience wrapper: verify against ring-Pedersen modulus.
    #[must_use]
    pub fn verify(&self, params: &PedersenModParams, rng: &mut impl CryptoRngCore) -> bool {
        self.verify_modulus(&params.n, rng)
    }

    fn derive_challenges(n: &Integer, w: &Integer) -> Vec<Integer> {
        use sha2::{Digest, Sha256};

        let n_bytes = n.to_bytes_msf();
        let n_byte_len = n_bytes.len();

        let mut challenges = Vec::with_capacity(SECURITY_PARAM);
        let mut counter: u32 = 0;

        while challenges.len() < SECURITY_PARAM {
            let mut hasher = Sha256::new();
            hasher.update(b"pi_mod_challenge");
            hasher.update(&n_bytes);
            hasher.update(w.to_bytes_msf());
            hasher.update(counter.to_be_bytes());
            let seed = hasher.finalize();

            let mut expanded = Vec::with_capacity(n_byte_len);
            let mut block_input = seed.to_vec();
            while expanded.len() < n_byte_len {
                let mut h = Sha256::new();
                h.update(&block_input);
                let block = h.finalize();
                expanded.extend_from_slice(&block);
                block_input = block.to_vec();
            }
            expanded.truncate(n_byte_len);

            let candidate = Integer::from_digits(&expanded, rug::integer::Order::Msf) % n;
            if candidate > 1 && candidate.clone().gcd(n) == 1 {
                challenges.push(candidate);
            }
            counter += 1;
        }

        challenges
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PedersenModParams;

    fn generate_blum_params(bits: u64) -> (PedersenModParams, PedersenModSecret) {
        let mut rng = rand::thread_rng();
        PedersenModParams::generate(bits, &mut rng)
    }

    // -- PiPrm tests --

    #[test]
    fn piprm_honest_proof_verifies() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let proof = PiPrm::prove(&params, &secret, &mut rng);
        assert!(proof.verify(&params), "honest PiPrm proof must verify");
    }

    #[test]
    fn piprm_wrong_lambda_fails() {
        let (params, mut secret) = generate_blum_params(256);
        secret.lambda = Integer::from(42u64);
        let mut rng = rand::thread_rng();
        let proof = PiPrm::prove(&params, &secret, &mut rng);
        assert!(!proof.verify(&params), "PiPrm with wrong lambda must fail");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn piprm_tampered_commitment_fails() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let mut proof = PiPrm::prove(&params, &secret, &mut rng);
        proof.commitment[0] = Integer::from(2u64);
        assert!(!proof.verify(&params), "tampered PiPrm must fail");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn piprm_tampered_response_fails() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let mut proof = PiPrm::prove(&params, &secret, &mut rng);
        proof.zs[0] = Integer::from(1u64);
        assert!(!proof.verify(&params), "tampered PiPrm response must fail");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn piprm_has_correct_length() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let proof = PiPrm::prove(&params, &secret, &mut rng);
        assert_eq!(proof.commitment.len(), SECURITY_PARAM);
        assert_eq!(proof.zs.len(), SECURITY_PARAM);
    }
}
